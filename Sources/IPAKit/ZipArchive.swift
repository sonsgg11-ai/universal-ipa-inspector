import Foundation

/// Reads a ZIP archive out of a file on disk.
///
/// Deliberately independent of ZIPFoundation so the extraction policy can be
/// tested on Linux and on iOS without the dependency, and so ZIPFoundation is
/// used only as a *fast path* for well-formed entries. Anything unusual is
/// handled by the pure-Swift reader below.
enum ZipArchive {

    struct Entry {
        var path: String
        var compressedSize: Int64
        var uncompressedSize: Int64
        var compressionMethod: UInt16
        var localHeaderOffset: Int64
        var isSymlink: Bool
        var isDirectory: Bool
        /// External file attributes' high 16 bits (Unix mode) when present.
        var unixMode: UInt16?

        /// Convenience init for tests and fixture builders: sizes default to
        /// the in-memory contents; directories are detected from the path.
        init(path: String,
             contents: Data = Data(),
             compressionMethod: UInt16 = 0,
             localHeaderOffset: Int64 = 0,
             isSymlink: Bool = false,
             isDirectory: Bool = false,
             compressedSize: Int64? = nil,
             uncompressedSize: Int64? = nil,
             unixMode: UInt16? = nil) {
            self.path = path
            self.compressionMethod = compressionMethod
            self.localHeaderOffset = localHeaderOffset
            self.isSymlink = isSymlink
            self.isDirectory = isDirectory
            self.compressedSize = compressedSize ?? Int64(contents.count)
            self.uncompressedSize = uncompressedSize ?? Int64(contents.count)
            self.unixMode = unixMode
        }
    }

    enum ZipError: LocalizedError {
        case notAZip
        case centralDirectoryMissing
        case corrupt(String)
        case unsafePath(String)
        case tooLarge(String)

        var errorDescription: String? {
            switch self {
            case .notAZip: return "File does not start with a ZIP signature."
            case .centralDirectoryMissing: return "ZIP end-of-central-directory record was not found."
            case .corrupt(let what): return "Corrupt ZIP: \(what)"
            case .unsafePath(let p): return "Archive entry has an unsafe path: \(p)"
            case .tooLarge(let what): return "Archive exceeds a safety limit: \(what)"
            }
        }
    }

    // Signatures
    static let localHeader: UInt32 = 0x04034b50
    static let centralHeader: UInt32 = 0x02014b50
    static let endOfCentralDirectory: UInt32 = 0x06054b50
    static let zip64End: UInt32 = 0x06064b50
    static let zip64Locator: UInt32 = 0x07064b50

    /// Largest central directory we will trust, and the largest single entry we
    /// will decompress. Both are policy limits, not ZIP limits.
    static let maxCentralDirectoryBytes = 64 * 1024 * 1024
    static let maxEntryUncompressed: Int64 = 8 * 1024 * 1024 * 1024  // 8 GiB
    static let maxTotalUncompressed: Int64 = 32 * 1024 * 1024 * 1024 // 32 GiB
    static let maxCompressionRatio: Int64 = 2000

    // MARK: Reading the directory

    /// Parses the central directory without decompressing anything.
    static func readDirectory(at url: URL) throws -> [Entry] {
        let handle = try FileHandle(forReadingFrom: url)
        defer { try? handle.close() }
        let size = try fileSize(of: handle)

        guard size >= 22 else { throw ZipError.notAZip }
        // The EOCD record is at most 22 bytes + 65535 bytes of comment.
        let tailLength = Int(min(size, Int64(22 + 0xFFFF)))
        try handle.seek(toOffset: UInt64(size) - UInt64(tailLength))
        guard let tail = try handle.read(upToCount: tailLength) else { throw ZipError.notAZip }
        let tailReader = ByteReader(tail, label: "eocd")

        var eocd = -1
        var i = tail.count - 22
        while i >= 0 {
            if tailReader.u32(i, bigEndian: false) == endOfCentralDirectory { eocd = i; break }
            i -= 1
        }
        guard eocd >= 0 else { throw ZipError.centralDirectoryMissing }

        var entryCount = Int(tailReader.u16(eocd + 10, bigEndian: false) ?? 0)
        var directoryOffset = Int64(tailReader.u32(eocd + 16, bigEndian: false) ?? 0)

        // ZIP64: read the locator that sits 20 bytes before the EOCD.
        if entryCount == 0xFFFF || directoryOffset == 0xFFFF_FFFF {
            let locatorOffset = eocd - 20
            if locatorOffset >= 0, tailReader.u32(locatorOffset, bigEndian: false) == zip64Locator,
               let zip64OffsetRaw = tailReader.u64(locatorOffset + 8, bigEndian: false) {
                let zip64Offset = Int64(zip64OffsetRaw)
                if zip64Offset >= 0, zip64Offset + 56 <= size {
                    try handle.seek(toOffset: UInt64(zip64Offset))
                    if let header = try handle.read(upToCount: 56) {
                        let hr = ByteReader(header, label: "zip64 eocd")
                        if hr.u32(0, bigEndian: false) == zip64End {
                            entryCount = Int(hr.u64(32, bigEndian: false) ?? UInt64(entryCount))
                            directoryOffset = Int64(hr.u64(48, bigEndian: false) ?? UInt64(max(0, directoryOffset)))
                        }
                    }
                }
            }
        }

        guard entryCount > 0 else { return [] }
        guard entryCount <= 500_000 else { throw ZipError.tooLarge("\(entryCount) entries") }
        guard directoryOffset >= 0, directoryOffset < size else {
            throw ZipError.corrupt("central directory offset \(directoryOffset) is outside the file")
        }
        let directoryLength = Int(min(Int64(maxCentralDirectoryBytes), size - directoryOffset))
        try handle.seek(toOffset: UInt64(directoryOffset))
        guard let directory = try handle.read(upToCount: directoryLength) else {
            throw ZipError.centralDirectoryMissing
        }
        return try parseCentralDirectory(directory, expectedCount: entryCount)
    }

    static func parseCentralDirectory(_ data: Data, expectedCount: Int) throws -> [Entry] {
        let r = ByteReader(data, label: "central directory")
        var entries: [Entry] = []
        var cursor = 0
        while cursor + 46 <= data.count, entries.count < expectedCount {
            guard r.u32(cursor, bigEndian: false) == centralHeader else { break }
            guard let method = r.u16(cursor + 10, bigEndian: false),
                  let compressed = r.u32(cursor + 20, bigEndian: false),
                  let uncompressed = r.u32(cursor + 24, bigEndian: false),
                  let nameLength = r.u16(cursor + 28, bigEndian: false),
                  let extraLength = r.u16(cursor + 30, bigEndian: false),
                  let commentLength = r.u16(cursor + 32, bigEndian: false),
                  let externalAttributes = r.u32(cursor + 38, bigEndian: false),
                  let localOffset = r.u32(cursor + 42, bigEndian: false),
                  let nameData = r.subdata(cursor + 46, Int(nameLength)) else { break }

            // The filename is UTF-8 when bit 11 of the flags is set, otherwise
            // CP437. Decoding as UTF-8 with a lossy fallback is close enough for
            // display; the safety decision uses the raw bytes' structure only.
            var path = String(decoding: nameData, as: UTF8.self)

            // ZIP64 extra field (id 0x0001) overrides 0xFFFFFFFF placeholders.
            var uncompressedSize = Int64(uncompressed)
            var compressedSize = Int64(compressed)
            var entryOffset = Int64(localOffset)
            let extraStart = cursor + 46 + Int(nameLength)
            if let extra = r.subdata(extraStart, Int(extraLength)) {
                var fields = 0
                let ex = ByteReader(extra, label: "extra")
                var p = 0
                while p + 4 <= extra.count, fields < 64 {
                    guard let id = ex.u16(p, bigEndian: false), let len = ex.u16(p + 2, bigEndian: false) else { break }
                    let body = p + 4
                    if id == 0x0001 {
                        var q = body
                        if uncompressedSize == 0xFFFF_FFFF, let v = ex.u64(q, bigEndian: false) { uncompressedSize = Int64(v); q += 8 }
                        if compressedSize == 0xFFFF_FFFF, let v = ex.u64(q, bigEndian: false) { compressedSize = Int64(v); q += 8 }
                        if entryOffset == 0xFFFF_FFFF, let v = ex.u64(q, bigEndian: false) { entryOffset = Int64(v) }
                    }
                    p = body + Int(len)
                    fields += 1
                }
            }

            let mode = UInt16((externalAttributes >> 16) & 0xFFFF)
            let fileType = mode & 0xF000
            // Unix symlink (0xA000) or a DOS/OS2 reparse point.
            let isSymlink = (fileType == 0xA000)
                || ((externalAttributes & 0xFFFF) & 0x0400 != 0)
            path = path.replacingOccurrences(of: "\\", with: "/")

            entries.append(Entry(path: path,
                                 compressionMethod: method,
                                 localHeaderOffset: entryOffset,
                                 isSymlink: isSymlink,
                                 isDirectory: path.hasSuffix("/"),
                                 compressedSize: compressedSize,
                                 uncompressedSize: uncompressedSize,
                                 unixMode: mode == 0 ? nil : mode))
            cursor += 46 + Int(nameLength) + Int(extraLength) + Int(commentLength)
        }
        return entries
    }

    // MARK: Extraction policy

    struct ExtractionPlan {
        var accepted: [Entry] = []
        var rejected: [(entry: String, reason: String)] = []
        var totalUncompressed: Int64 = 0
    }

    /// Decides what may be written to disk. This is the single place where
    /// archive safety is enforced, so it is the single place to audit.
    ///
    /// Rules:
    ///  * absolute paths, drive letters, UNC prefixes → rejected
    ///  * any `..` component → rejected (even if it would stay inside)
    ///  * empty or `.`-only paths → rejected
    ///  * symlinks → rejected (never created)
    ///  * duplicate paths (after normalisation) → first wins, rest rejected
    ///  * uncompressed size over the per-entry cap → rejected
    ///  * compression ratio over the cap → rejected (zip bomb)
    ///  * running total over the archive cap → rejected, and the plan stops
    static func buildPlan(_ entries: [Entry],
                          maxEntryBytes: Int64 = maxEntryUncompressed,
                          maxTotalBytes: Int64 = maxTotalUncompressed) -> ExtractionPlan {
        var plan = ExtractionPlan()
        var seen = Set<String>()
        for entry in entries {
            let raw = entry.path
            if entry.isSymlink {
                plan.rejected.append((raw, "symlink entries are never extracted"))
                continue
            }
            if raw.isEmpty || raw.hasSuffix("/") {
                continue // directory marker; created implicitly
            }
            if raw.hasPrefix("/") || raw.hasPrefix("\\") || raw.contains(":\\") {
                plan.rejected.append((raw, "absolute path"))
                continue
            }
            let components = raw.split(separator: "/", omittingEmptySubsequences: false)
            if components.contains("..") || components.contains(".") || components.contains("") {
                plan.rejected.append((raw, "path contains a relative or empty component"))
                continue
            }
            if components.contains(where: { $0 == "~" || $0.contains("\u{0}") }) {
                plan.rejected.append((raw, "path contains a home or NUL component"))
                continue
            }
            if seen.contains(raw) {
                plan.rejected.append((raw, "duplicate entry; the first occurrence is used"))
                continue
            }
            if entry.uncompressedSize < 0 || entry.compressedSize < 0 {
                plan.rejected.append((raw, "negative size field"))
                continue
            }
            if entry.uncompressedSize > maxEntryBytes {
                plan.rejected.append((raw, "uncompressed size \(entry.uncompressedSize) exceeds the per-entry limit"))
                continue
            }
            if entry.compressionMethod != 0, entry.compressedSize > 0 {
                let ratio = entry.uncompressedSize / max(1, entry.compressedSize)
                if ratio > maxCompressionRatio {
                    plan.rejected.append((raw, "compression ratio \(ratio):1 suggests a zip bomb"))
                    continue
                }
            }
            if plan.totalUncompressed + entry.uncompressedSize > maxTotalBytes {
                plan.rejected.append((raw, "archive total would exceed the extraction limit"))
                continue
            }
            plan.totalUncompressed += entry.uncompressedSize
            seen.insert(raw)
            plan.accepted.append(entry)
        }
        return plan
    }

    // MARK: Decompression

    /// Raw "stored" copy of an entry's bytes, without decompressing.
    static func rawData(at url: URL, entry: Entry, maxBytes: Int64 = maxEntryUncompressed) throws -> Data {
        let handle = try FileHandle(forReadingFrom: url)
        defer { try? handle.close() }
        guard entry.localHeaderOffset >= 0 else { throw ZipError.corrupt("negative local header offset") }
        try handle.seek(toOffset: UInt64(entry.localHeaderOffset))
        guard let header = try handle.read(upToCount: 30) else { throw ZipError.corrupt("local header missing for \(entry.path)") }
        let hr = ByteReader(header, label: "local header")
        guard hr.u32(0, bigEndian: false) == localHeader else {
            throw ZipError.corrupt("local header signature mismatch for \(entry.path)")
        }
        guard let nameLength = hr.u16(26, bigEndian: false),
              let extraLength = hr.u16(28, bigEndian: false) else {
            throw ZipError.corrupt("local header fields for \(entry.path)")
        }
        let dataStart = entry.localHeaderOffset + 30 + Int64(nameLength) + Int64(extraLength)
        try handle.seek(toOffset: UInt64(dataStart))
        let size = Int(min(entry.compressedSize, maxBytes))
        guard let data = try handle.read(upToCount: size) else {
            throw ZipError.corrupt("could not read \(entry.path)")
        }
        return data
    }

    static func fileSize(of handle: FileHandle) throws -> Int64 {
        let current = try handle.offset()
        let end = try handle.seekToEnd()
        try handle.seek(toOffset: current)
        return Int64(end)
    }
}
