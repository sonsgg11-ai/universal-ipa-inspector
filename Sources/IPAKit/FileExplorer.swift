import Foundation

/// File-type classification, metadata, streaming previews and the hex
/// workbench. Strictly read-only: nothing in this module writes to, moves or
/// renames anything inside the analysed bundle.
enum FileExplorer {

    // MARK: Classification

    enum FileNodeType: String, Codable, CaseIterable, Sendable {
        case executable
        case dynamicLibrary = "dynamic library"
        case framework
        case script
        case configuration = "configuration"
        case plist
        case json
        case xml
        case strings
        case database
        case certificate
        case provisioning = "provisioning profile"
        case image
        case audio
        case video
        case font
        case archive
        case text
        case binary
        case unknown

        var isPreviewableAsText: Bool {
            switch self {
            case .configuration, .plist, .json, .xml, .strings, .text, .script:
                return true
            default:
                return false
            }
        }
    }

    /// Classifies a file from its path, size and header bytes.
    static func classify(path: String, size: Int64, head: Data?) -> FileNodeType {
        let ext = (path as NSString).pathExtension.lowercased()
        let name = ((path as NSString).lastPathComponent).lowercased()

        switch ext {
        case "dylib": return .dynamicLibrary
        case "plist": return .plist
        case "json": return .json
        case "xml", "xcprivacy", "entitlements", "sb": return .xml
        case "strings", "stringsdict": return .strings
        case "sqlitedb", "sqlite", "db", "realm", "wal", "shm": return .database
        case "cer", "crt", "pem", "der", "p12", "keychain": return .certificate
        case "mobileprovision": return .provisioning
        case "png", "jpg", "jpeg", "gif", "webp", "heic", "bmp", "tiff", "ico", "pdf": return .image
        case "mp3", "m4a", "aac", "wav", "ogg", "caf", "flac": return .audio
        case "mp4", "mov", "m4v", "avi", "mkv": return .video
        case "ttf", "otf", "woff", "woff2": return .font
        case "zip", "gz", "car", "lproj", "ipa": return .archive
        case "txt", "md", "log", "rtf": return .text
        case "html", "htm", "css": return .text
        case "js", "sh", "bash", "py", "rb", "lua": return .script
        case "yaml", "yml", "ini", "cfg", "conf", "config", "properties", "csv": return .configuration
        default: break
        }
        if name == "info.plist" { return .plist }
        if name == "embedded.mobileprovision" { return .provisioning }
        if name.hasPrefix("_codechecksum") || name == "code_resources" { return .plist }
        if name == "localizable" { return .strings }

        // Header sniffing for extension-less files (executables etc.).
        if let head, head.count >= 4 {
            let r = ByteReader(head, label: "classify")
            if let le = r.u32(0, bigEndian: false) {
                if le == MachO.magic32 || le == MachO.magic64
                    || le == MachO.magic32Swapped || le == MachO.magic64Swapped {
                    return path.contains(".framework/") ? .executable : .executable
                }
            }
            if let be = r.u32(0, bigEndian: true), be == MachO.fatMagic || be == MachO.fat64Magic {
                return .executable
            }
            // SQLite magic "SQLite format 3"
            if head.count >= 16, String(data: head.prefix(15), encoding: .ascii) == "SQLite format 3" {
                return .database
            }
            // PK zip archive
            if head.count >= 2, head[head.startIndex] == 0x50, head[head.startIndex + 1] == 0x4B {
                return .archive
            }
        }
        if size > 4096 { return .binary }
        if let head, !head.isEmpty,
           head.allSatisfy({ ($0 >= 0x20 && $0 < 0x7F) || $0 == 0x0A || $0 == 0x0D || $0 == 0x09 }) {
            return .text
        }
        return .unknown
    }

    // MARK: Metadata

    struct FileMetadata: Identifiable, Codable, Sendable {
        var id: String { path }
        let path: String
        let size: Int64
        let compressedSize: Int64
        let compressionRatio: Double
        let permissions: String
        let location: String          // BundleRole raw value
        let nodeType: FileNodeType
        let isMachO: Bool
        let sha256: String?
    }

    /// Builds the full inventory from extraction results plus the archive's
    /// central directory (which holds compressed sizes).
    static func buildInventory(files: [FileEntry],
                               archiveEntries: [ZipArchive.Entry],
                               extractionRoot: URL,
                               maxHashedFiles: Int = 200,
                               isCancelled: () -> Bool = { false }) -> [FileMetadata] {
        let compressed: [String: Int64] = Dictionary(
            archiveEntries.map { ($0.path, $0.compressedSize) },
            uniquingKeysWith: { first, _ in first })

        var hashed = 0
        var result: [FileMetadata] = []
        result.reserveCapacity(files.count)
        for file in files {
            if isCancelled() { break }
            let url = extractionRoot.appendingPathComponent(file.path)
            var head: Data?
            if let handle = try? FileHandle(forReadingFrom: url) {
                head = try? handle.read(upToCount: 64)
                try? handle.close()
            }
            let nodeType = classify(path: file.path, size: file.size, head: head)
            let permString = permissions(of: url)

            var sha: String?
            let hashable = nodeType == .executable || nodeType == .dynamicLibrary
                || file.size <= 1_000_000
            if hashable, hashed < maxHashedFiles {
                sha = try? FileHasher.sha256(of: url)
                hashed += 1
            }

            let comp = compressed[file.path] ?? file.size
            let ratio = comp > 0 ? Double(file.size) / Double(comp) : 1.0
            result.append(FileMetadata(
                path: file.path,
                size: file.size,
                compressedSize: comp,
                compressionRatio: ratio,
                permissions: permString,
                location: file.kind,
                nodeType: nodeType,
                isMachO: nodeType == .executable || nodeType == .dynamicLibrary,
                sha256: sha))
        }
        return result
    }

    static func permissions(of url: URL) -> String {
        guard let attrs = try? FileManager.default.attributesOfItem(atPath: url.path),
              let mode = attrs[.posixPermissions] as? NSNumber else { return "---------" }
        let m = mode.intValue
        var out = ""
        for shift in [6, 3, 0] {
            let bits = (m >> shift) & 0o7
            out += (bits & 4) != 0 ? "r" : "-"
            out += (bits & 2) != 0 ? "w" : "-"
            out += (bits & 1) != 0 ? "x" : "-"
        }
        return out
    }

    // MARK: Previews

    enum Preview: Sendable {
        case text(String, truncated: Bool)
        case binary(totalBytes: Int64, reason: String)
        case image(totalBytes: Int64)
        case unavailable(String)
    }

    /// Renders a read-only preview of a file. Large files are truncated at
    /// `maxBytes` and say so; nothing here ever mutates the source.
    static func preview(path: String,
                        extractionRoot: URL,
                        maxBytes: Int = 256 * 1024) -> Preview {
        let url = extractionRoot.appendingPathComponent(path)
        guard FileManager.default.fileExists(atPath: url.path) else {
            return .unavailable("File not found in the extracted bundle.")
        }
        let attrs = try? FileManager.default.attributesOfItem(atPath: url.path)
        let size = (attrs?[.size] as? NSNumber)?.int64Value ?? 0

        guard let handle = try? FileHandle(forReadingFrom: url) else {
            return .unavailable("The file could not be opened for reading.")
        }
        defer { try? handle.close() }
        guard let chunk = try? handle.read(upToCount: maxBytes) else {
            return .unavailable("The file could not be read.")
        }

        let type = classify(path: path, size: size, head: chunk.prefix(64))
        switch type {
        case .image:
            return .image(totalBytes: size)
        case .plist, .json, .xml:
            if let dict = NativePlist.parse(chunk.prefix(min(Int(size), maxBytes))),
               let xml = try? PropertyListSerialization.data(fromPropertyList: dict, format: .xml, options: 0),
               let text = String(data: xml, encoding: .utf8) {
                return .text(text, truncated: size > maxBytes)
            }
            if let text = String(data: chunk, encoding: .utf8) {
                return .text(text, truncated: size > maxBytes)
            }
            return .binary(totalBytes: size, reason: "unreadable \(type.rawValue) data")
        default:
            if let text = String(data: chunk, encoding: .utf8), type.isPreviewableAsText || type == .text {
                return .text(text, truncated: size > maxBytes)
            }
            // Fallback: show strings from binary content.
            let strings = ByteReader(chunk, label: "preview")
                .asciiStrings(minLength: 6, limit: 400, maxBytes: maxBytes)
            if !strings.isEmpty {
                return .text(strings.joined(separator: "\n"),
                             truncated: size > maxBytes)
            }
            return .binary(totalBytes: size, reason: "no readable text found in the first \(maxBytes) bytes")
        }
    }

    // MARK: Hex workbench

    struct HexChunk: Sendable {
        let startOffset: Int64
        let bytes: [UInt8]
        var lines: [HexLine] {
            stride(from: 0, to: bytes.count, by: 16).map { rowStart -> HexLine in
                let row = Array(bytes[rowStart..<min(rowStart + 16, bytes.count)])
                let hex = row.map { String(format: "%02x", $0) }
                    .joined(separator: " ")
                let ascii = row.map { b -> String in
                    (b >= 0x20 && b < 0x7F) ? String(UnicodeScalar(b)) : "."
                }.joined()
                return HexLine(offset: startOffset + Int64(rowStart),
                               hex: hex,
                               ascii: ascii)
            }
        }
    }

    struct HexLine: Identifiable, Sendable {
        let offset: Int64
        let hex: String
        let ascii: String
        var id: Int64 { offset }
    }

    /// Streams one chunk of the file for the hex viewer without loading the
    /// whole file into memory.
    static func hexChunk(path: String,
                         extractionRoot: URL,
                         offset: Int64,
                         length: Int = 512) -> HexChunk? {
        guard offset >= 0, length > 0 else { return nil }
        let url = extractionRoot.appendingPathComponent(path)
        guard let handle = try? FileHandle(forReadingFrom: url) else { return nil }
        defer { try? handle.close() }
        do {
            try handle.seek(toOffset: UInt64(offset))
        } catch {
            return nil
        }
        guard let data = try? handle.read(upToCount: length), !data.isEmpty else { return nil }
        return HexChunk(startOffset: offset, bytes: [UInt8](data))
    }

    enum HexSearchError: Error, LocalizedError {
        case invalidHexPattern
        case emptyPattern

        var errorDescription: String? {
            switch self {
            case .invalidHexPattern: return "The hex pattern must contain an even number of hexadecimal digits."
            case .emptyPattern: return "Enter a pattern to search for."
            }
        }
    }

    /// Searches a file for a byte sequence (hex or ASCII). Scans in windows
    /// with overlap so matches at window boundaries are not missed, capped by
    /// `maxMatches` and `maxScanBytes` so huge files stay responsive.
    static func searchBytes(path: String,
                            extractionRoot: URL,
                            pattern: Data,
                            maxMatches: Int = 200,
                            maxScanBytes: Int64 = 64 * 1024 * 1024) throws -> [Int64] {
        guard !pattern.isEmpty else { throw HexSearchError.emptyPattern }
        let url = extractionRoot.appendingPathComponent(path)
        guard let handle = try? FileHandle(forReadingFrom: url) else { return [] }
        defer { try? handle.close() }

        let windowSize = 1 << 20
        let overlap = Int64(pattern.count - 1)
        var matches: [Int64] = []
        var base: Int64 = 0
        var carry = Data()

        while matches.count < maxMatches {
            let chunk = try handle.read(upToCount: windowSize) ?? Data()
            if chunk.isEmpty { break }
            let window = carry + chunk
            if let first = window.range(of: pattern) {
                var position = window.distance(from: window.startIndex, to: first.lowerBound)
                // Collect all matches within this window.
                while let found = window.range(of: pattern, in: position..<window.count) {
                    let at = window.distance(from: window.startIndex, to: found.lowerBound)
                    matches.append(base + Int64(at - carry.count))
                    if matches.count >= maxMatches { break }
                    position = found.lowerBound + max(1, pattern.count)
                }
            }
            base += Int64(chunk.count)
            carry = window.suffix(Int(overlap))
            if base >= maxScanBytes { break }
        }
        return matches
    }

    /// Parses a hex string ("de ad be ef", "0xdeadbeef") into bytes.
    static func parseHexPattern(_ text: String) throws -> Data {
        let cleaned = text
            .replacingOccurrences(of: "0x", with: "")
            .filter { $0.isHexDigit }
        guard !cleaned.isEmpty else { throw HexSearchError.emptyPattern }
        guard cleaned.count % 2 == 0 else { throw HexSearchError.invalidHexPattern }
        var bytes: [UInt8] = []
        var index = cleaned.startIndex
        while index < cleaned.endIndex {
            let next = cleaned.index(index, offsetBy: 2)
            if let byte = UInt8(cleaned[index..<next], radix: 16) {
                bytes.append(byte)
            } else {
                throw HexSearchError.invalidHexPattern
            }
            index = next
        }
        return Data(bytes)
    }

    /// Searches for ASCII text in the file.
    static func searchText(path: String,
                           extractionRoot: URL,
                           text: String,
                           caseSensitive: Bool = true,
                           maxMatches: Int = 200,
                           maxScanBytes: Int64 = 64 * 1024 * 1024) throws -> [Int64] {
        let pattern: Data
        if caseSensitive {
            pattern = Data(text.utf8)
        } else {
            pattern = Data(text.lowercased().utf8)
        }
        guard caseSensitive else {
            // Case-insensitive: scan lowercased windows.
            return try searchLowercased(path: path, extractionRoot: extractionRoot,
                                        text: text.lowercased(),
                                        maxMatches: maxMatches, maxScanBytes: maxScanBytes)
        }
        return try searchBytes(path: path, extractionRoot: extractionRoot,
                               pattern: pattern, maxMatches: maxMatches,
                               maxScanBytes: maxScanBytes)
    }

    private static func searchLowercased(path: String,
                                         extractionRoot: URL,
                                         text: String,
                                         maxMatches: Int,
                                         maxScanBytes: Int64) throws -> [Int64] {
        // Lowercase only ASCII letters byte-wise, preserving offsets.
        let url = extractionRoot.appendingPathComponent(path)
        guard let handle = try? FileHandle(forReadingFrom: url) else { return [] }
        defer { try? handle.close() }
        let pattern = [UInt8](Data(text.utf8))
        var matches: [Int64] = []
        var base: Int64 = 0
        var window = [UInt8]()
        let windowSize = 1 << 20
        let overlap = max(0, pattern.count - 1)

        while matches.count < maxMatches {
            let chunk = (try? handle.read(upToCount: windowSize)) ?? Data()
            if chunk.isEmpty { break }
            window.append(contentsOf: [UInt8](chunk).map { asciiLower($0) })
            if window.count > windowSize * 2 {
                window.removeFirst(max(0, window.count - windowSize - overlap))
                base += Int64(windowSize)
            }
            // naive search
            if pattern.count <= window.count {
                var i = 0
                let limit = window.count - pattern.count
                while i <= limit {
                    if window[i] == pattern[0] {
                        var ok = true
                        for j in 1..<pattern.count where window[i + j] != pattern[j] {
                            ok = false
                            break
                        }
                        if ok {
                            matches.append(base + Int64(i))
                            if matches.count >= maxMatches { return matches }
                            i += pattern.count
                            continue
                        }
                    }
                    i += 1
                }
            }
            if base >= maxScanBytes { break }
        }
        return matches
    }

    private static func asciiLower(_ byte: UInt8) -> UInt8 {
        (byte >= 0x41 && byte <= 0x5A) ? byte + 32 : byte
    }
}
