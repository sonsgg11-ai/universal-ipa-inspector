import Foundation
#if canImport(ZIPFoundation)
import ZIPFoundation
#endif

/// Streams deflated ZIP entries to disk through ZIPFoundation.
///
/// One pass over the archive builds a path→entry map that is reused for every
/// deflated entry, so extraction never degenerates into an O(n²) directory
/// scan. Bytes flow chunk by chunk from the archive to the destination file
/// handle: nothing is ever buffered whole, so a multi-gigabyte entry extracts
/// with bounded memory.
///
/// The destination file is *created first*. Writing through
/// `FileHandle(forWritingTo:)` on a path that does not exist is a silent
/// failure (and historically an exception on Apple platforms), which is
/// exactly the bug this extractor replaces.
struct DeflateExtractor {

    private enum Backing {
        #if canImport(ZIPFoundation)
        case zip(Archive, [String: Entry])
        #endif
        case none
    }
    private let backing: Backing

    /// Scans the archive's central directory once. When the archive cannot be
    /// opened or ZIPFoundation is unavailable in this build, the extractor
    /// reports `isAvailable == false` instead of failing the whole import.
    init(archiveURL: URL) {
        #if canImport(ZIPFoundation)
        if let archive = try? Archive(url: archiveURL, accessMode: .read) {
            var map: [String: Entry] = [:]
            for entry in archive { map[entry.path] = entry }
            backing = .zip(archive, map)
            return
        }
        #endif
        backing = .none
    }

    var isAvailable: Bool {
        #if canImport(ZIPFoundation)
        if case .zip = backing { return true }
        #endif
        return false
    }

    /// Streams `entry` (a `ZipArchive.Entry` from our own central-directory
    /// reader) to `destination`. Returns the number of bytes written, or nil
    /// when the entry could not be located. The caller treats nil as a
    /// warning, not as success.
    @discardableResult
    func stream(entry: ZipArchive.Entry,
                to destination: URL,
                bufferSize: Int = 1 << 20) throws -> Int64? {
        #if canImport(ZIPFoundation)
        guard case .zip(let archive, let entries) = backing,
              let zfEntry = entries[entry.path] else { return nil }

        FileManager.default.createFile(atPath: destination.path, contents: nil, attributes: nil)
        let out = try FileHandle(forWritingTo: destination)
        var written: Int64 = 0
        do {
            _ = try archive.extract(zfEntry, bufferSize: bufferSize, skipCRC32: true, consumer: { chunk in
                try out.write(contentsOf: chunk)
                written += Int64(chunk.count)
            })
        } catch {
            try? out.close()
            try? FileManager.default.removeItem(at: destination)
            throw error
        }
        try? out.close()
        return written
        #else
        return nil
        #endif
    }
}
