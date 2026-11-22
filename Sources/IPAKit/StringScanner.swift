import Foundation

/// Extracts printable strings from a file on disk with bounded memory use.
///
/// The file is streamed in chunks; only the trailing partial run is carried
/// between chunks, so peak memory stays at roughly one chunk regardless of
/// file size.
struct StringScanner {
    let url: URL
    let maxBytes: Int
    var chunkSize: Int = 256 * 1024
    var minLength: Int = 6
    var limit: Int = 200_000

    struct StreamedStrings: Sendable {
        var strings: [String]
        var scannedBytes: Int
        var truncated: Bool
    }

    /// Reads up to `maxBytes` of the file and returns printable ASCII runs.
    func strings() -> [String] {
        streamed().strings
    }

    func streamed() -> StreamedStrings {
        guard let handle = try? FileHandle(forReadingFrom: url) else { return .init(strings: [], scannedBytes: 0, truncated: false) }
        defer { try? handle.close() }

        var out: [String] = []
        var carry: [UInt8] = []
        var scanned = 0
        var truncated = false

        while scanned < maxBytes {
            let want = min(chunkSize, maxBytes - scanned)
            guard let chunk = try? handle.read(upToCount: want), !chunk.isEmpty else { break }
            scanned += chunk.count
            let bytes = [UInt8](chunk)
            for b in bytes {
                if b >= 0x20 && b < 0x7F {
                    carry.append(b)
                } else {
                    if carry.count >= minLength {
                        out.append(String(decoding: carry, as: UTF8.self))
                        if out.count >= limit {
                            truncated = true
                            return .init(strings: out, scannedBytes: scanned, truncated: truncated)
                        }
                    }
                    carry.removeAll(keepingCapacity: true)
                }
            }
            if chunk.count < want { break }
        }
        if carry.count >= minLength, out.count < limit {
            out.append(String(decoding: carry, as: UTF8.self))
        }
        return .init(strings: out, scannedBytes: scanned, truncated: out.count >= limit)
    }
}
