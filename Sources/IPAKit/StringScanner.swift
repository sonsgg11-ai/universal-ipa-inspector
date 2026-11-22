import Foundation

/// Extracts printable strings from a binary on disk, bounded by `maxBytes` so
/// peak memory stays predictable on a phone.
struct StringScanner {

    let url: URL
    let maxBytes: Int

    init(url: URL, maxBytes: Int) {
        self.url = url
        self.maxBytes = max(0, maxBytes)
    }

    /// Returns the printable ASCII strings of the file, in order.
    /// An unreadable or empty file yields an empty list, not an error.
    func strings() -> [String] {
        guard maxBytes > 0 else { return [] }
        guard let handle = try? FileHandle(forReadingFrom: url) else { return [] }
        defer { try? handle.close() }
        guard let data = try? handle.read(upToCount: maxBytes), !data.isEmpty else { return [] }
        return ByteReader(data, label: url.lastPathComponent)
            .asciiStrings(minLength: 5, limit: 20_000, maxBytes: data.count)
    }
}
