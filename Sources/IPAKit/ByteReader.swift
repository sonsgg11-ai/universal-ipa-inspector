import Foundation

/// Bounds-checked little/big-endian byte reader over a `Data` buffer.
///
/// Every accessor returns an Optional and never traps, so hostile input can be
/// parsed without pre-validation. `label` exists purely for debugging: pass the
/// artifact name in so a breakpoint on a bad read can identify the file.
struct ByteReader {
    let data: Data
    let label: String

    init(_ data: Data, label: String) {
        self.data = data
        self.label = label
    }

    var count: Int { data.count }

    /// True when `length` bytes starting at `offset` lie entirely in the buffer.
    func fits(_ offset: Int, _ length: Int) -> Bool {
        guard offset >= 0, length >= 0 else { return false }
        return length <= data.count - offset
    }

    // MARK: Numeric reads

    func u8(_ offset: Int) -> UInt8? {
        guard fits(offset, 1) else { return nil }
        return data.withUnsafeBytes { $0.loadUnaligned(fromByteOffset: offset, as: UInt8.self) }
    }

    func u16(_ offset: Int, bigEndian: Bool) -> UInt16? {
        guard fits(offset, 2) else { return nil }
        let raw = data.withUnsafeBytes { $0.loadUnaligned(fromByteOffset: offset, as: UInt16.self) }
        return bigEndian ? UInt16(bigEndian: raw) : raw
    }

    func u32(_ offset: Int, bigEndian: Bool) -> UInt32? {
        guard fits(offset, 4) else { return nil }
        let raw = data.withUnsafeBytes { $0.loadUnaligned(fromByteOffset: offset, as: UInt32.self) }
        return bigEndian ? UInt32(bigEndian: raw) : raw
    }

    func u64(_ offset: Int, bigEndian: Bool) -> UInt64? {
        guard fits(offset, 8) else { return nil }
        let raw = data.withUnsafeBytes { $0.loadUnaligned(fromByteOffset: offset, as: UInt64.self) }
        return bigEndian ? UInt64(bigEndian: raw) : raw
    }

    /// Reads an unsigned integer of an arbitrary width (1, 2, 4 or 8 bytes).
    func uint(_ offset: Int, size: Int, bigEndian: Bool) -> UInt64? {
        switch size {
        case 1: return u8(offset).map(UInt64.init)
        case 2: return u16(offset, bigEndian: bigEndian).map(UInt64.init)
        case 4: return u32(offset, bigEndian: bigEndian).map(UInt64.init)
        case 8: return u64(offset, bigEndian: bigEndian)
        default: return nil
        }
    }

    // MARK: Bytes and strings

    func subdata(_ offset: Int, _ length: Int) -> Data? {
        guard fits(offset, length) else { return nil }
        let start = data.startIndex + offset
        return data.subdata(in: start..<(start + length))
    }

    /// NUL-terminated printable-ASCII string at `offset`.
    ///
    /// Returns nil when the offset is outside the buffer; an empty string when
    /// the first byte is not printable. The scan stops at the first byte that
    /// is NUL or outside 0x20..<0x7F, so embedded binary never leaks into names.
    func cString(_ offset: Int, limit: Int = 4096) -> String? {
        guard offset >= 0, offset < data.count else { return nil }
        var bytes: [UInt8] = []
        let end = min(data.count, offset + max(limit, 0))
        var i = offset
        while i < end {
            let b = data.withUnsafeBytes { $0.loadUnaligned(fromByteOffset: i, as: UInt8.self) }
            if b == 0 || b < 0x20 || b >= 0x7F { break }
            bytes.append(b)
            i += 1
        }
        return String(decoding: bytes, as: UTF8.self)
    }

    /// Printable ASCII runs of at least `minLength` bytes, in order.
    ///
    /// A run that ends on a NUL counts its terminator towards the length, which
    /// is what the classic `strings(1)` byte accounting does. Scanning stops
    /// after `maxBytes` of input or after `limit` strings, whichever comes first.
    func asciiStrings(minLength: Int = 4, limit: Int = 200_000, maxBytes: Int = 1 << 30) -> [String] {
        var out: [String] = []
        var current: [UInt8] = []
        let scanned = min(data.count, max(maxBytes, 0))

        func flush(terminatedByNul: Bool) {
            let effectiveLength = current.count + (terminatedByNul ? 1 : 0)
            if effectiveLength >= minLength, !current.isEmpty {
                out.append(String(decoding: current, as: UTF8.self))
            }
            current.removeAll(keepingCapacity: true)
        }

        var i = 0
        while i < scanned {
            if out.count >= limit { break }
            let b = data.withUnsafeBytes { $0.loadUnaligned(fromByteOffset: i, as: UInt8.self) }
            if b >= 0x20 && b < 0x7F {
                current.append(b)
            } else if b == 0 {
                flush(terminatedByNul: true)
            } else {
                flush(terminatedByNul: false)
            }
            i += 1
        }
        if out.count < limit { flush(terminatedByNul: false) }
        return out
    }
}
