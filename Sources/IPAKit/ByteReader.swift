import Foundation

/// Bounds-checked cursor over a byte buffer.
///
/// Every read returns `nil` instead of crashing when the range is out of
/// bounds. Malformed files are the norm in this domain, not the exception:
/// the reader is the single place where "the file ends here" is enforced.
final class ByteReader {
    let data: Data
    let label: String

    init(_ data: Data, label: String = "data") {
        self.data = data
        self.label = label
    }

    var count: Int { data.count }

    /// `true` when `offset + length` fits inside the buffer.
    func fits(_ offset: Int, _ length: Int) -> Bool {
        offset >= 0 && length >= 0 && offset + length <= data.count
    }

    func u8(_ offset: Int) -> UInt8? {
        guard fits(offset, 1) else { return nil }
        return data[data.startIndex + offset]
    }

    func u16(_ offset: Int, bigEndian: Bool) -> UInt16? {
        guard fits(offset, 2) else { return nil }
        let b0 = UInt16(data[data.startIndex + offset])
        let b1 = UInt16(data[data.startIndex + offset + 1])
        return bigEndian ? (b0 << 8) | b1 : (b1 << 8) | b0
    }

    func u32(_ offset: Int, bigEndian: Bool) -> UInt32? {
        guard fits(offset, 4) else { return nil }
        var value: UInt32 = 0
        for i in 0..<4 {
            let byte = UInt32(data[data.startIndex + offset + i])
            value |= bigEndian ? byte << (24 - i * 8) : byte << (i * 8)
        }
        return value
    }

    func u64(_ offset: Int, bigEndian: Bool) -> UInt64? {
        guard fits(offset, 8) else { return nil }
        var value: UInt64 = 0
        for i in 0..<8 {
            let byte = UInt64(data[data.startIndex + offset + i])
            value |= bigEndian ? byte << (56 - i * 8) : byte << (i * 8)
        }
        return value
    }

    /// Unsigned read of an arbitrary small size (4 or 8 bytes in practice).
    func uint(_ offset: Int, size: Int, bigEndian: Bool) -> UInt64? {
        switch size {
        case 4: return u32(offset, bigEndian: bigEndian).map { UInt64($0) }
        case 8: return u64(offset, bigEndian: bigEndian)
        default:
            guard size > 0, size <= 8, fits(offset, size) else { return nil }
            var value: UInt64 = 0
            for i in 0..<size {
                let byte = UInt64(data[data.startIndex + offset + i])
                value |= bigEndian ? byte << UInt64((size - 1 - i) * 8) : byte << UInt64(i * 8)
            }
            return value
        }
    }

    func subdata(_ offset: Int, _ length: Int) -> Data? {
        guard length >= 0, fits(offset, length) else { return nil }
        return data.subdata(in: (data.startIndex + offset)..<(data.startIndex + offset + length))
    }

    /// NUL-terminated string at `offset`.
    ///
    /// Returns `nil` when the offset is out of bounds and an empty string when
    /// no NUL terminator is found within the limit (an unterminated field is
    /// not a trustworthy string).
    func cString(_ offset: Int, limit: Int = 4096) -> String? {
        guard offset >= 0, offset < count else { return nil }
        let end = min(count, offset + limit)
        var bytes: [UInt8] = []
        for i in offset..<end {
            let b = data[data.startIndex + i]
            if b == 0 {
                return String(decoding: bytes, as: UTF8.self)
            }
            bytes.append(b)
        }
        // No terminator within the limit: treat the field as invalid.
        return ""
    }

    /// Printable ASCII runs of at least `minLength` bytes, scanning at most
    /// `maxBytes` from the start and emitting at most `limit` strings.
    func asciiStrings(minLength: Int = 6, limit: Int = 200_000, maxBytes: Int = Int.max) -> [String] {
        guard minLength > 0 else { return [] }
        var out: [String] = []
        var current: [UInt8] = []
        let bound = min(count, maxBytes)
        for i in 0..<bound {
            let b = data[data.startIndex + i]
            if b >= 0x20 && b < 0x7F {
                current.append(b)
            } else {
                // A NUL-terminated run counts its terminator towards the
                // minimum length (C-string semantics).
                let effective = (b == 0) ? current.count + 1 : current.count
                if effective >= minLength, !current.isEmpty {
                    out.append(String(decoding: current, as: UTF8.self))
                    if out.count >= limit { return out }
                }
                current.removeAll(keepingCapacity: true)
            }
        }
        if current.count >= minLength, out.count < limit {
            out.append(String(decoding: current, as: UTF8.self))
        }
        return out
    }
}
