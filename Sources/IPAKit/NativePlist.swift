import Foundation

/// Robust property-list reading.
///
/// `PropertyListSerialization` is used behind strict error handling so a
/// malformed or encrypted plist yields `nil` instead of an exception, and
/// values are rendered with a single consistent describer.
enum NativePlist {

    enum PlistError: Error {
        case notAPropertyList
    }

    /// Parses a plist (binary or XML) into a dictionary, or nil.
    static func dictionary(_ data: Data) -> [String: Any]? {
        guard !data.isEmpty else { return nil }
        guard let any = parse(data) else { return nil }
        return any as? [String: Any]
    }

    /// Parses any plist value, or nil on malformed input.
    static func parse(_ data: Data) -> Any? {
        guard !data.isEmpty else { return nil }
        // Reject obvious non-plists fast (performance + avoids deep decoder
        // work on hostile input).
        let head = [UInt8](data.prefix(64))
        let isXML = Array(head.prefix(5).map { Character(UnicodeScalar($0)) }) == ["<", "?", "x", "m", "l"]
        let isBinary = head.count >= 8 && head[0] == 0x62 && head[1] == 0x70 && head[2] == 0x6C && head[3] == 0x69
            && head[4] == 0x73 && head[5] == 0x74 && head[6] == 0x30 && head[7] == 0x30
        guard isXML || isBinary else { return nil }

        var format = PropertyListSerialization.PropertyListFormat.openStep
        do {
            let any = try PropertyListSerialization.propertyList(
                from: data, options: [.mutableContainers], format: &format)
            return any
        } catch {
            return nil
        }
    }

    /// One-line human description of an arbitrary plist value, with limits so
    /// a giant value cannot flood the report.
    static func describe(_ value: Any, maxItems: Int = 24) -> String {
        switch value {
        case let s as String:
            return s.count > 800 ? String(s.prefix(800)) + " …" : s
        case let b as Bool:
            return b ? "true" : "false"
        case let n as NSNumber:
            return n.stringValue
        case let i as Int:
            return String(i)
        case let d as Double:
            return String(d)
        case let date as Date:
            return ISO8601DateFormatter().string(from: date)
        case let data as Data:
            return "<\(data.count) bytes of data>"
        case let array as [Any]:
            if array.isEmpty { return "(empty list)" }
            let items = array.prefix(maxItems).map { describe($0, maxItems: 6) }
            let more = array.count > maxItems ? " … (+\(array.count - maxItems))" : ""
            return items.joined(separator: ", ") + more
        case let dict as [String: Any]:
            if dict.isEmpty { return "(empty dictionary)" }
            let keys = dict.keys.sorted().prefix(maxItems)
            let items = keys.map { "\($0): \(describe(dict[$0] ?? "", maxItems: 6))" }
            let more = dict.count > maxItems ? " … (+\(dict.count - maxItems))" : ""
            return items.joined(separator: "\n") + more
        default:
            return String(describing: value).prefix(400).description
        }
    }

    /// Extracts the plist XML embedded in a CMS-signed mobileprovision blob.
    static func plistRange(in data: Data) -> Data? {
        guard let start = data.range(of: Data("<?xml".utf8)),
              let end = data.range(of: Data("</plist>".utf8), in: start.lowerBound..<data.endIndex)
        else { return nil }
        return data.subdata(in: start.lowerBound..<end.upperBound)
    }
}
