import Foundation

/// Property-list reading and human-readable description.
///
/// A thin wrapper over PropertyListSerialization so every caller shares the
/// same parsing and the same value formatting, and so the eventual switch to a
/// hand-written parser (if one is ever needed) touches a single file.
enum NativePlist {

    /// Parses any property list (XML or binary). Returns nil on failure.
    static func parse(_ data: Data) -> Any? {
        try? PropertyListSerialization.propertyList(from: data, format: nil)
    }

    /// Parses a property list whose root is a dictionary.
    static func dictionary(_ data: Data) -> [String: Any]? {
        parse(data) as? [String: Any]
    }

    /// Renders a plist value the way a human would want to read it: strings
    /// bare, booleans as true/false, dates ISO-8601, containers pretty-printed.
    static func describe(_ value: Any) -> String {
        switch value {
        case let string as String:
            return string
        case let bool as Bool:
            return bool ? "true" : "false"
        case let number as NSNumber:
            return describeNumber(number)
        case let date as Date:
            return ISO8601DateFormatter().string(from: date)
        case let bytes as Data:
            return "<\(bytes.count) bytes of binary data>"
        case let array as [Any]:
            return array.map(describe).joined(separator: ", ")
        case let dict as [String: Any]:
            return dict.sorted { $0.key < $1.key }
                .map { "\($0.key): \(describe($0.value))" }
                .joined(separator: "\n")
        default:
            return String(describing: value)
        }
    }

    private static func describeNumber(_ number: NSNumber) -> String {
        let type = String(cString: number.objCType)
        // Booleans can arrive as NSNumber with a char/bool objC type.
        if type == "c" || type == "B" {
            return number.boolValue ? "true" : "false"
        }
        if type == "f" || type == "d" {
            let value = number.doubleValue
            if value == value.rounded() && abs(value) < 1e15 {
                return String(format: "%.0f", value)
            }
            return "\(value)"
        }
        return number.stringValue
    }
}
