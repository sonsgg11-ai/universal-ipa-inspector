import Foundation

/// Binary metadata extraction: symbol tables, Objective-C name tables and
/// Swift metadata indicators. Everything is evidence-based: sections and
/// string tables are read from disk; anything inferred is labelled.
enum BinaryMetadata {

    struct ObjCInfo: Codable, Sendable {
        var classNames: [String] = []
        var methodNames: [String] = []
        var protocolNames: [String] = []
        var categories: [String] = []
        var sectionBytes: [String: Int] = [:]     // section → size
        var status: EvidenceStatus = .notFound
    }

    struct SwiftInfo: Codable, Sendable {
        var mangledTypeNames: [String] = []
        var demangledNames: [String] = []
        var moduleNames: [String] = []
        var swiftVersionStrings: [String] = []
        var metadataSections: [String: Int] = [:]
        var status: EvidenceStatus = .notFound
    }

    // MARK: Symbols

    /// Parses symbols for one binary file (opt-in pass over the same bytes).
    static func symbols(forBinaryAt url: URL) -> [SymbolEntry] {
        guard let data = try? Data(contentsOf: url, options: .mappedIfSafe) else { return [] }
        let (symbols, _) = MachOParser.parseSymbols(data)
        return symbols
    }

    // MARK: Objective-C

    static func objcInfo(extraction: ExtractionResult,
                         binaries: [BinaryInfo],
                         isCancelled: () -> Bool = { false }) -> [String: ObjCInfo] {
        var out: [String: ObjCInfo] = [:]
        for binary in binaries {
            if isCancelled() { break }
            if binary.isEncrypted {
                var info = ObjCInfo()
                info.status = .blocked
                out[binary.path] = info
                continue
            }
            let url = extraction.root.appendingPathComponent(binary.path)
            guard let data = try? Data(contentsOf: url, options: .mappedIfSafe) else { continue }

            var info = ObjCInfo()
            for (segment, section, target) in [
                ("__TEXT", "__objc_classname", "class"),
                ("__TEXT", "__objc_methname", "method"),
                ("__TEXT", "__objc_methtype", "method"),
                ("__TEXT", "__objc_protolist", "protocol"),
            ] {
                if let sectionData = MachOParser.sectionData(data, segment: segment, section: section) {
                    info.sectionBytes["\(segment),\(section)"] = sectionData.count
                    let names = ByteReader(sectionData, label: section)
                        .asciiStrings(minLength: 2, limit: 20_000)
                    switch target {
                    case "class": info.classNames.append(contentsOf: names)
                    case "method": info.methodNames.append(contentsOf: names)
                    default: info.protocolNames.append(contentsOf: names)
                    }
                }
            }
            // Categories from strings: "ClassName(Category)" in __cstring.
            if let cstrings = MachOParser.sectionData(data, segment: "__TEXT", section: "__cstring") {
                let strings = ByteReader(cstrings, label: "cstring")
                    .asciiStrings(minLength: 4, limit: 50_000)
                let categoryPattern = try? NSRegularExpression(pattern: #"^[A-Za-z_][A-Za-z0-9_]*\([A-Za-z_][A-Za-z0-9_]*\)$"#)
                for string in strings.prefix(50_000) {
                    if let regex = categoryPattern,
                       regex.firstMatch(in: string, range: NSRange(location: 0, length: (string as NSString).length)) != nil {
                        info.categories.append(string)
                    }
                }
            }
            info.status = (info.classNames.isEmpty && info.methodNames.isEmpty && info.categories.isEmpty)
                ? .notFound : .verified
            info.classNames = Array(Set(info.classNames)).sorted().prefix(2000).map { $0 }
            info.methodNames = Array(Set(info.methodNames)).sorted().prefix(2000).map { $0 }
            info.protocolNames = Array(Set(info.protocolNames)).sorted().prefix(1000).map { $0 }
            info.categories = Array(Set(info.categories)).sorted().prefix(1000).map { $0 }
            out[binary.path] = info
        }
        return out
    }

    // MARK: Swift

    static func swiftInfo(extraction: ExtractionResult,
                          binaries: [BinaryInfo],
                          isCancelled: () -> Bool = { false }) -> [String: SwiftInfo] {
        var out: [String: SwiftInfo] = [:]
        for binary in binaries {
            if isCancelled() { break }
            if binary.isEncrypted {
                var info = SwiftInfo()
                info.status = .blocked
                out[binary.path] = info
                continue
            }
            let url = extraction.root.appendingPathComponent(binary.path)
            guard let data = try? Data(contentsOf: url, options: .mappedIfSafe) else { continue }

            var info = SwiftInfo()

            // Metadata section inventory (sizes only; full decoding is out of
            // scope and honestly reported).
            for section in ["__swift5_types", "__swift5_protos", "__swift5_proto",
                            "__swift5_fieldmd", "__swift5_assocty", "__swift5_replace",
                            "__swift5_reflstr", "__swift5_builtin", "__swift5_capture"] {
                if let sectionData = MachOParser.sectionData(data, segment: "__TEXT", section: section) {
                    info.metadataSections[section] = sectionData.count
                }
            }

            // Reflection strings hold property/field names; mangled type names
            // appear in symbol names and strings.
            if let reflstr = MachOParser.sectionData(data, segment: "__TEXT", section: "__swift5_reflstr") {
                let names = ByteReader(reflstr, label: "reflstr")
                    .asciiStrings(minLength: 1, limit: 20_000)
                info.demangledNames = Array(Set(names)).sorted().prefix(2000).map { $0 }
            }

            let strings = ByteReader(data, label: "swift-scan")
                .asciiStrings(minLength: 6, limit: 120_000)
            let mangledPrefixes = ["_TtC", "_TtV", "_TtP", "_TtS", "_TtG"]
            var mangled = Set<String>()
            var modules = Set<String>()
            var versions = Set<String>()
            for string in strings.prefix(120_000) {
                if mangledPrefixes.contains(where: string.hasPrefix) {
                    mangled.insert(String(string.prefix(120)))
                }
                if string.hasPrefix("(Swift."), string.contains("swift-5."), string.contains("swift-6.") {
                    versions.insert(String(string.prefix(60)))
                }
                if string.hasPrefix("Swift.") || string.hasPrefix("Foundation.") {
                    // module-ish strings are not reliable; skip fabricating
                }
            }
            // Swift module names live in __TEXT,__swift5_entry? Not robustly;
            // derive from framework binary name instead, labelled as such.
            if binary.path.contains(".framework/") {
                let name = ((binary.path as NSString).lastPathComponent)
                if !name.hasSuffix(".framework") {
                    modules.insert(name)
                }
            }
            info.mangledTypeNames = mangled.sorted().prefix(2000).map { $0 }
            info.demangledNames += mangled.sorted().prefix(500).map { demangleLite($0) }
            info.moduleNames = Array(modules).sorted()
            info.swiftVersionStrings = versions.sorted().prefix(20).map { $0 }
            info.status = (info.mangledTypeNames.isEmpty && info.metadataSections.isEmpty && info.demangledNames.isEmpty)
                ? .notFound : .detected
            out[binary.path] = info
        }
        return out
    }

    /// Very small demangler for the common `_TtC<module><Class>` shape so
    /// lists are readable. Full demangling is explicitly out of scope.
    static func demangleLite(_ mangled: String) -> String {
        // _TtC9ModuleName11ClassName → ModuleName.ClassName (length-prefixed)
        guard mangled.hasPrefix("_Tt"), mangled.count > 4 else { return mangled }
        let body = String(mangled.dropFirst(4))     // after "_Tt" + kind letter? "_TtC" handled below
        // Handle _TtC<N><Module><M><Class>
        if mangled.hasPrefix("_TtC") {
            var rest = String(mangled.dropFirst(4))
            var module = ""
            var className = ""
            if let n = Int(rest.prefix(2)), n > 0 {
                rest = String(rest.dropFirst(2))
            }
            // read length-prefixed tokens
            func readToken(_ s: inout String) -> String? {
                var digits = ""
                while let first = s.first, first.isNumber {
                    digits.append(first); s.removeFirst()
                }
                guard let length = Int(digits), length > 0, s.count >= length else { return nil }
                let token = String(s.prefix(length))
                s = String(s.dropFirst(length))
                return token
            }
            module = readToken(&rest) ?? ""
            className = readToken(&rest) ?? ""
            if !module.isEmpty, !className.isEmpty {
                return "\(module).\(className)"
            }
        }
        return mangled
    }
}

// MARK: - Cross-binary search (requirement M)

/// One unified search engine over every indexed corpus. Results are grouped
/// by the source binary/resource and carry the exact location to jump to.
enum CrossBinarySearch {

    enum ResultCategory: String, Codable, CaseIterable, Sendable {
        case symbol
        case string
        case objcClass = "objective-c class"
        case objcMethod = "objective-c method"
        case swiftType = "swift type"
        case url
        case domain
        case framework
        case file
    }

    struct Filter: Sendable {
        var component: String? = nil         // binary path prefix, e.g. a framework
        var category: ResultCategory? = nil
        var caseSensitive: Bool = false
        var useRegex: Bool = false
    }

    struct Hit: Identifiable, Codable, Sendable {
        public var id: String { "\(category.rawValue)|\(source)|\(value)|\(location)" }
        let category: ResultCategory
        let value: String
        let source: String                   // file path the hit came from
        let location: String                 // offset, section, or resource name
        let context: String?
    }

    struct Results: Codable, Sendable {
        var query: String = ""
        var hits: [Hit] = []
        var bySource: [String: [Hit]] = [:]
        var totalScanned: Int = 0
        var truncated: Bool = false
        var elapsedMilliseconds: Int = 0
    }

    /// The index is built once per analysis and shared by all searches.
    final class SearchIndex: @unchecked Sendable {
        private let lock = NSLock()
        private var entries: [Hit] = []
        private var built = false

        var isBuilt: Bool {
            lock.lock(); defer { lock.unlock() }
            return built
        }

        func build(extraction: ExtractionResult,
                   report: Report,
                   symbols: [String: [SymbolEntry]],
                   objc: [String: BinaryMetadata.ObjCInfo],
                   swift: [String: BinaryMetadata.SwiftInfo],
                   maxStringsPerSource: Int = 20_000,
                   isCancelled: () -> Bool = { false }) {
            lock.lock(); defer { lock.unlock() }
            guard !built else { return }
            for (path, list) in symbols {
                for symbol in list.prefix(80_000) {
                    entries.append(Hit(
                        category: .symbol, value: symbol.name,
                        source: path, location: "symbol table (\(symbol.kind.rawValue))",
                        context: nil))
                }
            }
            for (path, info) in objc {
                for name in info.classNames.prefix(5000) {
                    entries.append(Hit(category: .objcClass, value: name, source: path,
                                       location: "__objc_classname", context: nil))
                }
                for name in info.methodNames.prefix(8000) {
                    entries.append(Hit(category: .objcMethod, value: name, source: path,
                                       location: "__objc_methname", context: nil))
                }
            }
            for (path, info) in swift {
                for name in info.mangledTypeNames.prefix(5000) {
                    entries.append(Hit(category: .swiftType, value: name, source: path,
                                       location: "mangled swift type", context: nil))
                }
            }
            for url in report.urls.prefix(8000) {
                entries.append(Hit(category: .url, value: url,
                                   source: "resources and binaries", location: "URL literal",
                                   context: nil))
            }
            for domain in report.domains.prefix(4000) {
                entries.append(Hit(category: .domain, value: domain,
                                   source: "resources and binaries", location: "URL host",
                                   context: nil))
            }
            for framework in extraction.layout.frameworks {
                entries.append(Hit(category: .framework, value: framework,
                                   source: framework, location: "bundle path", context: nil))
            }
            // Plain strings corpus per file, streamed and capped.
            for binary in report.binaries where !binary.isEncrypted {
                if isCancelled() { return }
                let url = extraction.root.appendingPathComponent(binary.path)
                let scanner = StringScanner(url: url, maxBytes: 16 * 1024 * 1024)
                for string in scanner.strings().prefix(maxStringsPerSource) {
                    entries.append(Hit(category: .string, value: string,
                                       source: binary.path, location: "binary strings",
                                       context: nil))
                }
            }
            built = true
        }

        func search(_ query: String, filter: Filter, limit: Int = 500) -> Results {
            lock.lock(); defer { lock.unlock() }
            let started = Date()
            var results = Results()
            results.query = query
            results.totalScanned = entries.count

            let trimmed = query.trimmingCharacters(in: .whitespacesAndNewlines)
            guard !trimmed.isEmpty else { return results }

            let regex: NSRegularExpression?
            if filter.useRegex {
                regex = try? NSRegularExpression(pattern: trimmed,
                                                 options: filter.caseSensitive ? [] : [.caseInsensitive])
            } else {
                regex = nil
            }

            var hits: [Hit] = []
            for entry in entries {
                if hits.count >= limit {
                    results.truncated = true
                    break
                }
                if let component = filter.component,
                   !entry.source.hasPrefix(component) { continue }
                if let category = filter.category,
                   entry.category != category { continue }

                let matches: Bool
                if let regex {
                    matches = regex.firstMatch(in: entry.value,
                                               range: NSRange(location: 0, length: (entry.value as NSString).length)) != nil
                } else if filter.caseSensitive {
                    matches = entry.value.contains(trimmed)
                } else {
                    matches = entry.value.localizedCaseInsensitiveContains(trimmed)
                }
                if matches { hits.append(entry) }
            }

            results.hits = hits
            var grouped: [String: [Hit]] = [:]
            for hit in hits { grouped[hit.source, default: []].append(hit) }
            results.bySource = grouped
            results.elapsedMilliseconds = Int(Date().timeIntervalSince(started) * 1000)
            return results
        }

        func reset() {
            lock.lock(); defer { lock.unlock() }
            entries = []
            built = false
        }
    }

    /// In-session search history (kept in memory only).
    final class History: @unchecked Sendable {
        private let lock = NSLock()
        private var items: [String] = []
        private let capacity = 30

        func add(_ query: String) {
            let trimmed = query.trimmingCharacters(in: .whitespacesAndNewlines)
            guard !trimmed.isEmpty else { return }
            lock.lock(); defer { lock.unlock() }
            items.removeAll { $0 == trimmed }
            items.insert(trimmed, at: 0)
            if items.count > capacity { items.removeLast(items.count - capacity) }
        }

        func all() -> [String] {
            lock.lock(); defer { lock.unlock() }
            return items
        }

        func clear() {
            lock.lock(); defer { lock.unlock() }
            items = []
        }
    }
}
