import Foundation

/// SDK / supply-chain intelligence (requirement J).
///
/// Honesty rules: versions come only from bundle metadata; the module never
/// fabricates "latest versions" or CVE data. A local snapshot without a
/// reliable vulnerability database means no vulnerability claims are made —
/// that limitation is stated in the output.
enum SDKInventory {

    struct SDKEntry: Identifiable, Codable, Sendable {
        var id: String { name }
        let name: String
        let category: String
        let version: String?
        let versionSource: String?
        let evidence: [String]
        let confidence: String            // high / medium / low
        let tracksUsers: Bool
        let frameworkPaths: [String]
        let duplicated: Bool
        let renamedSuspicious: Bool
        let minOS: String?
        let architectures: [String]
        let compatible: Bool?
        let notes: String
    }

    struct Inventory: Codable, Sendable {
        var entries: [SDKEntry] = []
        var duplicates: [String] = []
        var renames: [String] = []
        var vulnerabilities: [String] = []
        var limitations: [String] = []
        var totalDetected: Int = 0
    }

    static func build(extraction: ExtractionResult,
                      report: Report,
                      structure: StructureAnalyzer.StructureReport?,
                      isCancelled: () -> Bool = { false }) -> Inventory {
        var out = Inventory()
        let root = extraction.root

        // Evidence pool as in BundleInspector.fingerprintSDKs.
        var evidence: [String] = extraction.files.map { $0.path.lowercased() }
        for binary in report.binaries {
            for arch in binary.archs {
                evidence.append(contentsOf: arch.dylibs.map { $0.lowercased() })
                evidence.append(contentsOf: arch.weakDylibs.map { $0.lowercased() })
            }
        }
        let frameworkNames = extraction.layout.frameworks.map {
            (($0 as NSString).lastPathComponent as NSString).deletingPathExtension.lowercased()
        }
        evidence.append(contentsOf: frameworkNames)

        // Framework bundle metadata (paths → Info.plist facts).
        var frameworkMeta: [String: [String: Any]] = [:]
        for framework in extraction.layout.frameworks {
            let infoURL = root.appendingPathComponent("\(framework)/Info.plist")
            if let data = try? Data(contentsOf: infoURL, options: .mappedIfSafe),
               let plist = NativePlist.dictionary(data) {
                frameworkMeta[framework] = plist
            }
        }

        // Duplicate frameworks: same framework name embedded more than once.
        var byName: [String: [String]] = [:]
        for framework in extraction.layout.frameworks {
            let name = ((framework as NSString).lastPathComponent as NSString).deletingPathExtension.lowercased()
            byName[name, default: []].append(framework)
        }
        out.duplicates = byName.filter { $0.value.count > 1 }
            .map { "\($0.key): \($0.value.joined(separator: ", "))" }

        // Suspicious renames: framework names that look like random hex blobs
        // or UUID-like names.
        let hexPattern = try? NSRegularExpression(pattern: #"^[0-9a-fA-F]{8,}(-[0-9a-fA-F]{4}){2,}"#)
        for framework in extraction.layout.frameworks {
            let name = ((framework as NSString).lastPathComponent as NSString).deletingPathExtension
            if let regex = hexPattern,
               regex.firstMatch(in: name, range: NSRange(location: 0, length: (name as NSString).length)) != nil {
                out.renames.append("\(framework) — machine-generated name (possible renamed bundle)")
            }
        }

        for signature in SDKDatabase.all {
            if isCancelled() { break }
            var hits: [String] = []
            for pattern in signature.patterns {
                if let match = evidence.first(where: { $0.contains(pattern) }) {
                    hits.append(match)
                }
                if hits.count >= 5 { break }
            }
            guard !hits.isEmpty else { continue }

            // Version from matching framework Info.plist, when present.
            var version: String?
            var versionSource: String?
            var frameworkPaths: [String] = []
            for framework in extraction.layout.frameworks {
                let name = ((framework as NSString).lastPathComponent as NSString).deletingPathExtension.lowercased()
                let sigName = signature.name.lowercased().replacingOccurrences(of: " ", with: "")
                if name.contains(sigName.prefix(8)) || sigName.contains(name) {
                    frameworkPaths.append(framework)
                    if let plist = frameworkMeta[framework] {
                        let v = plist["CFBundleShortVersionString"] as? String
                            ?? plist["CFBundleVersion"] as? String
                        if v != nil, version == nil {
                            version = v
                            versionSource = "\(framework)/Info.plist"
                        }
                    }
                }
            }

            let weak = SDKDatabase.isWeakFingerprint(signature)
            var notes = signature.notes
            if version == nil, frameworkPaths.isEmpty == false {
                notes += " No version string found in the framework's Info.plist."
            }

            out.entries.append(SDKEntry(
                name: signature.name,
                category: signature.category,
                version: version,
                versionSource: versionSource,
                evidence: hits,
                confidence: weak ? "low" : (frameworkPaths.isEmpty ? "medium" : "high"),
                tracksUsers: signature.tracksUsers,
                frameworkPaths: frameworkPaths,
                duplicated: frameworkPaths.count > 1,
                renamedSuspicious: frameworkPaths.contains { path in
                    out.renames.contains { $0.hasPrefix(path) || path.hasPrefix($0) }
                },
                minOS: minOSOf(paths: frameworkPaths, meta: frameworkMeta, report: report),
                architectures: architecturesOf(paths: frameworkPaths, report: report),
                compatible: compatibilityOf(paths: frameworkPaths, report: report),
                notes: notes))
        }

        out.totalDetected = out.entries.count

        // Vulnerability claims: none. State the limitation explicitly.
        out.vulnerabilities = []
        out.limitations = [
            "No vulnerability database ships with this tool, so no CVE or 'outdated SDK' claims are made. Version strings shown (if any) come from bundle metadata only.",
            "A fingerprint match shows the library is present in the bundle. It does not show that the library initialises or which features the app uses.",
        ]
        return out
    }

    private static func minOSOf(paths: [String],
                                meta: [String: [String: Any]],
                                report: Report) -> String? {
        for path in paths {
            if let plist = meta[path], let minOS = plist["MinimumOSVersion"] as? String {
                return minOS
            }
        }
        for path in paths {
            if let binary = report.binaries.first(where: { $0.path.hasPrefix(path) }),
               let minOS = binary.archs.compactMap(\.minOS).min() {
                return minOS
            }
        }
        return nil
    }

    private static func architecturesOf(paths: [String], report: Report) -> [String] {
        var archs: Set<String> = []
        for path in paths {
            if let binary = report.binaries.first(where: { $0.path.hasPrefix(path) }) {
                binary.archs.forEach { archs.insert($0.cpu) }
            }
        }
        return archs.sorted()
    }

    private static func compatibilityOf(paths: [String], report: Report) -> Bool? {
        guard let main = report.binaries.first(where: { binary in
            !binary.path.contains(".framework/") && !binary.path.contains(".appex/")
        }) else { return nil }
        let mainMin = main.archs.compactMap(\.minOS).min()
        guard let mainMin else { return nil }
        for path in paths {
            if let binary = report.binaries.first(where: { $0.path.hasPrefix(path) }),
               let componentMin = binary.archs.compactMap(\.minOS).min() {
                return StructureAnalyzer.compareVersions(componentMin, mainMin)
            }
        }
        return nil
    }
}
