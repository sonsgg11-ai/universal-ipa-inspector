import Foundation

/// Application structure analysis (requirement G): components of the bundle,
/// their identity, minimum OS, architecture compatibility and analysis status.
enum StructureAnalyzer {

    struct Component: Identifiable, Codable, Sendable {
        var id: String { path }
        let path: String
        let kind: ComponentKind
        let bundleID: String?
        let name: String?
        let version: String?
        let buildNumber: String?
        let minOS: String?
        let architectures: [String]
        let executablePath: String?
        let analysisStatus: EvidenceStatus
        let note: String?
        /// Compatibility with the main executable's minimum OS.
        let minOSCompatible: Bool?
    }

    enum ComponentKind: String, Codable, Sendable {
        case mainExecutable = "main executable"
        case framework
        case dynamicLibrary = "dynamic library"
        case appExtension = "app extension"
        case appClip = "app clip"
        case plugIn = "plug-in"
        case watchApp = "watch app"
        case resourceBundle = "resource bundle"
        case localization
    }

    struct StructureReport: Codable, Sendable {
        var mainExecutablePath: String?
        var components: [Component] = []
        var frameworks: [String] = []
        var extensions: [String] = []
        var appClips: [String] = []
        var plugIns: [String] = []
        var watchApps: [String] = []
        var resourceBundles: [String] = []
        var localizations: [String] = []
        var hasEmbeddedProvisioning: Bool = false
        var privacyManifests: [String] = []
        var warnings: [String] = []
    }

    static func analyse(extraction: ExtractionResult,
                        report: Report,
                        isCancelled: () -> Bool = { false }) -> StructureReport {
        var out = StructureReport()
        let root = extraction.root
        let appPath = extraction.layout.appBundlePath

        // Main executable from Info.plist, or the best binary candidate.
        if let info = mainInfoPlist(root: root, appPath: appPath),
           let executable = info["CFBundleExecutable"] as? String {
            out.mainExecutablePath = "\(appPath)/\(executable)"
        } else if let binary = report.binaries.first(where: { $0.path.hasPrefix(appPath + "/") && !$0.path.contains(".framework/") }) {
            out.mainExecutablePath = binary.path
            out.warnings.append("Info.plist did not name the main executable; it was inferred from the bundle layout.")
        }

        out.frameworks = extraction.layout.frameworks
        out.extensions = extraction.layout.extensions
        out.plugIns = extraction.layout.plugins
        out.watchApps = extraction.layout.watchApps

        // App clips: .appex with a app-clip entitlement-ish marker, or names.
        out.appClips = extraction.files
            .map(\.path)
            .filter { $0.contains(".appclip/") || $0.hasSuffix(".appclip") }
        // Resource bundles (.bundle directories) and localizations.
        var bundles = Set<String>()
        var localizations = Set<String>()
        for file in extraction.files {
            if let range = file.path.range(of: ".bundle/") {
                bundles.insert(String(file.path[..<range.upperBound]).appending(""))
            }
            if file.path.contains(".lproj/") || file.path.hasSuffix(".lproj") {
                for component in file.path.split(separator: "/") {
                    if component.hasSuffix(".lproj") {
                        localizations.insert(String(component).replacingOccurrences(of: ".lproj", with: ""))
                    }
                }
            }
        }
        out.resourceBundles = Array(bundles).sorted()
        out.localizations = Array(localizations).sorted()

        out.hasEmbeddedProvisioning = extraction.files.contains {
            $0.path == "\(appPath)/embedded.mobileprovision"
        }
        out.privacyManifests = extraction.files
            .map(\.path)
            .filter { $0.hasSuffix("PrivacyInfo.xcprivacy") }

        // Main executable's minimum OS for compatibility checks.
        let mainMinOS = mainBinaryMinimumOS(report: report, path: out.mainExecutablePath)
        let mainArchs = mainBinaryArchitectures(report: report, path: out.mainExecutablePath)

        // --- main executable component ---
        if let mainPath = out.mainExecutablePath,
           let binary = report.binaries.first(where: { $0.path == mainPath }) {
            out.components.append(Component(
                path: mainPath,
                kind: .mainExecutable,
                bundleID: report.findings.first { $0.title == "Bundle ID" }?.value,
                name: report.name,
                version: report.findings.first { $0.title == "Version" }?.value,
                buildNumber: report.findings.first { $0.title == "Build number" }?.value,
                minOS: mainMinOS,
                architectures: mainArchs,
                executablePath: mainPath,
                analysisStatus: binary.isEncrypted ? .blocked : .verified,
                note: binary.isEncrypted
                    ? "Encrypted (FairPlay): disassembly and metadata extraction are blocked; load commands and structure remain readable."
                    : nil,
                minOSCompatible: nil))
        } else if let mainPath = out.mainExecutablePath {
            out.components.append(Component(
                path: mainPath,
                kind: .mainExecutable,
                bundleID: nil, name: report.name, version: nil, buildNumber: nil,
                minOS: nil, architectures: [], executablePath: mainPath,
                analysisStatus: .blocked,
                note: "The main executable could not be parsed as Mach-O.",
                minOSCompatible: nil))
            out.warnings.append("The main executable could not be parsed as Mach-O.")
        }

        // --- frameworks ---
        for framework in extraction.layout.frameworks {
            if isCancelled() { break }
            out.components.append(
                componentForBundle(at: framework,
                                   root: root,
                                   kind: .framework,
                                   report: report,
                                   mainMinOS: mainMinOS,
                                   mainArchs: mainArchs))
        }
        // --- extensions (each .appex) ---
        for extensionPath in extraction.layout.extensions {
            if isCancelled() { break }
            out.components.append(
                componentForBundle(at: extensionPath,
                                   root: root,
                                   kind: .appExtension,
                                   report: report,
                                   mainMinOS: mainMinOS,
                                   mainArchs: mainArchs))
        }
        // --- watch apps ---
        for watchPath in extraction.layout.watchApps {
            out.components.append(
                componentForBundle(at: watchPath,
                                   root: root,
                                   kind: .watchApp,
                                   report: report,
                                   mainMinOS: mainMinOS,
                                   mainArchs: mainArchs))
        }
        // --- standalone dylibs ---
        for file in extraction.files where file.path.hasSuffix(".dylib") {
            let binary = report.binaries.first { $0.path == file.path }
            out.components.append(Component(
                path: file.path,
                kind: .dynamicLibrary,
                bundleID: nil, name: (file.path as NSString).lastPathComponent,
                version: nil, buildNumber: nil,
                minOS: binary?.archs.first?.minOS,
                architectures: binary?.archs.map(\.cpu) ?? [],
                executablePath: file.path,
                analysisStatus: binary == nil ? .blocked : (binary!.isEncrypted ? .blocked : .verified),
                note: binary == nil ? "Not parsed as Mach-O." : nil,
                minOSCompatible: compareVersions(binary?.archs.first?.minOS, mainMinOS)))
        }
        // --- resource bundles ---
        for bundle in out.resourceBundles {
            let info = plistInBundle(at: bundle, root: root)
            out.components.append(Component(
                path: bundle,
                kind: .resourceBundle,
                bundleID: info?["CFBundleIdentifier"] as? String,
                name: info?["CFBundleName"] as? String ?? (bundle as NSString).lastPathComponent,
                version: info?["CFBundleShortVersionString"] as? String,
                buildNumber: info?["CFBundleVersion"] as? String,
                minOS: info?["MinimumOSVersion"] as? String,
                architectures: [],
                executablePath: nil,
                analysisStatus: info == nil ? .estimated : .verified,
                note: info == nil ? "No Info.plist found in this bundle." : nil,
                minOSCompatible: nil))
        }
        // --- localizations (aggregated) ---
        if !out.localizations.isEmpty {
            out.components.append(Component(
                path: appPath + "/(lproj)",
                kind: .localization,
                bundleID: nil,
                name: "Localizations",
                version: nil, buildNumber: nil,
                minOS: nil, architectures: [],
                executablePath: nil,
                analysisStatus: .verified,
                note: out.localizations.sorted().joined(separator: ", "),
                minOSCompatible: nil))
        }

        return out
    }

    // MARK: Helpers

    private static func componentForBundle(at bundlePath: String,
                                           root: URL,
                                           kind: ComponentKind,
                                           report: Report,
                                           mainMinOS: String?,
                                           mainArchs: [String]) -> Component {
        let info = plistInBundle(at: bundlePath, root: root)
        let bundleID = info?["CFBundleIdentifier"] as? String
        let version = info?["CFBundleShortVersionString"] as? String
        let build = info?["CFBundleVersion"] as? String
        let plistMinOS = info?["MinimumOSVersion"] as? String
        let executableName = info?["CFBundleExecutable"] as? String
            ?? ((bundlePath as NSString).lastPathComponent as NSString).deletingPathExtension
        let executablePath = "\(bundlePath)/\(executableName)"
        let binary = report.binaries.first { $0.path == executablePath }

        let archs = binary?.archs.map(\.cpu) ?? []
        let minOS = plistMinOS ?? binary?.archs.first?.minOS

        var status: EvidenceStatus = .estimated
        var note: String? = nil
        if binary == nil {
            status = .blocked
            note = "The executable inside this component could not be parsed as Mach-O."
        } else if binary!.isEncrypted {
            status = .blocked
            note = "Encrypted (FairPlay): metadata above comes from Info.plist and load commands only."
        } else {
            status = .verified
        }

        // Architecture compatibility: every architecture the main binary
        // supports should also exist in the component.
        var archCompatible: Bool? = nil
        if !mainArchs.isEmpty, !archs.isEmpty {
            archCompatible = archs.allSatisfy { arch in mainArchs.contains(arch) }
            if archCompatible == false {
                note = (note ?? "") + " Component architectures (\(archs.joined(separator: ", "))) do not cover the main binary's (\(mainArchs.joined(separator: ", ")))."
            }
        }

        return Component(
            path: bundlePath,
            kind: kind,
            bundleID: bundleID,
            name: info?["CFBundleDisplayName"] as? String ?? info?["CFBundleName"] as? String
                ?? ((bundlePath as NSString).lastPathComponent as NSString).deletingPathExtension,
            version: version,
            buildNumber: build,
            minOS: minOS,
            architectures: archs,
            executablePath: binary != nil ? executablePath : nil,
            analysisStatus: status,
            note: note?.trimmingCharacters(in: .whitespaces),
            minOSCompatible: compareVersions(minOS, mainMinOS))
    }

    private static func plistInBundle(at bundlePath: String, root: URL) -> [String: Any]? {
        let infoURL = root.appendingPathComponent("\(bundlePath)/Info.plist")
        guard let data = try? Data(contentsOf: infoURL, options: .mappedIfSafe) else { return nil }
        return NativePlist.dictionary(data)
    }

    private static func mainInfoPlist(root: URL, appPath: String) -> [String: Any]? {
        plistInBundle(at: appPath, root: root)
    }

    private static func mainBinaryMinimumOS(report: Report, path: String?) -> String? {
        guard let path,
              let binary = report.binaries.first(where: { $0.path == path }) else { return nil }
        let values = binary.archs.compactMap(\.minOS)
        return values.min()
    }

    private static func mainBinaryArchitectures(report: Report, path: String?) -> [String] {
        guard let path,
              let binary = report.binaries.first(where: { $0.path == path }) else { return [] }
        return binary.archs.map(\.cpu)
    }

    /// Returns true when `candidate` <= `baseline` (component's minimum OS is
    /// not newer than the app's), false when it is newer, nil when unknown.
    static func compareVersions(_ candidate: String?, _ baseline: String?) -> Bool? {
        guard let candidate, let baseline else { return nil }
        func parts(_ s: String) -> [Int] {
            s.split(separator: ".").map { Int($0.prefix(while: { $0.isNumber })) ?? 0 }
        }
        let a = parts(candidate), b = parts(baseline)
        for i in 0..<max(a.count, b.count) {
            let x = i < a.count ? a[i] : 0
            let y = i < b.count ? b[i] : 0
            if x != y { return x <= y }
        }
        return true
    }
}
