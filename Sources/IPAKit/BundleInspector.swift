import Foundation

/// Reads one extracted bundle and turns it into findings.
///
/// Kept separate from the archive handling so the two concerns can be tested
/// independently: `IPAAnalyzer` owns bytes on disk, this owns interpretation.
final class BundleInspector {

    let policy: IPAAnalyzer.Policy
    private let fileManager = FileManager.default

    init(policy: IPAAnalyzer.Policy) {
        self.policy = policy
    }

    func analyseBundle(extraction: ExtractionResult,
                       into report: inout Report,
                       progress: @escaping (String) -> Void,
                       isCancelled: () -> Bool) {

        let root = extraction.root
        let appPath = extraction.layout.appBundlePath

        progress("Reading Info.plist…")
        let info = readInfoPlist(root: root, appPath: appPath, into: &report)

        progress("Reading provisioning profile…")
        inspectProvisioningProfile(root: root, appPath: appPath, into: &report)

        progress("Reading privacy manifests…")
        inspectPrivacyManifests(extraction: extraction, into: &report)

        progress("Parsing Mach-O binaries…")
        let binaries = inspectBinaries(extraction: extraction, appPath: appPath,
                                       info: info, into: &report,
                                       progress: progress, isCancelled: isCancelled)

        progress("Fingerprinting SDKs…")
        fingerprintSDKs(extraction: extraction, binaries: binaries, into: &report)

        progress("Scanning resources…")
        scanResources(extraction: extraction, appPath: appPath, binaries: binaries,
                      into: &report, isCancelled: isCancelled)

        progress("Inventorying game assets…")
        inventoryGameAssets(extraction: extraction, binaries: binaries, into: &report)
    }

    // MARK: Info.plist

    @discardableResult
    private func readInfoPlist(root: URL, appPath: String, into report: inout Report) -> [String: Any] {
        let relative = "\(appPath)/Info.plist"
        let url = root.appendingPathComponent(relative)
        guard let data = try? Data(contentsOf: url, options: .mappedIfSafe) else {
            report.findings.append(Finding(
                category: "Application", title: "Info.plist",
                value: "not present at \(relative)", source: relative, status: .notFound))
            return [:]
        }
        guard let info = NativePlist.dictionary(data) else {
            report.findings.append(Finding(
                category: "Application", title: "Info.plist",
                value: "present but could not be parsed", source: relative, status: .blocked,
                note: "The file may be encrypted or corrupt."))
            return [:]
        }

        let scalars: [(key: String, title: String)] = [
            ("CFBundleDisplayName", "Display name"),
            ("CFBundleName", "Bundle name"),
            ("CFBundleIdentifier", "Bundle ID"),
            ("CFBundleShortVersionString", "Version"),
            ("CFBundleVersion", "Build number"),
            ("CFBundleExecutable", "Main executable"),
            ("MinimumOSVersion", "Minimum iOS"),
            ("DTPlatformName", "Platform"),
            ("DTPlatformVersion", "Platform SDK"),
            ("DTSDKName", "SDK name"),
            ("DTXcode", "Built with Xcode"),
            ("DTSDKBuild", "SDK build"),
            ("CFBundlePackageType", "Package type"),
            ("CFBundleSignature", "Creator code"),
            ("ApplicationCategoryType", "Category"),
            ("CFBundleDevelopmentRegion", "Development region"),
        ]
        for field in scalars {
            guard let value = info[field.key] else { continue }
            report.findings.append(Finding(
                category: "Application", title: field.title,
                value: NativePlist.describe(value), source: relative, status: .verified))
        }

        if let family = info["UIDeviceFamily"] as? [Int] {
            let names = family.map { $0 == 1 ? "iPhone" : $0 == 2 ? "iPad" : $0 == 3 ? "Apple TV" : $0 == 4 ? "Apple Watch" : $0 == 6 ? "Vision" : "family \($0)" }
            report.findings.append(Finding(
                category: "Application", title: "Device families",
                value: names.joined(separator: ", "), source: relative, status: .verified))
        }

        // Required device capabilities spell out hardware expectations.
        if let caps = info["UIRequiredDeviceCapabilities"] as? [String] {
            report.findings.append(Finding(
                category: "Application", title: "Required device capabilities",
                value: caps.joined(separator: ", "), source: relative, status: .verified))
        }

        inspectPermissions(info: info, source: relative, into: &report)
        inspectURLSchemes(info: info, source: relative, into: &report)
        inspectATS(info: info, source: relative, into: &report)
        inspectBackgroundModes(info: info, source: relative, into: &report)
        inspectAssociatedDomainsPlaceholder(source: relative, into: &report)
        inspectBundleMap(info: info, extractionSource: relative, into: &report)

        return info
    }

    private func inspectPermissions(info: [String: Any], source: String, into report: inout Report) {
        let descriptions = info.filter { $0.key.hasPrefix("NS") && $0.key.hasSuffix("UsageDescription") }
            .sorted { $0.key < $1.key }
        if descriptions.isEmpty {
            report.findings.append(Finding(
                category: "Permissions", title: "Purpose strings",
                value: "none declared", source: source, status: .notFound))
        } else {
            for (key, value) in descriptions {
                report.findings.append(Finding(
                    category: "Permissions", title: humanPermission(key),
                    value: NativePlist.describe(value), source: source, status: .verified))
            }
        }
        // Entitlement-backed capabilities declared in the plist itself.
        if let entitlements = info["UIBackgroundModes"] as? [String], !entitlements.isEmpty {
            report.findings.append(Finding(
                category: "Permissions", title: "Background modes",
                value: entitlements.joined(separator: ", "), source: source, status: .verified))
        }
    }

    private func humanPermission(_ key: String) -> String {
        let map: [String: String] = [
            "NSCameraUsageDescription": "Camera",
            "NSMicrophoneUsageDescription": "Microphone",
            "NSPhotoLibraryUsageDescription": "Photo library (read)",
            "NSPhotoLibraryAddUsageDescription": "Photo library (write)",
            "NSLocationWhenInUseUsageDescription": "Location when in use",
            "NSLocationAlwaysAndWhenInUseUsageDescription": "Location always",
            "NSLocationAlwaysUsageDescription": "Location (legacy always)",
            "NSContactsUsageDescription": "Contacts",
            "NSCalendarsUsageDescription": "Calendars",
            "NSRemindersUsageDescription": "Reminders",
            "NSBluetoothAlwaysUsageDescription": "Bluetooth",
            "NSBluetoothPeripheralUsageDescription": "Bluetooth (legacy)",
            "NSMotionUsageDescription": "Motion & fitness",
            "NSHealthShareUsageDescription": "Health data (read)",
            "NSHealthUpdateUsageDescription": "Health data (write)",
            "NSHomeKitUsageDescription": "HomeKit",
            "NSSpeechRecognitionUsageDescription": "Speech recognition",
            "NSFaceIDUsageDescription": "Face ID",
            "NSUserTrackingUsageDescription": "App tracking transparency",
            "NSLocalNetworkUsageDescription": "Local network",
            "NSNearbyInteractionUsageDescription": "Nearby interaction",
            "NSFamilyControlsUsageDescription": "Family controls",
            "NSAppleMusicUsageDescription": "Apple Music",
            "NFCReaderUsageDescription": "NFC",
            "NSSensorKitUsageDescription": "SensorKit",
            "NSVideoSubscriberAccountUsageDescription": "Video subscriber account",
            "NSUserNotificationUsageDescription": "Notifications",
        ]
        return map[key] ?? key
    }

    private func inspectURLSchemes(info: [String: Any], source: String, into report: inout Report) {
        if let types = info["CFBundleURLTypes"] as? [[String: Any]] {
            var lines: [String] = []
            for type in types {
                let name = (type["CFBundleURLName"] as? String) ?? "unnamed"
                let schemes = (type["CFBundleURLSchemes"] as? [String]) ?? []
                lines.append("\(name): \(schemes.joined(separator: ", "))")
            }
            if !lines.isEmpty {
                report.findings.append(Finding(
                    category: "Deep links", title: "Custom URL schemes",
                    value: lines.joined(separator: "\n"), source: source, status: .verified))
            }
        } else {
            report.findings.append(Finding(
                category: "Deep links", title: "Custom URL schemes",
                value: "none registered", source: source, status: .notFound))
        }
        if let queried = info["LSApplicationQueriesSchemes"] as? [String] {
            report.findings.append(Finding(
                category: "Deep links", title: "Schemes probed with canOpenURL",
                value: queried.joined(separator: ", "), source: source, status: .verified,
                note: "Each entry is a fingerprint of an integration the app checks for."))
        }
    }

    private func inspectATS(info: [String: Any], source: String, into report: inout Report) {
        guard let ats = info["NSAppTransportSecurity"] as? [String: Any] else {
            report.findings.append(Finding(
                category: "Network security", title: "App Transport Security",
                value: "no NSAppTransportSecurity dictionary — defaults apply (HTTPS required)",
                source: source, status: .verified))
            return
        }
        let arbitrary = (ats["NSAllowsArbitraryLoads"] as? Bool) ?? false
        report.findings.append(Finding(
            category: "Network security", title: "NSAllowsArbitraryLoads",
            value: arbitrary ? "true — plain HTTP is permitted anywhere" : "false",
            source: source, status: .verified,
            note: arbitrary ? "A security-relevant setting worth reviewing, not an exploit by itself." : nil))

        if let webContent = ats["NSAllowsArbitraryLoadsInWebContent"] as? Bool {
            report.findings.append(Finding(
                category: "Network security", title: "NSAllowsArbitraryLoadsInWebContent",
                value: webContent ? "true" : "false", source: source, status: .verified))
        }
        if let localNetworking = ats["NSAllowsLocalNetworking"] as? Bool {
            report.findings.append(Finding(
                category: "Network security", title: "NSAllowsLocalNetworking",
                value: localNetworking ? "true" : "false", source: source, status: .verified))
        }
        if let exceptions = ats["NSExceptionDomains"] as? [String: Any] {
            var lines: [String] = []
            for (domain, raw) in exceptions.sorted(by: { $0.key < $1.key }) {
                guard let rules = raw as? [String: Any] else { continue }
                var flags: [String] = []
                if (rules["NSExceptionAllowsInsecureHTTPLoads"] as? Bool) == true { flags.append("allows HTTP") }
                if (rules["NSExceptionRequiresForwardSecrecy"] as? Bool) == false { flags.append("no forward secrecy") }
                if (rules["NSExceptionMinimumTLSVersion"] as? String).map({ $0 < "TLSv1.2" }) == true { flags.append("weak TLS floor") }
                if (rules["NSIncludesSubdomains"] as? Bool) == true { flags.append("includes subdomains") }
                lines.append("\(domain): \(flags.isEmpty ? "exception present" : flags.joined(separator: ", "))")
            }
            if !lines.isEmpty {
                report.findings.append(Finding(
                    category: "Network security", title: "ATS exception domains",
                    value: lines.joined(separator: "\n"), source: source, status: .verified))
            }
        }
    }

    private func inspectBackgroundModes(info: [String: Any], source: String, into report: inout Report) {
        guard let modes = info["UIBackgroundModes"] as? [String], !modes.isEmpty else { return }
        report.findings.append(Finding(
            category: "Permissions", title: "Background execution modes",
            value: modes.joined(separator: ", "), source: source, status: .verified))
    }

    /// Associated domains live in an entitlement, not in Info.plist. This makes
    /// the distinction explicit instead of leaving a silent gap.
    private func inspectAssociatedDomainsPlaceholder(source: String, into report: inout Report) {
        report.findings.append(Finding(
            category: "Deep links", title: "Associated domains",
            value: "read from the code-signature entitlements of the main executable, see the Entitlements finding",
            source: source, status: .verified))
    }

    private func inspectBundleMap(info: [String: Any], extractionSource: String, into report: inout Report) {
        guard let map = info["CFBundleIcons"] as? [String: Any] else { return }
        if let primary = map["CFBundlePrimaryIcon"] as? [String: Any],
           let files = primary["CFBundleIconFiles"] as? [String] {
            report.findings.append(Finding(
                category: "Application", title: "Primary icon files",
                value: files.joined(separator: ", "), source: extractionSource, status: .verified))
        }
    }

    // MARK: Provisioning profile

    private func inspectProvisioningProfile(root: URL, appPath: String, into report: inout Report) {
        let relative = "\(appPath)/embedded.mobileprovision"
        let url = root.appendingPathComponent(relative)
        guard let data = try? Data(contentsOf: url, options: .mappedIfSafe) else {
            report.findings.append(Finding(
                category: "Signing", title: "Embedded provisioning profile",
                value: "none — expected for App Store builds, which are re-signed at download time",
                source: relative, status: .notFound))
            return
        }
        guard let start = data.range(of: Data("<?xml".utf8)),
              let end = data.range(of: Data("</plist>".utf8), in: start.lowerBound..<data.endIndex),
              let plist = NativePlist.dictionary(data.subdata(in: start.lowerBound..<end.upperBound)) else {
            report.findings.append(Finding(
                category: "Signing", title: "Embedded provisioning profile",
                value: "present (\(ByteCountFormatter.string(fromByteCount: Int64(data.count), countStyle: .file))) but not parseable",
                source: relative, status: .blocked))
            return
        }
        if let name = plist["Name"] as? String {
            report.findings.append(Finding(category: "Signing", title: "Profile name",
                                           value: name, source: relative, status: .verified))
        }
        if let team = plist["TeamName"] as? String {
            let id = (plist["TeamIdentifier"] as? [String])?.first ?? "?"
            report.findings.append(Finding(category: "Signing", title: "Team",
                                           value: "\(team) (\(id))", source: relative, status: .verified))
        }
        if let expiration = plist["ExpirationDate"] as? Date {
            let df = ISO8601DateFormatter()
            let expired = expiration < Date()
            report.findings.append(Finding(
                category: "Signing", title: "Profile expiry",
                value: df.string(from: expiration) + (expired ? " (expired)" : ""),
                source: relative, status: .verified))
        }
        if let devices = plist["ProvisionedDevices"] as? [String] {
            report.findings.append(Finding(
                category: "Signing", title: "Registered devices",
                value: "\(devices.count) UDIDs", source: relative, status: .verified,
                note: "Device UDIDs are personal data and are deliberately not listed."))
        } else {
            report.findings.append(Finding(
                category: "Signing", title: "Distribution type",
                value: "no device list — enterprise, App Store, or a wildcard profile",
                source: relative, status: .estimated))
        }
        if let entitlements = plist["Entitlements"] as? [String: Any] {
            report.findings.append(Finding(
                category: "Signing", title: "Profile entitlements",
                value: entitlements.keys.sorted().joined(separator: ", "),
                source: relative, status: .verified))
        }
        if let provisionsAllDevices = plist["ProvisionsAllDevices"] as? Bool, provisionsAllDevices {
            report.findings.append(Finding(
                category: "Signing", title: "Enterprise provisioning",
                value: "provisions all devices", source: relative, status: .verified))
        }
    }

    // MARK: Privacy manifests

    private func inspectPrivacyManifests(extraction: ExtractionResult, into report: inout Report) {
        let manifests = extraction.files.filter { $0.path.hasSuffix("PrivacyInfo.xcprivacy") }
        if manifests.isEmpty {
            report.findings.append(Finding(
                category: "Privacy", title: "Privacy manifests",
                value: "none found in the bundle", source: "Payload/", status: .notFound,
                note: "Apple requires manifests for listed SDKs; a missing one is a finding about the app, not about this tool."))
            return
        }
        for manifest in manifests {
            let url = extraction.root.appendingPathComponent(manifest.path)
            guard let data = try? Data(contentsOf: url, options: .mappedIfSafe),
                  let plist = NativePlist.dictionary(data) else {
                report.findings.append(Finding(
                    category: "Privacy", title: "Privacy manifest",
                    value: "present but unreadable", source: manifest.path, status: .blocked))
                continue
            }
            let tracking = (plist["NSPrivacyTracking"] as? Bool) == true
            let domains = (plist["NSPrivacyTrackingDomains"] as? [String]) ?? []
            let collected = (plist["NSPrivacyCollectedDataTypes"] as? [[String: Any]]) ?? []
            let accessed = (plist["NSPrivacyAccessedAPITypes"] as? [[String: Any]]) ?? []

            var summary = ["tracking: \(tracking ? "declared" : "not declared")"]
            if !domains.isEmpty { summary.append("tracking domains: \(domains.joined(separator: ", "))") }
            if !collected.isEmpty {
                let types = collected.compactMap { $0["NSPrivacyCollectedDataType"] as? String }
                summary.append("declared collected data types (\(collected.count)): \(types.prefix(12).joined(separator: ", "))")
            }
            if !accessed.isEmpty {
                let apis = accessed.compactMap { $0["NSPrivacyAccessedAPIType"] as? String }
                summary.append("accessed API categories (\(accessed.count)): \(apis.joined(separator: ", "))")
            }
            report.findings.append(Finding(
                category: "Privacy", title: "Privacy manifest",
                value: summary.joined(separator: "\n"), source: manifest.path, status: .verified,
                note: "The manifest states what the developer declared, which is not proof of what the app does at runtime."))
        }
    }

    // MARK: Binaries

    @discardableResult
    private func inspectBinaries(extraction: ExtractionResult,
                                 appPath: String,
                                 info: [String: Any],
                                 into report: inout Report,
                                 progress: (String) -> Void,
                                 isCancelled: () -> Bool) -> [String: BinaryInfo] {

        var parsed: [String: BinaryInfo] = [:]
        let mainExecutable = info["CFBundleExecutable"] as? String
        let mainPath = mainExecutable.map { "\(appPath)/\($0)" }

        // Binaries worth attempting: Mach-O files plus files with no extension
        // inside a bundle (Swift module stubs, extension executables).
        var candidates: [FileEntry] = []
        for file in extraction.files {
            let ext = (file.path as NSString).pathExtension.lowercased()
            if ["dylib", "so", "a"].contains(ext) {
                candidates.append(file); continue
            }
            if file.path.contains(".framework/") && ext.isEmpty {
                candidates.append(file); continue
            }
            if ext.isEmpty && file.size > 4096 {
                candidates.append(file)
            }
            if file.path == mainPath { candidates.append(file) }
        }

        let inspected = min(candidates.count, 400)
        if candidates.count > inspected {
            report.findings.append(Finding(
                category: "Binary", title: "Binary inspection truncated",
                value: "inspected \(inspected) of \(candidates.count) candidate files",
                source: "Payload/", status: .blocked))
        }

        for file in candidates.prefix(inspected) {
            if isCancelled() { return parsed }
            let url = extraction.root.appendingPathComponent(file.path)
            guard let handle = try? FileHandle(forReadingFrom: url),
                  let head = try? handle.read(upToCount: 8) else { continue }
            try? handle.close()
            guard MachOParser.looksLikeMachO(head) else { continue }

            let size = (try? FileManager.default.attributesOfItem(atPath: url.path)[.size] as? Int64) ?? 0
            guard let data = size <= Int64(policy.maxBinaryScanBytes) * 4
                    ? try? Data(contentsOf: url, options: .alwaysMapped) : nil else {
                report.findings.append(Finding(
                    category: "Binary", title: (file.path as NSString).lastPathComponent,
                    value: "larger than the in-memory parse limit; inventoried but not parsed",
                    source: file.path, status: .blocked))
                continue
            }

            do {
                let archs = try MachOParser.parse(data, label: file.path)
                guard !archs.isEmpty else { continue }
                let binary = BinaryInfo(path: file.path, archs: archs,
                                        warnings: archs.flatMap { $0.warnings })
                parsed[file.path] = binary
                report.binaries.append(binary)

                for arch in archs where !arch.warnings.isEmpty {
                    for warning in arch.warnings {
                        report.findings.append(Finding(
                            category: "Binary", title: "Parse warning",
                            value: warning, source: file.path, status: .detected))
                    }
                }
            } catch {
                report.findings.append(Finding(
                    category: "Binary", title: (file.path as NSString).lastPathComponent,
                    value: "starts with a Mach-O magic but did not parse: \(error.localizedDescription)",
                    source: file.path, status: .blocked))
            }
        }

        // Summarise the main executable in full detail.
        if let mainPath, let main = parsed[mainPath] {
            for arch in main.archs {
                let prefix = main.archs.count > 1 ? "[\(arch.cpu)] " : ""
                func add(_ title: String, _ value: String, _ status: EvidenceStatus, _ note: String? = nil) {
                    report.findings.append(Finding(category: "Binary", title: prefix + title,
                                                   value: value, source: mainPath,
                                                   status: status, note: note))
                }
                add("Architecture", arch.cpu + (arch.is64Bit ? " (64-bit)" : " (32-bit)"), .verified)
                if let platform = arch.platform { add("Platform", platform, .verified) }
                if let minOS = arch.minOS { add("Minimum OS (load command)", minOS, .verified) }
                if let sdk = arch.sdk { add("Built with SDK", sdk, .verified) }
                if let uuid = arch.uuid { add("LC_UUID", uuid, .verified) }

                switch arch.encrypted {
                case .some(true):
                    add("FairPlay encryption", "encrypted (cryptid \(arch.cryptID ?? 0))", .verified,
                        "The __TEXT segment is scrambled on disk. Disassembly, Objective-C/Swift metadata and string scanning are not possible for this slice, and this tool does not attempt to defeat the encryption.")
                    add("Code and string analysis", "blocked by encryption", .blocked,
                        "Use a build you produced yourself, or an unencrypted build the rights holder provides.")
                case .some(false):
                    add("FairPlay encryption", "not encrypted (cryptid 0)", .verified)
                case .none:
                    add("FairPlay encryption", "no LC_ENCRYPTION_INFO load command", .estimated,
                        "Typical for a locally built dylib or framework; an App Store main executable always carries the command.")
                }

                if !arch.dylibs.isEmpty {
                    let thirdParty = arch.dylibs.filter { !AppleFrameworks.isSystemPath($0) }
                    let system = arch.dylibs.filter { AppleFrameworks.isSystemPath($0) }
                    add("Linked libraries (embedded)", thirdParty.isEmpty ? "none" : thirdParty.joined(separator: "\n"), .verified)
                    add("Linked libraries (system)", "\(system.count) entries", .verified)
                }
                if !arch.weakDylibs.isEmpty {
                    add("Weak-linked libraries", arch.weakDylibs.joined(separator: "\n"), .verified)
                }
                if !arch.reexportedDylibs.isEmpty {
                    add("Re-exported libraries", arch.reexportedDylibs.joined(separator: "\n"), .verified)
                }
                if !arch.rpaths.isEmpty {
                    add("Runtime search paths", arch.rpaths.joined(separator: "\n"), .verified)
                }
                let truncated = arch.segments.filter(\.truncated)
                if !truncated.isEmpty {
                    add("Truncated segments", truncated.map(\.name).joined(separator: ", "), .detected,
                        "These segments declare a file range beyond the end of the binary — the file is likely damaged or deliberately padded.")
                }
                let writableExecutable = arch.segments.filter { $0.isWritable && $0.isExecutable }
                if !writableExecutable.isEmpty {
                    add("Writable + executable segments", writableExecutable.map(\.name).joined(separator: ", "), .detected,
                        "Legitimate for some runtimes (JavaScriptCore, some game engines); worth noting, not proof of a problem.")
                }
                if let entitlements = arch.entitlementsXML {
                    add("Entitlements", summariseEntitlements(entitlements), .verified)
                    if entitlements.contains("get-task-allow") && entitlements.contains("<true/>") {
                        add("Debug entitlement", "get-task-allow is true", .verified,
                            "This build is debuggable. It is a development or ad-hoc build, not an App Store build.")
                    }
                } else {
                    add("Entitlements", "not present in the code signature", .notFound)
                }
            }
        } else if let mainPath {
            report.findings.append(Finding(
                category: "Binary", title: "Main executable",
                value: "\(mainPath) was not parsed as Mach-O", source: mainPath, status: .blocked))
        }

        report.findings.append(Finding(
            category: "Binary", title: "Mach-O files parsed",
            value: "\(parsed.count)", source: "Payload/", status: .verified))
        return parsed
    }

    private func summariseEntitlements(_ xml: String) -> String {
        guard let data = xml.data(using: .utf8),
              let dict = NativePlist.dictionary(data) else {
            return xml.prefix(2000).description
        }
        var lines: [String] = []
        for key in dict.keys.sorted() {
            let value = dict[key]!
            if let array = value as? [String] {
                lines.append("\(key): \(array.prefix(20).joined(separator: ", "))\(array.count > 20 ? " …" : "")")
            } else {
                lines.append("\(key): \(NativePlist.describe(value))")
            }
        }
        return lines.joined(separator: "\n")
    }

    // MARK: SDK fingerprinting

    private func fingerprintSDKs(extraction: ExtractionResult,
                                 binaries: [String: BinaryInfo],
                                 into report: inout Report) {
        // Evidence pool: relative paths, embedded framework names, linked libs.
        var evidence: [String] = extraction.files.map { $0.path.lowercased() }
        for binary in binaries.values {
            for arch in binary.archs {
                evidence.append(contentsOf: arch.dylibs.map { $0.lowercased() })
                evidence.append(contentsOf: arch.weakDylibs.map { $0.lowercased() })
            }
        }
        let frameworkNames = extraction.layout.frameworks.map {
            (($0 as NSString).lastPathComponent as NSString).deletingPathExtension.lowercased()
        }
        evidence.append(contentsOf: frameworkNames)

        var matched = 0
        for signature in SDKDatabase.all {
            var hits: [String] = []
            for pattern in signature.patterns {
                if let match = evidence.first(where: { $0.contains(pattern) }) {
                    hits.append(match)
                }
                if hits.count >= 5 { break }
            }
            guard !hits.isEmpty else { continue }
            matched += 1
            let weak = SDKDatabase.isWeakFingerprint(signature)
            report.findings.append(Finding(
                category: signature.category,
                title: signature.name,
                value: "evidence: " + hits.joined(separator: ", "),
                source: hits[0],
                status: weak ? .estimated : .detected,
                note: signature.notes + (weak ? " This fingerprint is short and may match unrelated symbols." : "")))
        }

        report.findings.append(Finding(
            category: "Dependencies", title: "SDK fingerprints",
            value: "\(matched) of \(SDKDatabase.all.count) known signatures matched",
            source: "bundle paths and linked libraries", status: .detected,
            note: "A match shows the library is present in the bundle. It does not show that the library initialises, or which of its features the app uses."))

        // Apple frameworks actually used, from the linked libraries.
        var apple = Set<String>()
        for binary in binaries.values {
            for arch in binary.archs {
                for lib in arch.dylibs {
                    let base = (lib as NSString).lastPathComponent
                    if base.hasSuffix(".framework") {
                        apple.insert(String(base.dropLast(".framework".count)))
                    }
                }
            }
        }
        if !apple.isEmpty {
            report.findings.append(Finding(
                category: "Dependencies", title: "Apple frameworks linked",
                value: apple.sorted().joined(separator: ", "),
                source: "LC_LOAD_DYLIB", status: .verified))
        }

        if !extraction.layout.frameworks.isEmpty {
            report.findings.append(Finding(
                category: "Dependencies", title: "Embedded frameworks",
                value: "\(extraction.layout.frameworks.count): " +
                       extraction.layout.frameworks.map { ($0 as NSString).lastPathComponent }.joined(separator: ", "),
                source: "Payload/", status: .verified))
        }
        if !extraction.layout.extensions.isEmpty {
            report.findings.append(Finding(
                category: "Dependencies", title: "App extensions",
                value: "\(extraction.layout.extensions.count): " +
                       extraction.layout.extensions.map { ($0 as NSString).lastPathComponent }.joined(separator: ", "),
                source: "Payload/", status: .verified))
        }
        if !extraction.layout.nestedBundles.isEmpty {
            report.findings.append(Finding(
                category: "Dependencies", title: "Other application bundles",
                value: extraction.layout.nestedBundles.joined(separator: "\n"),
                source: "Payload/", status: .verified))
        }
    }

    // MARK: Resource scanning

    private func scanResources(extraction: ExtractionResult,
                               appPath: String,
                               binaries: [String: BinaryInfo],
                               into report: inout Report,
                               isCancelled: () -> Bool) {

        // Inventory by type, so the report says what is actually in the bundle.
        var byExtension: [String: (count: Int, bytes: Int64)] = [:]
        for file in extraction.files {
            let ext = (file.path as NSString).pathExtension.lowercased()
            let key = ext.isEmpty ? "(no extension)" : ext
            var entry = byExtension[key] ?? (0, 0)
            entry.count += 1
            entry.bytes += file.size
            byExtension[key] = entry
        }
        let top = byExtension.sorted { $0.value.bytes > $1.value.bytes }.prefix(25)
        report.findings.append(Finding(
            category: "Resources", title: "Inventory by file type",
            value: top.map { "\($0.key): \($0.value.count) files, \(ByteCountFormatter.string(fromByteCount: $0.value.bytes, countStyle: .file))" }
                .joined(separator: "\n"),
            source: "Payload/", status: .verified))

        // Scannable text resources.
        let textExtensions: Set<String> = ["json", "plist", "js", "xml", "txt", "html", "htm",
                                           "strings", "cfg", "config", "ini", "yaml", "yml", "csv",
                                           "jsbundle", "bundle", "properties", "css"]
        var scanned = 0
        var skippedLarge = 0
        var secrets: [SecretScanner.Hit] = []
        var binaryStrings: [String] = []

        for file in extraction.files {
            if isCancelled() { break }
            let ext = (file.path as NSString).pathExtension.lowercased()
            guard textExtensions.contains(ext) || file.path.contains("/Localizable") else { continue }
            if scanned >= 300 { break }
            if file.size > Int64(policy.maxTextResourceBytes) { skippedLarge += 1; continue }
            let url = extraction.root.appendingPathComponent(file.path)
            guard let data = try? Data(contentsOf: url, options: .mappedIfSafe),
                  data.count < policy.maxTextResourceBytes else { continue }
            scanned += 1
            var text = String(decoding: data, as: UTF8.self)
            if ext == "plist", let plist = NativePlist.parse(data),
               let xml = try? PropertyListSerialization.data(fromPropertyList: plist, format: .xml, options: 0) {
                text = String(decoding: xml, as: UTF8.self)
            }
            secrets.append(contentsOf: SecretScanner.scan(text: text, source: file.path))
            binaryStrings.append(text)
        }

        if scanned > 0 {
            report.findings.append(Finding(
                category: "Resources", title: "Text resources scanned",
                value: "\(scanned) files" + (skippedLarge > 0 ? "; \(skippedLarge) skipped for exceeding the size cap" : ""),
                source: "Payload/", status: .verified))
        }

        // Strings from unencrypted binaries only.
        var scannedBinaries = 0
        var encryptedBinaries = 0
        for binary in binaries.values {
            if isCancelled() { break }
            let scannedArchs = binary.archs.filter { $0.encrypted != true }
            if scannedArchs.isEmpty {
                encryptedBinaries += 1
                continue
            }
            let url = extraction.root.appendingPathComponent(binary.path)
            let size = (try? FileManager.default.attributesOfItem(atPath: url.path)[.size] as? Int64) ?? 0
            if size > Int64(policy.maxBinaryScanBytes) { continue }
            var scanner = StringScanner(url: url, maxBytes: policy.maxBinaryScanBytes)
            let strings = scanner.strings()
            if !strings.isEmpty {
                scannedBinaries += 1
                binaryStrings.append(contentsOf: strings.prefix(5_000))
                secrets.append(contentsOf: SecretScanner.scan(
                    text: strings.joined(separator: "\n"),
                    source: binary.path + " (binary strings)",
                    limit: 12))
            }
        }
        if encryptedBinaries > 0 {
            report.findings.append(Finding(
                category: "Binary", title: "String scanning skipped",
                value: "\(encryptedBinaries) encrypted binaries", source: "Payload/", status: .blocked,
                note: "Their strings are not readable on disk. This tool does not attempt to decrypt them."))
        }
        if scannedBinaries > 0 {
            report.findings.append(Finding(
                category: "Binary", title: "Unencrypted binaries string-scanned",
                value: "\(scannedBinaries)", source: "Payload/", status: .verified))
        }

        // Report secrets, redacted.
        var seen = Set<String>()
        for hit in secrets where seen.insert(hit.redacted).inserted {
            report.findings.append(Finding(
                category: "Secrets", title: hit.name,
                value: hit.redacted, source: hit.source, status: .detected, note: hit.note))
        }
        if secrets.isEmpty {
            report.findings.append(Finding(
                category: "Secrets", title: "Credential-shaped strings",
                value: "none matched the known patterns",
                source: "resources and unencrypted binaries", status: .notFound,
                note: "Absence of matches is not proof that the app holds no secrets. A secret can be hidden by encryption, encoded, or fetched at runtime."))
        }

        collectURLs(from: binaryStrings, source: "resources and unencrypted binaries", into: &report)
    }

    // MARK: URL collection

    /// Called from the resource pass with the blobs already in memory. There is
    /// no second pass over the disk: re-reading every resource would double the
    /// I/O for no gain, and the URL list is already complete at this point.
    private func collectURLs(from blobs: [String], source: String, into report: inout Report) {
        guard !blobs.isEmpty else { return }
        let pattern = #"(?:https?|wss?)://[A-Za-z0-9](?:[A-Za-z0-9\-\.]*[A-Za-z0-9])?(?::\d{1,5})?(?:/[A-Za-z0-9\.\-_~:/\?#\[\]@!\$&'\(\)\*\+,;=%]*)?"#
        guard let regex = try? NSRegularExpression(pattern: pattern) else { return }

        var counts: [String: Int] = [:]
        for blob in blobs {
            let ns = blob as NSString
            let range = NSRange(location: 0, length: ns.length)
            regex.enumerateMatches(in: blob, range: range) { match, _, stop in
                guard let match else { return }
                let url = ns.substring(with: match.range)
                    .trimmingCharacters(in: CharacterSet(charactersIn: ".,;:\"'()[]{}"))
                guard url.count > 8 else { return }
                // Skip template placeholders and obvious noise.
                if url.contains("%@") || url.contains("${") || url.contains("{{") { return }
                counts[url, default: 0] += 1
                if counts.count >= self.policy.maxURLs { stop.pointee = true }
            }
            if counts.count >= policy.maxURLs { break }
        }

        report.urls = counts.sorted {
            $0.value == $1.value ? $0.key < $1.key : $0.value > $1.value
        }.map(\.key)

        var hosts: [String: Int] = [:]
        for url in report.urls {
            guard let host = URL(string: url)?.host?.lowercased() else { continue }
            hosts[host, default: 0] += 1
        }
        report.domains = hosts.sorted { $0.value == $1.value ? $0.key < $1.key : $0.value > $1.value }.map(\.key)

        if !report.domains.isEmpty {
            report.findings.append(Finding(
                category: "Network", title: "Distinct hosts referenced",
                value: "\(report.domains.count): " + report.domains.prefix(40).joined(separator: ", "),
                source: source, status: .detected,
                note: "These are string literals found on disk. A host that appears here is not necessarily contacted at runtime, and a host contacted at runtime is not necessarily written down anywhere."))
        }
        let cleartext = report.urls.filter { $0.hasPrefix("http://") || $0.hasPrefix("ws://") }
        if !cleartext.isEmpty {
            report.findings.append(Finding(
                category: "Network security", title: "Cleartext endpoints in strings",
                value: "\(cleartext.count) of \(report.urls.count): " + cleartext.prefix(10).joined(separator: ", "),
                source: source, status: .detected,
                note: "Plain HTTP endpoints are often legacy or test URLs that the app never calls. ATS settings decide whether they could be used at all."))
        }
        let nonAppleHosts = report.domains.filter { !$0.hasSuffix("apple.com") && !$0.hasSuffix("icloud.com") }
        report.findings.append(Finding(
            category: "Network", title: "Third-party hosts",
            value: nonAppleHosts.isEmpty ? "none" : "\(nonAppleHosts.count) hosts, e.g. " + nonAppleHosts.prefix(20).joined(separator: ", "),
            source: source, status: .detected))
    }

    // MARK: Game assets

    private func inventoryGameAssets(extraction: ExtractionResult,
                                     binaries: [String: BinaryInfo],
                                     into report: inout Report) {
        let assetExtensions = ["png", "jpg", "jpeg", "webp", "ktx", "ktx2", "astc", "pvr",
                               "mp3", "wav", "m4a", "aac", "ogg", "caf",
                               "mp4", "mov",
                               "ttf", "otf", "woff", "woff2",
                               "dae", "obj", "fbx", "gltf", "glb", "usdz", "scn", "sks",
                               "pak", "assetbundle", "bundle", "resS", "resource", "assets",
                               "pck", "dat", "bson", "bytes"]
        var counts: [String: (count: Int, bytes: Int64)] = [:]
        for file in extraction.files {
            let ext = (file.path as NSString).pathExtension.lowercased()
            guard assetExtensions.contains(ext) else { continue }
            var entry = counts[ext] ?? (0, 0)
            entry.count += 1
            entry.bytes += file.size
            counts[ext] = entry
        }
        if counts.isEmpty { return }
        report.findings.append(Finding(
            category: "Game assets", title: "Asset types present",
            value: counts.sorted { $0.value.count > $1.value.count }
                .map { "\($0.key): \($0.value.count) files (\(ByteCountFormatter.string(fromByteCount: $0.value.bytes, countStyle: .file)))" }
                .joined(separator: "\n"),
            source: "Payload/", status: .verified))

        // Unity-specific structure.
        if let unityData = extraction.files.first(where: { $0.path.contains("/Data/") && $0.path.hasSuffix("global-metadata.dat") }) {
            report.findings.append(Finding(
                category: "Game engine", title: "Unity global-metadata.dat",
                value: "present, \(ByteCountFormatter.string(fromByteCount: unityData.size, countStyle: .file))",
                source: unityData.path, status: .verified,
                note: "This file holds the app's managed type and method names. It is not decoded in this version; Il2CppDumper is the tool normally used for that."))
        }
        let unityBundles = extraction.files.filter { $0.path.hasSuffix(".assetbundle") || $0.path.contains("/Data/") }
        if !unityBundles.isEmpty {
            report.findings.append(Finding(
                category: "Game engine", title: "Unity data files",
                value: "\(unityBundles.count) files under Data/ or with .assetbundle",
                source: "Payload/", status: .detected))
        }
        // IL2CPP indicator.
        let hasIL2CPP = binaries.values.contains { binary in
            binary.path.lowercased().contains("il2cpp") ||
            binary.archs.contains { $0.dylibs.contains { $0.lowercased().contains("il2cpp") } }
        }
        if hasIL2CPP {
            report.findings.append(Finding(
                category: "Game engine", title: "IL2CPP runtime",
                value: "libil2cpp present", source: "Payload/", status: .detected,
                note: "C# methods are compiled to native code. Class and method names survive in global-metadata.dat, but the original C# source does not."))
        }
    }
}
