import Foundation

/// OWASP MASVS/MASTG-aligned static security assessment (requirement H).
///
/// Ground rules, enforced in code and in copy:
///  * Static analysis can only detect indicators on disk. It can never prove
///    or disprove runtime behaviour, and the findings say exactly that.
///  * Suspicions are labelled `estimated` and carry a confidence level; they
///    are never called vulnerabilities.
///  * Checks that cannot run (e.g. encrypted binaries) come back `blocked`,
///    never silently empty.
enum SecurityAssessor {

    enum Severity: String, Codable, CaseIterable, Sendable {
        case critical, high, medium, low, informational

        var order: Int {
            switch self {
            case .critical: return 0
            case .high: return 1
            case .medium: return 2
            case .low: return 3
            case .informational: return 4
            }
        }
        var label: String { rawValue.capitalized }
    }

    enum Confidence: String, Codable, CaseIterable, Sendable {
        case high, medium, low
    }

    struct Finding: Identifiable, Codable, Sendable {
        let id: String                 // SEC-001 …
        let title: String
        let severity: Severity
        let confidence: Confidence
        let evidence: String
        let sourceFile: String
        let sourceLocation: String     // Info.plist key, byte offset, or "—"
        let explanation: String
        let masvs: [String]
        let mastg: [String]
        let remediation: String
        let status: EvidenceStatus
    }

    // MARK: MASVS/MASTG reference data

    enum MASVS {
        static let storage1 = "MASVS-STORAGE-1 (sensitive data is encrypted at rest)"
        static let crypto1 = "MASVS-CRYPTO-1 (modern, strong cryptography is used)"
        static let crypto3 = "MASVS-CRYPTO-3 (cryptographic keys are managed securely)"
        static let network1 = "MASVS-NETWORK-1 (network traffic is encrypted in transit)"
        static let network2 = "MASVS-NETWORK-2 (endpoint identity is verified)"
        static let platform1 = "MASVS-PLATFORM-1 (app components are exposed securely)"
        static let platform2 = "MASVS-PLATFORM-2 (webviews are configured securely)"
        static let code1 = "MASVS-CODE-1 (the app requires a current platform version)"
        static let code3 = "MASVS-CODE-3 (security features are not disabled)"
        static let resilience1 = "MASVS-RESILIENCE-1 (anti-tampering controls exist)"
        static let privacy = "MASVS-PRIVACY-1 (data collection is transparent)"
    }

    // MARK: Entry point

    struct Context {
        let report: Report
        let structure: StructureAnalyzer.StructureReport?
        let secrets: [SecretScanner.Hit]
        let extraction: ExtractionResult?
        let policyMaxFiles: Int
    }

    static func assess(_ context: Context,
                       isCancelled: () -> Bool = { false }) -> [Finding] {
        var findings: [Finding] = []
        let report = context.report

        func nextID(_ n: inout Int) -> String {
            n += 1
            return String(format: "SEC-%03d", n)
        }
        var n = 0

        // ---- SEC: App Transport Security ----
        if let ats = report.findings.first(where: { $0.title == "NSAllowsArbitraryLoads" }),
           ats.value.hasPrefix("true") {
            findings.append(Finding(
                id: nextID(&n),
                title: "App Transport Security allows arbitrary loads",
                severity: .high, confidence: .high,
                evidence: ats.value,
                sourceFile: ats.source,
                sourceLocation: "Info.plist › NSAppTransportSecurity › NSAllowsArbitraryLoads",
                explanation: "The app declares that plain HTTP and weak TLS are acceptable to any endpoint. Static analysis shows the configuration only; whether insecure connections happen depends on what the app contacts at runtime.",
                masvs: [MASVS.network1, MASVS.network2],
                mastg: ["MASTG » Testing App Transport Security Settings (iOS)"],
                remediation: "Remove NSAllowsArbitraryLoads. Allow per-domain exceptions with modern TLS floors instead.",
                status: .verified))
        } else if let ats = report.findings.first(where: { $0.title == "NSAllowsArbitraryLoads" }),
                  ats.value == "false" {
            findings.append(Finding(
                id: nextID(&n),
                title: "App Transport Security: default policy in effect",
                severity: .informational, confidence: .high,
                evidence: "NSAllowsArbitraryLoads is explicitly false — HTTPS is required.",
                sourceFile: ats.source,
                sourceLocation: "Info.plist › NSAppTransportSecurity › NSAllowsArbitraryLoads",
                explanation: "The ATS policy is the secure one. Per-domain exceptions, if present, weaken it.",
                masvs: [MASVS.network1],
                mastg: ["MASTG » Testing App Transport Security Settings (iOS)"],
                remediation: "Keep the default policy; document any future exception domains.",
                status: .verified))
        } else if report.findings.first(where: { $0.title == "NSAllowsArbitraryLoads" }) == nil,
                  report.findings.contains(where: { $0.category == "Application" }) {
            findings.append(Finding(
                id: nextID(&n),
                title: "App Transport Security: default policy in effect",
                severity: .informational, confidence: .high,
                evidence: "No NSAppTransportSecurity dictionary — HTTPS is required by default.",
                sourceFile: report.findings.first { $0.category == "Application" }?.source ?? "Info.plist",
                sourceLocation: "Info.plist › NSAppTransportSecurity (absent)",
                explanation: "The default ATS policy is the secure one. Per-domain exceptions, if added later, weaken it.",
                masvs: [MASVS.network1],
                mastg: ["MASTG » Testing App Transport Security Settings (iOS)"],
                remediation: "Keep the default policy; document any future exception domains.",
                status: .verified))
        }

        // ---- SEC: ATS exception domains ----
        if let exceptions = report.findings.first(where: { $0.title == "ATS exception domains" }),
           exceptions.value.contains("allows HTTP") || exceptions.value.contains("weak TLS") {
            findings.append(Finding(
                id: nextID(&n),
                title: "ATS exceptions weaken TLS for specific domains",
                severity: .medium, confidence: .high,
                evidence: exceptions.value,
                sourceFile: exceptions.source,
                sourceLocation: "Info.plist › NSAppTransportSecurity › NSExceptionDomains",
                explanation: "One or more domains may be reached over plain HTTP or with a TLS version below 1.2. This is a configuration fact; exploitation depends on those endpoints' actual behaviour.",
                masvs: [MASVS.network1],
                mastg: ["MASTG » Testing App Transport Security Settings (iOS)"],
                remediation: "Restrict exceptions to domains that truly need them and raise the minimum TLS version to 1.2 or higher.",
                status: .verified))
        }

        // ---- SEC: cleartext endpoints ----
        let cleartext = report.urls.filter { $0.hasPrefix("http://") || $0.hasPrefix("ws://") }
        if !cleartext.isEmpty {
            findings.append(Finding(
                id: nextID(&n),
                title: "Cleartext HTTP endpoints found in strings",
                severity: .high, confidence: .medium,
                evidence: "\(cleartext.count) endpoint(s), e.g. \(cleartext.prefix(8).joined(separator: ", "))",
                sourceFile: "resources and unencrypted binaries (strings)",
                sourceLocation: "byte offsets recorded by the URL scanner",
                explanation: "URL literals on disk use plain HTTP. ATS may still block them at runtime, but their presence indicates code paths that expect insecure transport. Static analysis cannot determine whether they are called.",
                masvs: [MASVS.network1],
                mastg: ["MASTG » Identifying Insecure Network Communication"],
                remediation: "Migrate every endpoint to HTTPS and remove legacy HTTP URLs from code and configuration.",
                status: .detected))
        }

        // ---- SEC: certificate pinning indicators ----
        let pinningIndicators = scanBinariesAndResources(context, needles: [
            "trustkit", "sslpinning", "ssl_pinning", "pinnedcertificates",
            "spki", "sectrustevaluate", "publickeypinner", "pinnedkeys",
        ])
        if pinningIndicators.found {
            findings.append(Finding(
                id: nextID(&n),
                title: "Certificate pinning indicators present",
                severity: .informational, confidence: .medium,
                evidence: pinningIndicators.evidence,
                sourceFile: pinningIndicators.source,
                sourceLocation: pinningIndicators.location,
                explanation: "Strings matching known pinning frameworks were found. Their presence suggests pinning code exists; whether it is correct and enforced cannot be proven statically.",
                masvs: [MASVS.network2],
                mastg: ["MASTG » Testing Certificate Pinning"],
                remediation: "Verify pinning covers every sensitive endpoint and has a safe backup key path.",
                status: .detected))
        } else if !report.binaries.isEmpty, report.binaries.allSatisfy({ !$0.isEncrypted }) {
            findings.append(Finding(
                id: nextID(&n),
                title: "No certificate pinning indicator found",
                severity: .low, confidence: .low,
                evidence: "No known pinning strings in \(report.binaries.count) unencrypted binary(ies).",
                sourceFile: "Payload/",
                sourceLocation: "—",
                explanation: "Absence of a string indicator is weak evidence: pinning can be implemented with generic APIs and no distinctive strings. This finding states what was searched, not what the app does.",
                masvs: [MASVS.network2],
                mastg: ["MASTG » Testing Certificate Pinning"],
                remediation: "If the app handles sensitive traffic, implement pinning or confirm it exists by review.",
                status: .estimated))
        }

        // ---- SEC: custom URL schemes ----
        if let schemes = report.findings.first(where: { $0.title == "Custom URL schemes" }),
           schemes.status == .verified, !schemes.value.contains("none registered") {
            findings.append(Finding(
                id: nextID(&n),
                title: "Custom URL schemes registered",
                severity: .low, confidence: .medium,
                evidence: schemes.value,
                sourceFile: schemes.source,
                sourceLocation: "Info.plist › CFBundleURLTypes › CFBundleURLSchemes",
                explanation: "Any app on the device can open these schemes with arbitrary parameters. Static analysis cannot see how handlers validate input.",
                masvs: [MASVS.platform1],
                mastg: ["MASTG » Testing Universal Links' Validation of Data (iOS)"],
                remediation: "Validate every parameter of every scheme entry point; prefer universal links for inbound app traffic.",
                status: .verified))
        }

        // ---- SEC: canOpenURL probe list ----
        if let probes = report.findings.first(where: { $0.title.contains("Schemes probed") }) {
            findings.append(Finding(
                id: nextID(&n),
                title: "App probes for other installed apps",
                severity: .informational, confidence: .high,
                evidence: probes.value,
                sourceFile: probes.source,
                sourceLocation: "Info.plist › LSApplicationQueriesSchemes",
                explanation: "The list of schemes the app can query is a fingerprint of installed-app detection. Not a vulnerability by itself.",
                masvs: [MASVS.privacy],
                mastg: ["MASTG » Testing App Permission Requests (iOS)"],
                remediation: "Keep the list minimal and justified.",
                status: .verified))
        }

        // ---- SEC: sensitive permissions ----
        let sensitive = ["Camera", "Microphone", "Location always", "Location when in use",
                         "Contacts", "Calendars", "Reminders", "Bluetooth", "Motion & fitness",
                         "Health data (read)", "Health data (write)", "Speech recognition",
                         "App tracking transparency", "NFC", "SensorKit"]
        let granted = sensitive.filter { perm in
            report.findings.contains { $0.title == perm && $0.category == "Permissions" }
        }
        if !granted.isEmpty {
            findings.append(Finding(
                id: nextID(&n),
                title: "Sensitive permission usage strings present",
                severity: .low, confidence: .high,
                evidence: granted.joined(separator: ", "),
                sourceFile: report.findings.first { $0.category == "Permissions" }?.source ?? "Info.plist",
                sourceLocation: "Info.plist › NS*UsageDescription",
                explanation: "Declared permission strings show which protected APIs the app may use. Declared is not the same as exercised at runtime.",
                masvs: [MASVS.privacy],
                mastg: ["MASTG » Testing App Permission Requests (iOS)"],
                remediation: "Confirm each permission is justified by a user-visible feature.",
                status: .verified))
        }

        // ---- SEC: debug entitlement ----
        if let debug = report.findings.first(where: { $0.title.contains("Debug entitlement") }),
           debug.value.contains("true") {
            findings.append(Finding(
                id: nextID(&n),
                title: "Debuggable build (get-task-allow)",
                severity: .high, confidence: .high,
                evidence: debug.value,
                sourceFile: debug.source,
                sourceLocation: "code signature entitlements › get-task-allow",
                explanation: "This build may be attached to by a debugger and reads its data container in an unencrypted backup context. Distribution to end users with this entitlement is a hardening failure, not proof of exploitation.",
                masvs: [MASVS.code3, MASVS.resilience1],
                mastg: ["MASTG » Testing whether the App is Debuggable (iOS)"],
                remediation: "Ship release builds with get-task-allow false.",
                status: .verified))
        }

        // ---- SEC: weak cryptography indicators ----
        let weakCrypto = scanBinariesAndResources(context, needles: [
            "md5", "sha1", "rc4", "des-ecb", "ccdigest(", "ccmd5", "ccsha1",
            "kcchmacsha1", "cckeystreamrc4", "ecb",
        ])
        if weakCrypto.found {
            findings.append(Finding(
                id: nextID(&n),
                title: "Weak or legacy cryptography indicators",
                severity: .medium, confidence: .low,
                evidence: weakCrypto.evidence,
                sourceFile: weakCrypto.source,
                sourceLocation: weakCrypto.location,
                explanation: "Names of weak algorithms appear in the bundle. MD5/SHA-1 are also used for non-security checksums, so their presence is an indicator that needs code-level review, not proof of weak encryption.",
                masvs: [MASVS.crypto1],
                mastg: ["MASTG » Identifying Usage of Cryptographic APIs (iOS)"],
                remediation: "Audit each usage; replace MD5/SHA-1/RC4/DES with SHA-256/AES-GCM or platform crypto.",
                status: .detected))
        }

        // ---- SEC: weak randomness ----
        let weakRandom = scanBinariesAndResources(context, needles: ["srand(", "_rand(", "rand()"])
        if weakRandom.found {
            findings.append(Finding(
                id: nextID(&n),
                title: "Weak randomness indicator (rand/srand)",
                severity: .medium, confidence: .low,
                evidence: weakRandom.evidence,
                sourceFile: weakRandom.source,
                sourceLocation: weakRandom.location,
                explanation: "Classic rand() references were found. They may be unrelated to security decisions; review is required before drawing conclusions.",
                masvs: [MASVS.crypto1],
                mastg: ["MASTG » Testing the Implementation of Cryptographic Operations (iOS)"],
                remediation: "Use SecRandomCopyBytes or arc4random_buf for anything security-relevant.",
                status: .detected))
        }

        // ---- SEC: hardcoded credentials ----
        for hit in context.secrets where hit.confidence == "high" {
            let severity: Severity = hit.name.contains("live secret") || hit.name.contains("Private key")
                || hit.name.contains("AWS") || hit.name.contains("GitHub") ? .critical : .high
            findings.append(Finding(
                id: nextID(&n),
                title: "Credential-shaped string: \(hit.name)",
                severity: severity, confidence: .medium,
                evidence: hit.masked,
                sourceFile: hit.source,
                sourceLocation: "byte offset \(hit.offset) · \(hit.method)",
                explanation: "A string matching a known credential format was found. It is a candidate; a live credential is only proven by trying it, which this tool will never do. The value is masked everywhere in this report.",
                masvs: [MASVS.storage1, MASVS.crypto3],
                mastg: ["MASTG » Identifying Sensitive Hardcoded Information"],
                remediation: "Remove secrets from the client. Fetch short-lived tokens from a backend after authentication, and rotate any exposed key.",
                status: .detected))
        }

        // ---- SEC: local storage of credential-like values ----
        let storedCredentials = context.secrets.filter {
            $0.source.hasSuffix(".plist") || $0.source.hasSuffix(".json") || $0.source.hasSuffix(".xml")
        }
        if !storedCredentials.isEmpty {
            findings.append(Finding(
                id: nextID(&n),
                title: "Credential-like values stored in configuration files",
                severity: .medium, confidence: .medium,
                evidence: "\(storedCredentials.count) file(s): \(storedCredentials.prefix(6).map(\.source).joined(separator: ", "))",
                sourceFile: storedCredentials.first?.source ?? "—",
                sourceLocation: "configuration files on disk",
                explanation: "Values matching credential patterns sit in files readable from the app container and in unencrypted backups. Masked here; presence is factual, live-ness is not established.",
                masvs: [MASVS.storage1],
                mastg: ["MASTG » Determining the Sensitive Data Sent via the Network / Stored by an App (iOS)"],
                remediation: "Move secrets to the Keychain with a strict protection class, or fetch them at runtime.",
                status: .detected))
        }

        // ---- SEC: backup exposure ----
        let fileSharing = report.findings.first { $0.title == "UIFileSharingEnabled" }
        if let fileSharing, fileSharing.value.contains("true") {
            findings.append(Finding(
                id: nextID(&n),
                title: "File sharing exposes the Documents folder",
                severity: .informational, confidence: .high,
                evidence: "\(fileSharing.title) = \(fileSharing.value)" +
                    (report.findings.first { $0.title == "LSSupportsOpeningDocumentsInPlace" }.map { "; \($0.title) = \($0.value)" } ?? ""),
                sourceFile: fileSharing.source,
                sourceLocation: "Info.plist › UIFileSharingEnabled",
                explanation: "Users (and anyone with the device) can browse the app's Documents folder via Finder or iTunes, and it is included in backups unless excluded per-file.",
                masvs: [MASVS.storage1],
                mastg: ["MASTG » Testing Backup Exclusion (iOS)"],
                remediation: "Exclude sensitive files with NSURLIsExcludedFromBackupKey and keep Documents clean.",
                status: .verified))
        }

        // ---- SEC: suspicious script content ----
        let scriptFindings = scanScripts(context)
        if !scriptFindings.isEmpty {
            findings.append(Finding(
                id: nextID(&n),
                title: "Dynamic code evaluation in bundled scripts",
                severity: .medium, confidence: .medium,
                evidence: scriptFindings.joined(separator: "; "),
                sourceFile: scriptFindings.first ?? "—",
                sourceLocation: "bundled .js/.html resources",
                explanation: "Bundled scripts contain eval/document.write style constructs. Their risk depends on where the script gets its input at runtime, which static analysis cannot establish.",
                masvs: [MASVS.platform2, MASVS.code3],
                mastg: ["MASTG » Testing JavaScript Bridges (iOS)"],
                remediation: "Remove eval-based paths; if webviews load remote content, restrict them with WKAppBoundDomains.",
                status: .detected))
        }

        // ---- SEC: tracking SDKs ----
        let trackingFindings = report.findings.filter {
            $0.category == "Analytics" || $0.category == "Advertising" || $0.category == "Attribution"
        }
        if !trackingFindings.isEmpty {
            findings.append(Finding(
                id: nextID(&n),
                title: "Analytics/advertising SDKs present",
                severity: .medium, confidence: .high,
                evidence: trackingFindings.map(\.title).joined(separator: ", "),
                sourceFile: trackingFindings.first?.source ?? "Payload/",
                sourceLocation: "bundle paths and linked libraries",
                explanation: "SDKs in these categories commonly collect device or usage data. Presence in the bundle does not prove data is collected or transmitted.",
                masvs: [MASVS.privacy],
                mastg: ["MASTG » Testing Data Collection from Third Parties (iOS)"],
                remediation: "Cross-check each SDK against the privacy manifest and the app privacy label.",
                status: .detected))
        }

        // ---- SEC: privacy manifest consistency ----
        let privacyFindings = report.findings.filter { $0.category == "Privacy" && $0.title.contains("Privacy manifest") }
        for privacy in privacyFindings {
            let declaresTracking = privacy.value.contains("tracking: declared")
            let hasDomains = privacy.value.contains("tracking domains:")
            if hasDomains && !declaresTracking {
                findings.append(Finding(
                    id: nextID(&n),
                    title: "Privacy manifest inconsistency (tracking domains without tracking declaration)",
                    severity: .medium, confidence: .high,
                    evidence: privacy.value,
                    sourceFile: privacy.source,
                    sourceLocation: "PrivacyInfo.xcprivacy › NSPrivacyTracking",
                    explanation: "Tracking domains are declared while NSPrivacyTracking is false. One of the two statements is likely wrong; the manifest is what App Review reads.",
                    masvs: [MASVS.privacy],
                    mastg: ["MASTG » Testing the Privacy Manifest (iOS)"],
                    remediation: "Align NSPrivacyTracking with the declared tracking domains.",
                    status: .verified))
            }
        }
        if privacyFindings.isEmpty, !trackingFindings.isEmpty {
            findings.append(Finding(
                id: nextID(&n),
                title: "No privacy manifest although tracking SDKs are present",
                severity: .medium, confidence: .medium,
                evidence: "SDKs: \(trackingFindings.map(\.title).joined(separator: ", ")) · manifest: none found",
                sourceFile: "Payload/",
                sourceLocation: "—",
                explanation: "Apple requires a privacy manifest from listed SDKs and from apps that use required-reason APIs. Absence is a compliance gap indicator, not proof of data misuse.",
                masvs: [MASVS.privacy],
                mastg: ["MASTG » Testing the Privacy Manifest (iOS)"],
                remediation: "Add and populate PrivacyInfo.xcprivacy.",
                status: .estimated))
        }

        // ---- SEC: minimum OS vintage ----
        if let minOS = report.findings.first(where: { $0.title == "Minimum iOS" }) {
            let parts = minOS.value.split(separator: ".").compactMap { Int($0) }
            if parts.first ?? 17 < 15 {
                findings.append(Finding(
                    id: nextID(&n),
                    title: "Minimum OS below iOS 15",
                    severity: .low, confidence: .high,
                    evidence: "MinimumOSVersion \(minOS.value)",
                    sourceFile: minOS.source,
                    sourceLocation: "Info.plist › MinimumOSVersion",
                    explanation: "Older minimum versions inherit devices stuck on older platform security. This is a hardening posture note, not a vulnerability.",
                    masvs: [MASVS.code1],
                    mastg: ["MASTG » Testing the Minimum OS Version (iOS)"],
                    remediation: "Raise the deployment target when feature work allows.",
                    status: .verified))
            }
        }

        // ---- SEC: encryption blocks analysis (honest blocked marker) ----
        let encryptedBinaries = report.binaries.filter { $0.isEncrypted }
        if !encryptedBinaries.isEmpty {
            findings.append(Finding(
                id: nextID(&n),
                title: "Checks blocked by FairPlay encryption",
                severity: .informational, confidence: .high,
                evidence: "\(encryptedBinaries.count) binary(ies) encrypted: \(encryptedBinaries.map { ($0.path as NSString).lastPathComponent }.joined(separator: ", "))",
                sourceFile: encryptedBinaries.first?.path ?? "—",
                sourceLocation: "LC_ENCRYPTION_INFO › cryptid 1",
                explanation: "String scanning, disassembly and ObjC/Swift metadata extraction cannot run on encrypted slices. Every dependent check above is labelled by the evidence it could gather from unencrypted resources alone. This tool does not decrypt.",
                masvs: [MASVS.resilience1, MASVS.code3],
                mastg: ["MASTG » Overview (encrypted app stores)"],
                remediation: "Analyse a development build or a build the rights holder provides in unencrypted form.",
                status: .blocked))
        }

        // ---- SEC: structure compatibility notes ----
        if let structure = context.structure {
            for component in structure.components where component.minOSCompatible == false {
                findings.append(Finding(
                    id: nextID(&n),
                    title: "Component minimum OS newer than the app (\(component.name))",
                    severity: .low, confidence: .high,
                    evidence: "\(component.path): minOS \(component.minOS ?? "?") vs app \(component.minOS ?? "?")",
                    sourceFile: component.path,
                    sourceLocation: "component Info.plist › MinimumOSVersion",
                    explanation: "A component declaring a newer minimum OS than the app may crash or be skipped on older devices. Supply-chain hygiene issue rather than a vulnerability.",
                    masvs: [MASVS.code1],
                    mastg: ["MASTG » Testing the Minimum OS Version (iOS)"],
                    remediation: "Rebuild the component against the app's deployment target.",
                    status: .verified))
            }
        }

        return findings.sorted { a, b in
            a.severity.order != b.severity.order
                ? a.severity.order < b.severity.order
                : a.id < b.id
        }
    }

    // MARK: Content scans

    private struct ScanOutcome {
        var found = false
        var evidence = ""
        var source = "—"
        var location = "—"
    }

    /// Searches unencrypted binaries (strings) and text resources for needles.
    private static func scanBinariesAndResources(_ context: Context,
                                                 needles: [String],
                                                 limit: Int = 60_000) -> ScanOutcome {
        var outcome = ScanOutcome()
        guard let extraction = context.extraction else { return outcome }
        let lowercased = needles.map { $0.lowercased() }

        var seen = Set<String>()
        // Resources first (cheap), then binary strings.
        let textExtensions: Set<String> = ["json", "plist", "js", "xml", "txt", "html", "strings", "cfg", "config"]
        for file in extraction.files.prefix(context.policyMaxFiles) {
            if outcome.found { break }
            let ext = (file.path as NSString).pathExtension.lowercased()
            guard textExtensions.contains(ext) else { continue }
            guard file.size < 8 * 1024 * 1024 else { continue }
            guard let data = try? Data(contentsOf: extraction.root.appendingPathComponent(file.path), options: .mappedIfSafe) else { continue }
            let text = String(decoding: data, as: UTF8.self).lowercased()
            for needle in lowercased where text.contains(needle) {
                let key = "\(file.path):\(needle)"
                if seen.insert(key).inserted {
                    outcome.found = true
                    outcome.evidence += (outcome.evidence.isEmpty ? "" : ", ") + "\"\(needle)\" in \(file.path)"
                    outcome.source = file.path
                    outcome.location = "text resource"
                    if outcome.evidence.count > 600 { break }
                }
            }
        }
        if outcome.found { return outcome }

        for binary in context.report.binaries where binary.archs.contains(where: { $0.encrypted != true }) {
            if outcome.found { break }
            let scanner = StringScanner(url: extraction.root.appendingPathComponent(binary.path),
                                        maxBytes: limit)
            let strings = scanner.strings().map { $0.lowercased() }
            for needle in lowercased {
                if let match = strings.first(where: { $0.contains(needle) }) {
                    outcome.found = true
                    outcome.evidence = "\"\(needle)\" matched string \"\(String(match.prefix(80)))\""
                    outcome.source = binary.path
                    outcome.location = "binary strings (\(binary.archs.first?.cpu ?? "?"))"
                    return outcome
                }
            }
        }
        return outcome
    }

    private static func scanScripts(_ context: Context) -> [String] {
        guard let extraction = context.extraction else { return [] }
        var hits: [String] = []
        let needles = ["eval(", "document.write(", "settimeout(eval", "new function("]
        for file in extraction.files {
            let ext = (file.path as NSString).pathExtension.lowercased()
            guard ext == "js" || ext == "html" else { continue }
            guard file.size < 2 * 1024 * 1024 else { continue }
            guard let data = try? Data(contentsOf: extraction.root.appendingPathComponent(file.path), options: .mappedIfSafe) else { continue }
            let text = String(decoding: data, as: UTF8.self)
            let found = needles.filter { text.localizedCaseInsensitiveContains($0) }
            if !found.isEmpty {
                hits.append("\(file.path): \(found.joined(separator: ", "))")
                if hits.count >= 6 { break }
            }
        }
        return hits
    }
}
