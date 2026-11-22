import Foundation

/// Signing, provisioning profile and entitlements inspection (requirement K).
///
/// The central honesty rule: the four signature states below are distinct and
/// never conflated. The presence of a signature or profile file is NOT a
/// statement that the signature is valid; cryptographic verification is out
/// of scope for this tool and reported as such.
enum ProvisioningParser {

    enum SignatureState: String, Codable, Sendable {
        case unsigned                    // no LC_CODE_SIGNATURE at all
        case signaturePresent            // LC_CODE_SIGNATURE exists (blob parsed)
        case structureCheckable          // entitlements/superblob structure read
        case cryptographicallyVerified   // CMS chain validated — this tool never claims this
    }

    struct ProfileInfo: Codable, Sendable {
        var present: Bool = false
        var parseable: Bool = false
        var name: String?
        var teamName: String?
        var teamIDs: [String] = []
        var appIDName: String?
        var bundleID: String?
        var applicationPrefixes: [String] = []
        var creationDate: Date?
        var expirationDate: Date?
        var isExpired: Bool = false
        var provisionedDeviceCount: Int?
        var provisionsAllDevices: Bool = false
        var distributionMethod: String?     // development / ad-hoc / enterprise / app-store (inferred)
        var entitlements: [String: String] = [:]
        var keychainAccessGroups: [String] = []
        var appGroups: [String] = []
        var associatedDomains: [String] = []
        var apsEnvironment: String?
        var getTaskAllow: Bool?
        var source: String = ""
        var rawStatus: EvidenceStatus = .notFound
    }

    struct SigningReport: Codable, Sendable {
        var profile = ProfileInfo()
        var mainExecutableStates: [String: SignatureState] = [:]   // path → state
        var entitlementKeysByBinary: [String: [String]] = [:]
        var sensitiveEntitlements: [String] = []
        var summary: String = ""
    }

    static func analyse(extraction: ExtractionResult,
                        report: Report,
                        isCancelled: () -> Bool = { false }) -> SigningReport {
        var out = SigningReport()
        let appPath = extraction.layout.appBundlePath
        let root = extraction.root

        // ---- embedded.mobileprovision ----
        let profilePath = "\(appPath)/embedded.mobileprovision"
        let profileURL = root.appendingPathComponent(profilePath)
        out.profile.source = profilePath

        if let data = try? Data(contentsOf: profileURL, options: .mappedIfSafe) {
            out.profile.present = true
            if let plistData = NativePlist.plistRange(in: data),
               let plist = NativePlist.dictionary(plistData) {
                out.profile.parseable = true
                out.profile.rawStatus = .verified
                out.profile.name = plist["Name"] as? String
                out.profile.teamName = plist["TeamName"] as? String
                out.profile.teamIDs = plist["TeamIdentifier"] as? [String] ?? []
                out.profile.appIDName = plist["AppIDName"] as? String
                out.profile.applicationPrefixes = plist["ApplicationIdentifierPrefix"] as? [String] ?? []

                if let created = plist["CreationDate"] as? Date {
                    out.profile.creationDate = created
                }
                if let expiry = plist["ExpirationDate"] as? Date {
                    out.profile.expirationDate = expiry
                    out.profile.isExpired = expiry < Date()
                }
                if let devices = plist["ProvisionedDevices"] as? [String] {
                    out.profile.provisionedDeviceCount = devices.count
                }
                out.profile.provisionsAllDevices = (plist["ProvisionsAllDevices"] as? Bool) == true

                // Distribution method inference — always labelled as such.
                if out.profile.provisionsAllDevices {
                    out.profile.distributionMethod = "enterprise (inferred: ProvisionsAllDevices)"
                } else if out.profile.provisionedDeviceCount != nil {
                    if (plistEntitlement(plist, "get-task-allow")) == true {
                        out.profile.distributionMethod = "development or ad-hoc (inferred: device list + get-task-allow)"
                    } else {
                        out.profile.distributionMethod = "ad-hoc (inferred: device list, release entitlement)"
                    }
                } else {
                    out.profile.distributionMethod = "app store or TestFlight (inferred: no device list)"
                }

                out.profile.bundleID = bundleID(fromProfile: plist,
                                                prefixes: out.profile.applicationPrefixes)
                if let ents = plist["Entitlements"] as? [String: Any] {
                    for key in ents.keys.sorted() {
                        out.profile.entitlements[key] = NativePlist.describe(ents[key] ?? "")
                    }
                    out.profile.keychainAccessGroups = ents["keychain-access-groups"] as? [String] ?? []
                    out.profile.appGroups = ents["com.apple.security.application-groups"] as? [String] ?? []
                    out.profile.associatedDomains = ents["com.apple.developer.associated-domains"] as? [String] ?? []
                    out.profile.apsEnvironment = ents["aps-environment"] as? String
                    if let task = ents["get-task-allow"] as? Bool {
                        out.profile.getTaskAllow = task
                    }
                }
            } else {
                out.profile.rawStatus = .blocked
            }
        }

        // ---- signature state per binary ----
        for binary in report.binaries {
            if isCancelled() { break }
            var state: SignatureState = .unsigned
            var keys: [String] = []
            for arch in binary.archs {
                if arch.entitlementsXML != nil {
                    state = .structureCheckable
                    if let xml = arch.entitlementsXML,
                       let dict = xml.data(using: .utf8).flatMap(NativePlist.dictionary) {
                        keys = dict.keys.sorted()
                    }
                } else if arch.linkedItOffset != 0 {
                    // A slice with a code-signature load command but no
                    // readable entitlements blob: the signature exists, its
                    // contents were not structurally parsed.
                    state = .signaturePresent
                }
            }
            out.mainExecutableStates[binary.path] = state
            if !keys.isEmpty {
                out.entitlementKeysByBinary[binary.path] = keys
            }
        }

        // ---- sensitive entitlements ----
        var sensitive: [String] = []
        for (path, keys) in out.entitlementKeysByBinary {
            let flagged = keys.filter {
                $0.contains("keychain-access-groups")
                    || $0.contains("application-groups")
                    || $0.contains("associated-domains")
                    || $0.contains("icloud")
                    || $0.contains("aps-environment")
                    || $0.contains("get-task-allow")
                    || $0.contains("personal-hotspot")
                    || $0.contains("nfc")
            }
            if !flagged.isEmpty {
                sensitive.append("\(path): \(flagged.joined(separator: ", "))")
            }
        }
        out.sensitiveEntitlements = sensitive

        // ---- summary in plain language, always distinguishing states ----
        let mainPath = out.mainExecutableStates.first { $0.key.hasPrefix(appPath) && !$0.key.contains(".framework") }?.key
        let mainState = mainPath.flatMap { out.mainExecutableStates[$0] }
        let profileSummary: String
        switch out.profile.rawStatus {
        case .verified:
            profileSummary = "embedded profile parsed (Team \(out.profile.teamIDs.first ?? "?"), expires \(out.profile.expirationDate.map { ISO8601DateFormatter().string(from: $0) } ?? "n/a"))"
        case .blocked:
            profileSummary = "embedded profile present but not parseable"
        case .notFound:
            profileSummary = "no embedded profile (expected for App Store builds)"
        default:
            profileSummary = "embedded profile status unknown"
        }
        out.summary = "Main executable: \(describe(state: mainState)). \(profileSummary.capitalizedFirst). Cryptographic verification of signatures is not performed by this tool."
        return out
    }

    static func describe(state: SignatureState?) -> String {
        switch state {
        case .none: return "unsigned (no code-signature load command)"
        case .unsigned: return "unsigned (no code-signature load command)"
        case .signaturePresent: return "signature blob present (structure not parsed)"
        case .structureCheckable: return "signature present and structurally checked (entitlements read)"
        case .cryptographicallyVerified: return "cryptographically verified (never claimed by static analysis)"
        }
    }

    private static func plistEntitlement(_ plist: [String: Any], _ key: String) -> Bool? {
        (plist["Entitlements"] as? [String: Any])?[key] as? Bool
    }

    private static func bundleID(fromProfile plist: [String: Any], prefixes: [String]) -> String? {
        guard let appID = (plist["Entitlements"] as? [String: Any])?["application-identifier"] as? String else { return nil }
        for prefix in prefixes where appID.hasPrefix(prefix + ".") {
            return String(appID.dropFirst(prefix.count + 1))
        }
        return appID
    }
}

private extension String {
    var capitalizedFirst: String {
        guard let first = first else { return self }
        return String(first).uppercased() + dropFirst()
    }
}
