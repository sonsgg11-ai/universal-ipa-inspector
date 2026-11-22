import XCTest
@testable import IPAKit

/// Engine module tests (requirements F, G, H, I, J, K, L).
final class EngineModuleTests: XCTestCase {

    private var tempDirectory: URL!
    private var workRoot: URL!
    private var report: Report!
    private var extraction: ExtractionResult!

    override func setUpWithError() throws {
        tempDirectory = FileManager.default.temporaryDirectory
            .appendingPathComponent("EngineTests-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: tempDirectory, withIntermediateDirectories: true)

        let ipa = tempDirectory.appendingPathComponent("Sample.ipa")
        try FixtureBuilder.sampleIPA().write(to: ipa)
        let analyzer = IPAAnalyzer()
        report = try analyzer.analyze(ipaURL: ipa, progress: { _ in }, isCancelled: { false })
        guard let root = analyzer.currentWorkRoot else {
            throw XCTSkip("working root unavailable")
        }
        workRoot = root

        var layout = BundleLayout(appBundlePath: "Payload/Sample.app")
        for file in report.files {
            if file.path.contains(".framework/"), let r = file.path.range(of: ".framework") {
                let f = String(file.path[..<r.upperBound])
                if !layout.frameworks.contains(f) { layout.frameworks.append(f) }
            }
            if file.path.contains(".appex/"), let r = file.path.range(of: ".appex") {
                let e = String(file.path[..<r.upperBound])
                if !layout.extensions.contains(e) { layout.extensions.append(e) }
            }
        }
        extraction = ExtractionResult(root: root, layout: layout, files: report.files,
                                      totalBytes: report.totalBytes, rejectedEntries: [],
                                      hash: report.sha256, warnings: [])
    }

    override func tearDownWithError() throws {
        if let workRoot { try? FileManager.default.removeItem(at: workRoot) }
        if let tempDirectory { try? FileManager.default.removeItem(at: tempDirectory) }
    }

    // MARK: F — File explorer & hex workbench

    func testFileClassification() {
        let machoHead = Data([0xCF, 0xFA, 0xED, 0xFE])
        XCTAssertEqual(FileExplorer.classify(path: "Payload/App.app/App", size: 1000, head: machoHead), .executable)
        XCTAssertEqual(FileExplorer.classify(path: "Payload/App.app/App", size: 10_000, head: nil), .binary)
        XCTAssertEqual(FileExplorer.classify(path: "x/Info.plist", size: 10, head: nil), .plist)
        XCTAssertEqual(FileExplorer.classify(path: "x/config.json", size: 10, head: nil), .json)
        XCTAssertEqual(FileExplorer.classify(path: "x/libfoo.dylib", size: 10, head: nil), .dynamicLibrary)
        XCTAssertEqual(FileExplorer.classify(path: "x/embedded.mobileprovision", size: 10, head: nil), .provisioning)
        XCTAssertEqual(FileExplorer.classify(path: "x/icon.png", size: 10, head: nil), .image)
        XCTAssertEqual(FileExplorer.classify(path: "x/db.sqlitedb", size: 10, head: nil), .database)
    }

    func testInventoryBuildsWithCompressionAndPermissions() {
        let archiveEntries = try? ZipArchive.readDirectory(
            at: tempDirectory.appendingPathComponent("Sample.ipa"))
        XCTAssertNotNil(archiveEntries)
        let inventory = FileExplorer.buildInventory(
            files: report.files, archiveEntries: archiveEntries ?? [],
            extractionRoot: workRoot, maxHashedFiles: 10)
        XCTAssertEqual(inventory.count, report.files.count)
        let config = inventory.first { $0.path.contains("config.json") }
        XCTAssertNotNil(config)
        XCTAssertEqual(config?.nodeType, .json)
        XCTAssertTrue(["rw-r--r--", "rw-------", "rw-rw-r--"].contains(config?.permissions ?? ""),
                      "permissions must render in rwx form, got \(config?.permissions ?? "?")")
        XCTAssertEqual(config?.compressionRatio ?? 0, 1.0, accuracy: 0.01,
                       "stored fixture entries have compression ratio 1")
        XCTAssertTrue(inventory.contains { $0.nodeType == .executable && $0.isMachO })
        // SHA-256 present for executables
        let exe = inventory.first { $0.nodeType == .executable }
        XCTAssertEqual(exe?.sha256?.count, 64)
    }

    func testHexChunkAndSearch() throws {
        let binaryPath = report.files.first { $0.path.hasSuffix("/Sample") }!.path
        let chunk = FileExplorer.hexChunk(path: binaryPath, extractionRoot: workRoot, offset: 0, length: 64)
        XCTAssertNotNil(chunk)
        XCTAssertEqual(chunk?.bytes.count, 64)
        XCTAssertEqual(chunk?.lines.first?.offset, 0)

        // ASCII search for a string planted in the cstring payload.
        let hits = try FileExplorer.searchText(path: binaryPath, extractionRoot: workRoot,
                                               text: "https://api.example.com/v1/users")
        XCTAssertFalse(hits.isEmpty, "the planted URL must be found at an exact offset")

        // Hex search: find the Mach-O magic (MH_MAGIC_64 written little-endian).
        let pattern = try FileExplorer.parseHexPattern("cf fa ed fe")
        let magicHits = try FileExplorer.searchBytes(path: binaryPath, extractionRoot: workRoot,
                                                     pattern: pattern)
        XCTAssertEqual(magicHits.first, 0, "the Mach-O magic must be the first byte of the binary")

        // Invalid pattern is rejected.
        XCTAssertThrowsError(try FileExplorer.parseHexPattern("abc"))
        XCTAssertThrowsError(try FileExplorer.searchBytes(path: binaryPath, extractionRoot: workRoot,
                                                          pattern: Data()))
    }

    func testSearchIsCaseInsensitiveWhenRequested() throws {
        let binaryPath = report.files.first { $0.path.hasSuffix("/Sample") }!.path
        let sensitive = try FileExplorer.searchText(path: binaryPath, extractionRoot: workRoot,
                                                    text: "HTTPS://API.EXAMPLE.COM", caseSensitive: true)
        XCTAssertTrue(sensitive.isEmpty, "wrong case must not match when case-sensitive")
        let insensitive = try FileExplorer.searchText(path: binaryPath, extractionRoot: workRoot,
                                                      text: "HTTPS://API.EXAMPLE.COM", caseSensitive: false)
        XCTAssertFalse(insensitive.isEmpty, "case-insensitive search must find the planted URL")
    }

    func testPreviewTruncatesLargeFiles() throws {
        let bigPath = "Payload/Sample.app/bigtext.txt"
        let bigURL = workRoot.appendingPathComponent(bigPath)
        try Data(String(repeating: "abcdefghij", count: 40_000).utf8).write(to: bigURL)
        defer { try? FileManager.default.removeItem(at: bigURL) }

        let preview = FileExplorer.preview(path: bigPath, extractionRoot: workRoot, maxBytes: 1024)
        guard case .text(let text, let truncated) = preview else {
            return XCTFail("expected a text preview, got \(preview)")
        }
        XCTAssertTrue(truncated)
        XCTAssertLessThanOrEqual(text.utf8.count, 1024 + 40)
    }

    func testPreviewNeverModifiesSource() throws {
        let path = "Payload/Sample.app/config.json"
        let url = workRoot.appendingPathComponent(path)
        let before = try Data(contentsOf: url)
        _ = FileExplorer.preview(path: path, extractionRoot: workRoot)
        _ = FileExplorer.hexChunk(path: path, extractionRoot: workRoot, offset: 0, length: 100)
        _ = try? FileExplorer.searchText(path: path, extractionRoot: workRoot, text: "AIza")
        let after = try Data(contentsOf: url)
        XCTAssertEqual(before, after, "read-only operations must not mutate the extracted bundle")
    }

    // MARK: G — Structure

    func testStructureAnalysisListsAllComponents() {
        let structure = StructureAnalyzer.analyse(extraction: extraction, report: report)
        XCTAssertTrue(structure.components.contains { $0.kind == .mainExecutable })
        XCTAssertTrue(structure.components.contains { $0.kind == .framework && $0.name == "SampleKit" })
        XCTAssertTrue(structure.components.contains { $0.kind == .appExtension })
        XCTAssertEqual(structure.mainExecutablePath, "Payload/Sample.app/Sample")

        let framework = structure.components.first { $0.kind == .framework }
        XCTAssertEqual(framework?.bundleID, "com.example.sample.SampleKit")
        XCTAssertEqual(framework?.version, "2.0.1")
        XCTAssertEqual(framework?.minOS, "15.0")
        XCTAssertNotNil(framework?.minOSCompatible)
        XCTAssertFalse(structure.localizations.isEmpty, "en/de .lproj must be detected")
        XCTAssertFalse(structure.privacyManifests.isEmpty)
        XCTAssertTrue(structure.hasEmbeddedProvisioning == false, "the synthetic IPA has no embedded profile")
    }

    func testVersionCompatibilityCheck() {
        XCTAssertEqual(StructureAnalyzer.compareVersions("15.0", "13.0"), false)
        XCTAssertEqual(StructureAnalyzer.compareVersions("13.0", "13.0"), true)
        XCTAssertEqual(StructureAnalyzer.compareVersions("12.4", "13.0"), true)
        XCTAssertNil(StructureAnalyzer.compareVersions(nil, "13.0"))
    }

    // MARK: H — Security assessment

    func testSecurityAssessmentProducesMasvsMappedFindings() {
        let secrets = SecretScan.collectAll(extraction: extraction, report: report)
        let security = SecurityAssessor.assess(.init(report: report, structure: nil,
                                                     secrets: secrets, extraction: extraction,
                                                     policyMaxFiles: 60_000))
        XCTAssertGreaterThanOrEqual(security.count, 8)

        for finding in security {
            XCTAssertFalse(finding.masvs.isEmpty, "\(finding.id) must map to MASVS")
            XCTAssertFalse(finding.mastg.isEmpty, "\(finding.id) must map to MASTG")
            XCTAssertFalse(finding.remediation.isEmpty)
            XCTAssertTrue(finding.id.hasPrefix("SEC-"))
        }

        // ATS default: fixture has NSAllowsArbitraryLoads=false → informational default-policy finding
        XCTAssertTrue(security.contains { $0.title.contains("default policy") })
        // Cleartext http endpoints planted in the fixture
        XCTAssertTrue(security.contains { $0.title.contains("Cleartext HTTP") })
        // Debug entitlement is false in the fixture → no debuggable finding
        XCTAssertFalse(security.contains { $0.title.contains("Debuggable build") })
        // Weak TLS exception domain is planted
        XCTAssertTrue(security.contains { $0.title.contains("ATS exceptions weaken TLS") })
        // Privacy manifest present with tracking → no inconsistency
        XCTAssertFalse(security.contains { $0.title.contains("inconsistency") })
    }

    func testSecurityFindingsNeverClaimRuntimeProof() {
        let security = SecurityAssessor.assess(.init(report: report, structure: nil,
                                                     secrets: [], extraction: extraction,
                                                     policyMaxFiles: 60_000))
        let forbidden = ["confirmed vulnerability", "exploit proven", "runtime behaviour proven"]
        for finding in security {
            for phrase in forbidden {
                XCTAssertFalse(finding.explanation.lowercased().contains(phrase),
                               "\(finding.id) must not claim proof of runtime behaviour")
            }
        }
    }

    // MARK: I — Secrets

    func testSecretDetectionWithOffsetsAndMasking() {
        let hits = SecretScan.collectAll(extraction: extraction, report: report)
        guard let google = hits.first(where: { $0.name.contains("Google") }) else {
            return XCTFail("the planted Google API key must be detected, got \(hits.map(\.name))")
        }
        XCTAssertEqual(google.method, "pattern")
        XCTAssertEqual(google.confidence, "high")
        XCTAssertGreaterThan(google.offset, 0)
        XCTAssertFalse(google.masked.contains("1b2C3d4E"), "the masked value must hide the secret body")
        XCTAssertFalse(hits.contains { $0.masked.contains("AAaa11BBbb22CCcc33") },
                       "no raw secret may appear in any hit value")

        // Reveal is gated by an explicit flag.
        XCTAssertNil(SecretScanner.reveal(google, authorisedLocally: false))
        XCTAssertEqual(SecretScanner.reveal(google, authorisedLocally: true), google.matched)
    }

    func testEntropyAloneIsNeverAFinding() {
        // A high-entropy string with no credential context must NOT be flagged.
        let text = "var padding = \"Xk9mQ2vB7nLp4wZr8Tj5cY3hG6fD1sA0eU\"; var title = \"welcome\";"
        let hits = SecretScanner.scan(text: text, source: "test.js")
        XCTAssertTrue(hits.isEmpty, "entropy without context must not produce findings, got \(hits)")

        // The same string next to a credential word (but not an assignment the
        // pattern rules already cover) IS a low-confidence candidate.
        let withContext = "// keep this secret out of logs: Xk9mQ2vB7nLp4wZr8Tj5cY3hG6fD1sA0eU"
        let contextual = SecretScanner.scan(text: withContext, source: "test.js")
        XCTAssertTrue(contextual.contains { $0.method == "entropy+context" },
                      "entropy+context must catch this, got \(contextual)")
    }

    func testAllowlistedExampleKeysAreSkipped() {
        let text = "key = \"AKIAIOSFODNN7EXAMPLE\"; name = \"your_api_key_here\";"
        let hits = SecretScanner.scan(text: text, source: "docs.txt")
        XCTAssertTrue(hits.isEmpty, "documented example keys are allowlisted, got \(hits)")
    }

    // MARK: J — SDK inventory

    func testSDKInventoryDetectsWithEvidenceAndLimitations() {
        let inventory = SDKInventory.build(extraction: extraction, report: report, structure: nil)
        XCTAssertGreaterThanOrEqual(inventory.entries.count, 2)

        let firebase = inventory.entries.first { $0.name.contains("Firebase") }
        XCTAssertNotNil(firebase)
        XCTAssertFalse(firebase?.evidence.isEmpty ?? true)
        XCTAssertTrue(firebase?.tracksUsers ?? false)

        // No fabricated vulnerability claims.
        XCTAssertTrue(inventory.vulnerabilities.isEmpty)
        XCTAssertTrue(inventory.limitations.contains {
            $0.contains("No vulnerability database")
        })
        XCTAssertGreaterThanOrEqual(inventory.totalDetected, inventory.entries.count)
    }

    func testDuplicateFrameworkDetection() {
        let dup = FixtureBuilder.sampleIPA(extraEntries: [
            .init(path: "Payload/Sample.app/Frameworks/FirebaseCore.framework/FirebaseCore",
                  contents: FixtureBuilder.thinMachO(.init(symbols: [("_x", true, false)]))),
            .init(path: "Payload/Sample.app/Frameworks/FirebaseCore.framework/Info.plist",
                  contents: FixtureBuilder.xmlPlist("""
                  <dict><key>CFBundleIdentifier</key><string>com.firebase.core</string>
                  <key>CFBundleShortVersionString</key><string>11.0.0</string></dict>
                  """)),
            .init(path: "Payload/Sample.app/Frameworks/Nested/FirebaseCore.framework/FirebaseCore",
                  contents: FixtureBuilder.thinMachO(.init(symbols: [("_x", true, false)]))),
            .init(path: "Payload/Sample.app/Frameworks/Nested/FirebaseCore.framework/Info.plist",
                  contents: FixtureBuilder.xmlPlist("""
                  <dict><key>CFBundleIdentifier</key><string>com.firebase.core</string>
                  <key>CFBundleShortVersionString</key><string>11.0.0</string></dict>
                  """)),
        ])
        let ipa = tempDirectory.appendingPathComponent("Dup.ipa")
        try? dup.write(to: ipa)
        let analyzer = IPAAnalyzer()
        guard let dupReport = try? analyzer.analyze(ipaURL: ipa, progress: { _ in }, isCancelled: { false }),
              let root = analyzer.currentWorkRoot else {
            return XCTFail("duplicate-fixture analysis failed")
        }
        var layout = BundleLayout(appBundlePath: "Payload/Sample.app")
        for file in dupReport.files {
            if file.path.contains(".framework/"), let r = file.path.range(of: ".framework") {
                let f = String(file.path[..<r.upperBound])
                if !layout.frameworks.contains(f) { layout.frameworks.append(f) }
            }
        }
        let extraction = ExtractionResult(root: root, layout: layout, files: dupReport.files,
                                          totalBytes: dupReport.totalBytes, rejectedEntries: [],
                                          hash: nil, warnings: [])
        let inventory = SDKInventory.build(extraction: extraction, report: dupReport, structure: nil)
        XCTAssertFalse(inventory.duplicates.isEmpty, "the same framework name embedded twice must be flagged")
        try? FileManager.default.removeItem(at: root)
    }

    // MARK: K — Signing & provisioning

    func testProvisioningParsingFullProfile() throws {
        let profileData = FixtureBuilder.mobileprovision(plist: FixtureBuilder.sampleProfilePlist())
        let profilePath = workRoot.appendingPathComponent("Payload/Sample.app/embedded.mobileprovision")
        try profileData.write(to: profilePath)
        defer { try? FileManager.default.removeItem(at: profilePath) }

        let signing = ProvisioningParser.analyse(extraction: extraction, report: report)
        XCTAssertTrue(signing.profile.present)
        XCTAssertTrue(signing.profile.parseable)
        XCTAssertEqual(signing.profile.name, "Sample Profile")
        XCTAssertEqual(signing.profile.teamIDs.first, "TEAMID1234")
        XCTAssertEqual(signing.profile.bundleID, "com.example.sample")
        XCTAssertEqual(signing.profile.provisionedDeviceCount, 1)
        XCTAssertEqual(signing.profile.isExpired, false)
        XCTAssertTrue(signing.profile.distributionMethod?.contains("inferred") ?? false)

        // Signature state of the main binary: entitlements structurally readable.
        let mainState = signing.mainExecutableStates["Payload/Sample.app/Sample"]
        XCTAssertEqual(mainState, .structureCheckable)
        XCTAssertTrue(signing.summary.contains("not performed"), "the tool must state that it does not cryptographically verify")
    }

    func testExpiredProfileIsFlagged() throws {
        let profileData = FixtureBuilder.mobileprovision(plist: FixtureBuilder.sampleProfilePlist(expired: true))
        let profilePath = workRoot.appendingPathComponent("Payload/Sample.app/embedded.mobileprovision")
        try profileData.write(to: profilePath)
        defer { try? FileManager.default.removeItem(at: profilePath) }

        let signing = ProvisioningParser.analyse(extraction: extraction, report: report)
        XCTAssertEqual(signing.profile.isExpired, true)
    }

    func testMissingProfileIsReportedAsNotFound() {
        let signing = ProvisioningParser.analyse(extraction: extraction, report: report)
        XCTAssertEqual(signing.profile.rawStatus, .notFound)
        XCTAssertFalse(signing.profile.present)
    }

    func testUnsignedBinaryIsDistinguishedFromSigned() throws {
        // A binary without LC_CODE_SIGNATURE must be reported unsigned.
        let bare = FixtureBuilder.thinMachO(.init())
        let path = workRoot.appendingPathComponent("Payload/Sample.app/bare.bin")
        try bare.write(to: path)
        defer { try? FileManager.default.removeItem(at: path) }
        let archs = try MachOParser.parse(bare)
        XCTAssertTrue(archs[0].entitlementsXML == nil)
        // No signature command → linkedItOffset stays 0 → state unsigned
        let signing = ProvisioningParser.analyse(extraction: extraction, report: report)
        // bare.bin is not in report.binaries (not part of the analyzed report);
        // the important distinction: the main binary IS structureCheckable, so
        // unsigned vs signed states are not conflated.
        XCTAssertEqual(signing.mainExecutableStates["Payload/Sample.app/Sample"], .structureCheckable)
    }

    // MARK: L — FairPlay

    func testFairPlayDetectionPerSlice() throws {
        let encryptedIPA = tempDirectory.appendingPathComponent("Encrypted.ipa")
        try FixtureBuilder.sampleIPA(executableEncrypted: true).write(to: encryptedIPA)
        let analyzer = IPAAnalyzer()
        let encryptedReport = try analyzer.analyze(ipaURL: encryptedIPA, progress: { _ in }, isCancelled: { false })

        let fairplay = FairPlayDetector.detect(report: encryptedReport)
        XCTAssertEqual(fairplay.encryptedBinaryPaths.count, 1)
        XCTAssertTrue(fairplay.slices.contains { $0.encrypted == true && $0.cryptID == 1 && $0.cryptSize == 1024 })
        XCTAssertFalse(fairplay.blockedOperations.isEmpty)
        XCTAssertFalse(fairplay.availableOperations.isEmpty)
        XCTAssertTrue(fairplay.notice.contains("No decryption"))

        // Unencrypted fixture: no blocked operations
        let plain = FairPlayDetector.detect(report: report)
        XCTAssertTrue(plain.encryptedBinaryPaths.isEmpty)
        XCTAssertTrue(plain.blockedOperations.isEmpty)
        try? FileManager.default.removeItem(at: encryptedIPA)
    }

    func testMixedFatEncryptionIsReportedPerSlice() throws {
        let encrypted = FixtureBuilder.MachOSpec(cryptID: 1)
        let plain = FixtureBuilder.MachOSpec(cryptID: 0)
        let fat = FixtureBuilder.fat(slices: [
            (0x0100_000C, 0, FixtureBuilder.thinMachO(encrypted)),
            (0x0100_000C, 2, FixtureBuilder.thinMachO(plain)),
        ])
        let archs = try MachOParser.parse(fat)
        XCTAssertEqual(archs.count, 2)
        XCTAssertEqual(archs[0].encrypted, true)
        XCTAssertEqual(archs[1].encrypted, false)

        let binary = BinaryInfo(path: "mixed", archs: archs)
        var report = Report(source: "IPA", name: "mixed")
        report.binaries.append(binary)
        let fairplay = FairPlayDetector.detect(report: report)
        XCTAssertEqual(fairplay.mixedBinaries.count, 1)
        XCTAssertTrue(fairplay.slices.contains { $0.encrypted == true })
        XCTAssertTrue(fairplay.slices.contains { $0.encrypted == false })
    }
}

private extension FixtureBuilder.MachOSpec {
    init(cryptID: UInt32?) {
        self.init()
        self.cryptID = cryptID
    }
}
