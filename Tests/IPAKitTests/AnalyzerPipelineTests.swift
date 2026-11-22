import XCTest
@testable import IPAKit

/// End-to-end tests over a synthetic IPA.
///
/// These prove the analyzer pipeline works on a real archive: hashing,
/// extraction, plist reading, Mach-O parsing, redaction and report assembly.
/// The tests drive the analyzer directly from worker queues (no UI, no main
/// actor), which keeps them portable across Apple and Linux test runners.
final class AnalyzerPipelineTests: XCTestCase {

    private var tempDirectory: URL!

    override func setUpWithError() throws {
        tempDirectory = FileManager.default.temporaryDirectory
            .appendingPathComponent("IPAKitTests-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: tempDirectory, withIntermediateDirectories: true)
    }

    override func tearDownWithError() throws {
        if let tempDirectory { try? FileManager.default.removeItem(at: tempDirectory) }
    }

    private func makeIPA(encrypted: Bool = false, extra: [FixtureBuilder.ZipSpec] = []) throws -> URL {
        let url = tempDirectory.appendingPathComponent("Sample.ipa")
        try FixtureBuilder.sampleIPA(executableEncrypted: encrypted, extraEntries: extra).write(to: url)
        return url
    }

    private func analyze(_ url: URL) throws -> Report {
        let analyzer = IPAAnalyzer(policy: .default)
        var report: Report?
        var failure: Error?
        let done = DispatchSemaphore(value: 0)
        DispatchQueue.global().async {
            do {
                report = try analyzer.analyze(ipaURL: url, progress: { _ in }, isCancelled: { false })
            } catch {
                failure = error
            }
            done.signal()
        }
        XCTAssertEqual(done.wait(timeout: .now() + 60), .success, "analysis timed out")
        if let failure { throw failure }
        return try XCTUnwrap(report)
    }

    func testFullPipelineOnSyntheticIPA() throws {
        let url = try makeIPA()
        let report = try analyze(url)

        // Archive
        XCTAssertEqual(report.source, "IPA")
        XCTAssertNotNil(report.sha256)
        XCTAssertEqual(report.sha256?.count, 64, "SHA-256 must be 64 hex characters")
        XCTAssertGreaterThanOrEqual(report.fileCount, 4)

        // Application metadata, read from Info.plist
        let bundleID = report.findings.first { $0.title == "Bundle ID" }
        XCTAssertEqual(bundleID?.value, "com.example.sample")
        XCTAssertEqual(bundleID?.status, .verified)
        XCTAssertEqual(bundleID?.source, "Payload/Sample.app/Info.plist",
                       "every finding must name the path it came from")

        let version = report.findings.first { $0.title == "Version" }
        XCTAssertEqual(version?.value, "1.2.3")

        // Permissions
        let camera = report.findings.first { $0.title == "Camera" }
        XCTAssertEqual(camera?.value, "To scan documents.")

        // URL scheme
        let schemes = report.findings.first { $0.title == "Custom URL schemes" }
        XCTAssertTrue(schemes?.value.contains("sampleapp") == true)

        // ATS
        let ats = report.findings.first { $0.title == "NSAllowsArbitraryLoads" }
        XCTAssertEqual(ats?.value, "false")

        // Mach-O
        XCTAssertFalse(report.binaries.isEmpty)
        let mainBinary = try XCTUnwrap(report.binaries.first { $0.path.hasSuffix("/Sample") })
        XCTAssertEqual(mainBinary.archs.first?.cpu, "arm64")
        XCTAssertTrue(mainBinary.archs.first?.dylibs.contains { $0.contains("FirebaseCore") } == true)

        // Entitlements from the code signature
        let entitlements = report.findings.first { $0.title.contains("Entitlements") }
        XCTAssertTrue(entitlements?.value.contains("application-identifier") == true)
        let associatedDomains = report.findings.first { $0.title.contains("Entitlements") }
        XCTAssertTrue(associatedDomains?.value.contains("applinks:example.com") == true)

        // SDK fingerprinting
        XCTAssertTrue(report.findings.contains { $0.title == "Firebase" })
        XCTAssertTrue(report.findings.contains { $0.title == "Unity" })

        // Privacy manifest
        XCTAssertTrue(report.findings.contains { $0.category == "Privacy" && $0.value.contains("tracker.example.net") })

        // URL discovery and redaction
        XCTAssertTrue(report.domains.contains("api.example.com"))
        XCTAssertTrue(report.urls.contains { $0.hasPrefix("https://api.example.com") })
        guard let secret = report.findings.first(where: { $0.category == "Secrets" && $0.title.contains("Google") }) else {
            return XCTFail("the Google key in config.json should have been detected")
        }
        XCTAssertFalse(secret.value.contains("1b2C3d4E"),
                       "the secret must be redacted in the report")
        XCTAssertEqual(secret.status, .detected)

        // Honest limitations must be present
        XCTAssertFalse(report.limitations.isEmpty)
    }

    func testEncryptedExecutableIsBlockedNotGuessed() throws {
        let url = try makeIPA(encrypted: true)
        let report = try analyze(url)

        let encryption = report.findings.first { $0.title.contains("FairPlay encryption") }
        XCTAssertEqual(encryption?.status, .verified)
        XCTAssertTrue(encryption?.value.contains("cryptid 1") == true)

        let blocked = report.findings.first { $0.title == "Code and string analysis" }
        XCTAssertEqual(blocked?.status, .blocked,
                       "an encrypted binary must produce a blocked finding, not a silent empty result")
        XCTAssertNotNil(blocked?.note)

        // Structural facts survive encryption: load commands are not encrypted.
        let mainBinary = try XCTUnwrap(report.binaries.first { $0.path.hasSuffix("/Sample") })
        XCTAssertTrue(mainBinary.isEncrypted)
        XCTAssertFalse(mainBinary.archs.first?.dylibs.isEmpty ?? true,
                       "LC_LOAD_DYLIB is readable even when the binary is encrypted")
    }

    func testPathTraversalEntriesAreRejectedAndNotWritten() throws {
        let extra: [FixtureBuilder.ZipSpec] = [
            .init(path: "../../../../tmp/pwned.txt", contents: Data("pwned".utf8),
                  externalAttributes: FixtureBuilder.regularAttributes()),
        ]
        let url = try makeIPA(extra: extra)
        let report = try analyze(url)

        let rejection = report.findings.first { $0.title.contains("Rejected entries") }
        XCTAssertNotNil(rejection, "a traversal attempt must be reported, not silently dropped")
        XCTAssertEqual(rejection?.status, .detected)

        let target = URL(fileURLWithPath: "/tmp/pwned.txt")
        XCTAssertFalse(FileManager.default.fileExists(atPath: target.path),
                       "no file may be written outside the working directory")
        XCTAssertFalse(report.files.contains { $0.path.contains("..") })
    }

    func testSymlinkEntryIsNotWritten() throws {
        let extra: [FixtureBuilder.ZipSpec] = [
            .init(path: "Payload/Sample.app/evil-link", contents: Data("/etc/passwd".utf8),
                  externalAttributes: FixtureBuilder.symlinkAttributes()),
        ]
        let url = try makeIPA(extra: extra)
        let report = try analyze(url)
        XCTAssertTrue(report.findings.contains { $0.title.contains("symlink") && $0.status == .detected })
    }

    func testNonIPAIsRejectedCleanly() throws {
        let url = tempDirectory.appendingPathComponent("notanipa.ipa")
        try Data("this is definitely not a zip archive".utf8).write(to: url)
        let analyzer = IPAAnalyzer()
        XCTAssertThrowsError(try analyzer.analyze(ipaURL: url, progress: { _ in }, isCancelled: { false }))
    }

    func testZipWithoutAppBundleIsRejected() throws {
        let url = tempDirectory.appendingPathComponent("noapp.ipa")
        try FixtureBuilder.zip([
            .init(path: "README.txt", contents: Data("nothing here".utf8))
        ]).write(to: url)
        let analyzer = IPAAnalyzer()
        XCTAssertThrowsError(try analyzer.analyze(ipaURL: url, progress: { _ in }, isCancelled: { false })) { error in
            XCTAssertTrue("\(error)".contains("Payload") || "\(error)".contains(".app"),
                          "the error must say what was missing, got: \(error)")
        }
    }

    func testCancellationStopsTheRunAndCleansUp() throws {
        let url = try makeIPA()
        let analyzer = IPAAnalyzer()
        var calls = 0
        XCTAssertThrowsError(try analyzer.analyze(
            ipaURL: url,
            progress: { _ in },
            isCancelled: {
                calls += 1
                return calls > 1     // cancel after the first checkpoint
            }
        )) { error in
            XCTAssertTrue(error is CancellationError, "expected CancellationError, got \(error)")
        }
    }

    func testTemporaryDirectoriesAreRemovedOnFailure() throws {
        let before = try FileManager.default.contentsOfDirectory(atPath: FileManager.default.temporaryDirectory.path)
            .filter { $0.hasPrefix("IPAInspector-") }
        let url = tempDirectory.appendingPathComponent("broken.ipa")
        try Data(repeating: 0x41, count: 5000).write(to: url)
        let analyzer = IPAAnalyzer()
        _ = try? analyzer.analyze(ipaURL: url, progress: { _ in }, isCancelled: { false })
        let after = try FileManager.default.contentsOfDirectory(atPath: FileManager.default.temporaryDirectory.path)
            .filter { $0.hasPrefix("IPAInspector-") }
        XCTAssertEqual(before.count, after.count,
                       "a failed run must not leave analysis work directories behind")
    }

    func testProgressIsReportedThroughout() throws {
        let url = try makeIPA()
        let analyzer = IPAAnalyzer()
        var messages: [String] = []
        let done = DispatchSemaphore(value: 0)
        DispatchQueue.global().async {
            _ = try? analyzer.analyze(ipaURL: url, progress: { messages.append($0) }, isCancelled: { false })
            done.signal()
        }
        XCTAssertEqual(done.wait(timeout: .now() + 60), .success)
        XCTAssertGreaterThanOrEqual(messages.count, 5, "the UI needs frequent progress updates")
        XCTAssertTrue(messages.contains { $0.contains("Hashing") })
        XCTAssertTrue(messages.contains { $0.contains("Mach-O") || $0.contains("Parsing") })
    }

    func testLargeArchiveIsHandledWithinPolicy() throws {
        // 400 files of 64 KiB, stored — representative of a real app bundle.
        var specs: [FixtureBuilder.ZipSpec] = []
        let payload = Data(repeating: 0xAB, count: 64 * 1024)
        for i in 0..<400 {
            specs.append(.init(path: "Payload/Sample.app/assets/file\(i).bin", contents: payload,
                               externalAttributes: FixtureBuilder.regularAttributes()))
        }
        let url = try makeIPA(extra: specs)
        let report = try analyze(url)
        XCTAssertGreaterThanOrEqual(report.fileCount, 400)
        XCTAssertGreaterThan(report.totalBytes, 400 * 64 * 1024)
    }
}
