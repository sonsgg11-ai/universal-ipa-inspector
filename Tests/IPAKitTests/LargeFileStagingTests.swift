import XCTest
@testable import IPAKit
#if canImport(ZIPFoundation)
import ZIPFoundation
#endif

/// Large-file and staging coverage.
///
/// These tests exist because of a real production failure: a ~230 MB IPA could
/// not be imported. Two defects were responsible — deflated entries were
/// "extracted" through a file handle opened on a file that was never created
/// (so the payload silently vanished), and stored entries were loaded into
/// memory whole. Both paths are now streaming, and these tests prove they
/// produce byte-identical output across chunk boundaries.
final class LargeFileStagingTests: XCTestCase {

    private var tempDirectory: URL!

    override func setUpWithError() throws {
        tempDirectory = FileManager.default.temporaryDirectory
            .appendingPathComponent("IPAKitStaging-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: tempDirectory, withIntermediateDirectories: true)
    }

    override func tearDownWithError() throws {
        if let tempDirectory { try? FileManager.default.removeItem(at: tempDirectory) }
    }

    // MARK: Deterministic large payload

    /// A deterministic, position-sensitive pattern: any dropped, reordered or
    /// duplicated chunk breaks the comparison.
    private static func patternedData(_ byteCount: Int) -> Data {
        var data = Data(capacity: byteCount)
        var seed: UInt64 = 0x9E37_79B9_7F4A_7C15
        for index in 0..<byteCount {
            seed = seed &* 6364136223846793005 &+ 1442695040888963407
            data.append(UInt8(truncatingIfNeeded: seed >> 33))
            if index % (1 << 20) == 0 { data.append(UInt8(index & 0xFF)) }
        }
        return data
    }

    /// Sendable-safe accumulator for values recorded inside @Sendable closures.
    final class Box<T>: @unchecked Sendable {
        var value: T
        init(_ value: T) { self.value = value }
    }

    // MARK: Deflated IPA end to end

    #if canImport(ZIPFoundation)
    /// Real-world IPAs carry deflated entries (ZIP method 8). Builds one with
    /// ZIPFoundation, runs the full pipeline, and requires every entry to land
    /// on disk byte for byte — the old bug silently produced empty files here.
    func testDeflatedIPAPipelineExtractsEveryFileByteForByte() throws {
        let configJSON = """
        {
          "endpoint": "https://api.example.com/v2",
          "marker": "deflate-e2e"
        }
        """
        let entries: [(path: String, data: Data, deflate: Bool)] = [
            ("Payload/Sample.app/Info.plist", FixtureBuilder.sampleInfoPlist(), false),
            ("Payload/Sample.app/Sample",
             FixtureBuilder.thinMachO(FixtureBuilder.MachOSpec(symbols: [("_main", true, false)])),
             true),
            ("Payload/Sample.app/config.json", Data(configJSON.utf8), true),
            ("Payload/Sample.app/assets.bin", Self.patternedData(3 * 1024 * 1024 + 12345), true),
        ]

        let ipa = tempDirectory.appendingPathComponent("Deflated.ipa")
        let archive = try Archive(url: ipa, accessMode: .create)
        for entry in entries {
            let scratch = tempDirectory.appendingPathComponent(UUID().uuidString)
            try entry.data.write(to: scratch)
            try archive.addEntry(with: entry.path, fileURL: scratch,
                                 compressionMethod: entry.deflate ? .deflate : .none)
            try? FileManager.default.removeItem(at: scratch)
        }

        let analyzer = IPAAnalyzer(policy: .default)
        let report = try analyzer.analyze(ipaURL: ipa, progress: { _ in }, isCancelled: { false })

        // Every entry reached the disk with the right size.
        XCTAssertEqual(report.fileCount, entries.count,
                       "every deflated entry must be extracted, not silently skipped")
        for entry in entries {
            let url = try XCTUnwrap(analyzer.currentWorkRoot?.appendingPathComponent(entry.path))
            let onDisk = try Data(contentsOf: url)
            XCTAssertEqual(onDisk, entry.data,
                           "\(entry.path) must survive a deflate round trip byte for byte")
        }

        // The pipeline still understood what it extracted.
        let bundleID = report.findings.first { $0.title == "Bundle ID" }
        XCTAssertEqual(bundleID?.value, "com.example.sample")
        XCTAssertEqual(bundleID?.status, .verified)
        XCTAssertFalse(report.binaries.isEmpty, "the extracted main executable must be parsed as Mach-O")
        XCTAssertEqual(report.binaries.first?.path, "Payload/Sample.app/Sample")
    }

    /// An entry ZIPFoundation cannot locate must come back as nil (a warning),
    /// never as success — silent success is what made the old bug invisible.
    func testDeflateExtractorReportsMissingEntryAsNil() throws {
        let storedZip = tempDirectory.appendingPathComponent("plain.zip")
        try FixtureBuilder.zip([
            .init(path: "Payload/Sample.app/config.json", contents: "{}"),
        ]).write(to: storedZip)

        let extractor = DeflateExtractor(archiveURL: storedZip)
        XCTAssertTrue(extractor.isAvailable, "a well-formed archive must yield a usable deflate index")
        let entry = ZipArchive.Entry(path: "Payload/Sample.app/does-not-exist",
                                     contents: Data("ghost".utf8))
        let written = try extractor.stream(entry: entry, to: tempDirectory.appendingPathComponent("ghost.bin"))
        XCTAssertNil(written, "a missing entry is a warning, not a silent success")
    }
    #endif

    // MARK: Stored entries across chunk boundaries

    /// A stored entry larger than the streaming chunk size (1 MiB default).
    /// Multi-chunk streaming must reassemble the exact bytes.
    func testStoredEntryLargerThanChunkStreamsWithExactBytes() throws {
        let payload = Self.patternedData(3 * 1024 * 1024 + 777)
        let ipa = tempDirectory.appendingPathComponent("BigStored.ipa")
        try FixtureBuilder.sampleIPA(extraEntries: [
            .init(path: "Payload/Sample.app/Data/big.dat", contents: payload),
        ]).write(to: ipa)

        let analyzer = IPAAnalyzer(policy: .default)
        let report = try analyzer.analyze(ipaURL: ipa, progress: { _ in }, isCancelled: { false })

        let onDisk = try Data(contentsOf: XCTUnwrap(
            analyzer.currentWorkRoot?.appendingPathComponent("Payload/Sample.app/Data/big.dat")))
        XCTAssertEqual(onDisk, payload)
        XCTAssertGreaterThanOrEqual(report.totalBytes, Int64(payload.count),
                                    "the inventory total must include the streamed entry")
    }

    /// Direct multi-chunk read through the raw streamer.
    func testStreamRawDataRoundTripsAcrossChunks() throws {
        let payload = Self.patternedData(4 * 1024 * 1024 + 11)
        let zipURL = tempDirectory.appendingPathComponent("one-entry.zip")
        try FixtureBuilder.zip([
            .init(path: "Payload/Sample.app/Data/blob.dat", contents: payload),
        ]).write(to: zipURL)

        let entries = try ZipArchive.readDirectory(at: zipURL)
        let entry = try XCTUnwrap(entries.first)

        var collected = Data()
        let consumed = try ZipArchive.streamRawData(at: zipURL, entry: entry, chunkSize: 1 << 20) { chunk in
            collected.append(chunk)
        }
        XCTAssertEqual(Int64(collected.count), consumed)
        XCTAssertEqual(collected, payload)
    }

    // MARK: Staging

    func testRequiredCapacityIsConservativeAndCapped() {
        // Small IPA: copy + ~2x expansion + margin.
        let small = IPAStager.requiredCapacity(compressedSize: 230 * 1024 * 1024)
        XCTAssertEqual(small, Int64(230 * 1024 * 1024) * 3 + 256 * 1024 * 1024)

        // The expansion plan never exceeds the analyzer's extraction policy.
        let huge = IPAStager.requiredCapacity(compressedSize: 900 * 1024 * 1024 * 1024)
        XCTAssertEqual(huge, 966_367_641_600 + 4_294_967_296 + 268_435_456,
                       "900 GiB compressed: copy + capped expansion + margin")

        // Monotonic: a bigger IPA never needs less storage.
        XCTAssertGreaterThanOrEqual(
            IPAStager.requiredCapacity(compressedSize: 500_000_000),
            IPAStager.requiredCapacity(compressedSize: 100_000_000))
    }

    func testStorageGuardHonoursUnknownVolumeAndRealNumbers() throws {
        // Unknown capacity (Linux, exotic volumes) must never block an import.
        try IPAStager.guardStorage(compressedSize: 900 * 1024 * 1024 * 1024, available: nil)

        // Plenty of space passes.
        try IPAStager.guardStorage(compressedSize: 230 * 1024 * 1024, available: 8 * 1024 * 1024 * 1024)

        // Too little space fails with the actionable error.
        XCTAssertThrowsError(
            try IPAStager.guardStorage(compressedSize: 230 * 1024 * 1024, available: 100 * 1024 * 1024)
        ) { error in
            guard case IPAStager.StagingError.notEnoughStorage = error else {
                return XCTFail("expected notEnoughStorage, got \(error)")
            }
            XCTAssertTrue(error.localizedDescription.contains("storage"),
                          "the message must tell the user what to do")
        }
    }

    func testStreamingCopyRoundTripsWithProgress() throws {
        let payload = Self.patternedData(9 * 1024 * 1024 + 3)   // 3+ chunks at 4 MiB
        let source = tempDirectory.appendingPathComponent("source.ipa")
        try payload.write(to: source)
        let destination = tempDirectory.appendingPathComponent("staged.ipa")

        var progressCalls = Box<[(copied: Int64, total: Int64)]>([])
        try IPAStager.copyStreaming(from: source, to: destination, chunkSize: 4 * 1024 * 1024) {
            progressCalls.value.append(($0, $1))
        }

        let copied = try Data(contentsOf: destination)
        XCTAssertEqual(copied, payload, "the staged copy must be byte-identical to the import")
        XCTAssertFalse(progressCalls.value.isEmpty, "progress must be reported during the copy")
        XCTAssertEqual(progressCalls.value.last?.copied, Int64(payload.count))
        XCTAssertEqual(progressCalls.value.last?.total, Int64(payload.count))
        for call in progressCalls.value where call.total > 0 {
            XCTAssertLessThanOrEqual(call.copied, call.total, "progress must never run ahead of the file size")
        }
    }

    func testCancelledCopyRemovesItsOutput() throws {
        let payload = Data(repeating: 0x5A, count: 10 * 1024 * 1024)
        let source = tempDirectory.appendingPathComponent("source.ipa")
        try payload.write(to: source)
        let destination = tempDirectory.appendingPathComponent("staged.ipa")

        let checks = Box(0)
        XCTAssertThrowsError(
            try IPAStager.copyStreaming(from: source, to: destination,
                                        chunkSize: 4 * 1024 * 1024,
                                        isCancelled: { checks.value += 1; return checks.value > 1 })
        ) { error in
            XCTAssertTrue(error is CancellationError, "cancellation must surface as CancellationError")
        }
        XCTAssertFalse(FileManager.default.fileExists(atPath: destination.path),
                       "a cancelled copy must not leave a partial file behind")
    }

    // MARK: App Store link parsing and formatting

    func testAppStoreLinkParsingCoversRealWorldInputs() {
        // The exact shape from the product video: a path-only store link.
        XCTAssertEqual(AppStoreClient.parse("/app/botb-win-your-dream-car/id528229538")?.id, "528229538")
        XCTAssertEqual(AppStoreClient.parse("/app/botb-win-your-dream-car/id528229538")?.country, "us")

        // Full URLs, with and without a storefront segment.
        XCTAssertEqual(AppStoreClient.parse("https://apps.apple.com/gb/app/anything/id1234567890?foo=bar")?.id, "1234567890")
        XCTAssertEqual(AppStoreClient.parse("https://apps.apple.com/gb/app/anything/id1234567890?foo=bar")?.country, "gb")
        XCTAssertEqual(AppStoreClient.parse("https://apps.apple.com/app/anything/id1234567890")?.country, "us")

        // Bare IDs and id-prefixed tokens.
        XCTAssertEqual(AppStoreClient.parse("528229538")?.id, "528229538")
        XCTAssertEqual(AppStoreClient.parse("id528229538")?.id, "528229538")

        // Non-links fail honestly.
        XCTAssertNil(AppStoreClient.parse("https://example.com/not-a-store-page"))
    }

    func testListingValuesAreHumanised() {
        XCTAssertEqual(AppStoreClient.humanisedValue("fileSizeBytes", "241172480"),
                       ByteCountFormatter.string(fromByteCount: 241_172_480, countStyle: .file))
        XCTAssertEqual(AppStoreClient.humanisedValue("userRatingCount", 33000), "33000")
        XCTAssertEqual(AppStoreClient.humanisedValue("averageUserRating", 4.8), "4.8")
        XCTAssertEqual(AppStoreClient.humanisedValue("trackName", "BOTB"), "BOTB")
    }
}
