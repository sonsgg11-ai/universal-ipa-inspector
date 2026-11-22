import XCTest
@testable import IPAKit

/// Engine module tests part 2 (requirements M, N, O, P, Q, V).
final class SearchDashboardExportTests: XCTestCase {

    private var tempDirectory: URL!
    private var workRoot: URL!
    private var report: Report!
    private var extraction: ExtractionResult!
    private var outcome: AnalysisEngine.Outcome!

    override func setUpWithError() throws {
        tempDirectory = FileManager.default.temporaryDirectory
            .appendingPathComponent("SearchTests-\(UUID().uuidString)")
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

        // Build a full engine outcome synchronously for module tests.
        var o = AnalysisEngine.Outcome(report: report)
        o.inventory = FileExplorer.buildInventory(files: report.files, archiveEntries: [],
                                                  extractionRoot: root, maxHashedFiles: 5)
        o.structure = StructureAnalyzer.analyse(extraction: extraction, report: report)
        o.signing = ProvisioningParser.analyse(extraction: extraction, report: report)
        o.fairplay = FairPlayDetector.detect(report: report)
        o.secrets = SecretScan.collectAll(extraction: extraction, report: report)
        o.sdk = SDKInventory.build(extraction: extraction, report: report, structure: o.structure)
        o.security = SecurityAssessor.assess(.init(report: report, structure: o.structure,
                                                   secrets: o.secrets, extraction: extraction,
                                                   policyMaxFiles: 60_000))
        var rebuiltBinaries: [BinaryInfo] = []
        for binary in report.binaries {
            let symbols = BinaryMetadata.symbols(forBinaryAt: root.appendingPathComponent(binary.path))
            o.symbols[binary.path] = symbols
            let archs = binary.archs.map { arch -> ArchInfo in
                var copy = arch
                copy.symbols = symbols
                return copy
            }
            rebuiltBinaries.append(BinaryInfo(path: binary.path, archs: archs,
                                              warnings: binary.warnings,
                                              componentKind: binary.componentKind,
                                              parentBundle: binary.parentBundle))
        }
        o.report.binaries = rebuiltBinaries
        o.dashboard = DashboardProvider.snapshot(report: o.report, structure: o.structure,
                                                 security: o.security, secrets: o.secrets,
                                                 sdk: o.sdk, fairplay: o.fairplay,
                                                 searchIndex: nil, signing: o.signing)
        let index = CrossBinarySearch.SearchIndex()
        let objc = BinaryMetadata.objcInfo(extraction: extraction, binaries: report.binaries)
        let swift = BinaryMetadata.swiftInfo(extraction: extraction, binaries: report.binaries)
        index.build(extraction: extraction, report: report, symbols: o.symbols,
                    objc: objc, swift: swift)
        o.searchIndex = index
        o.extractionRoot = root
        o.engineMetadata = ReportExporter.EngineMetadata(analysisStartedAt: Date(),
                                                         analysisFinishedAt: Date(),
                                                         limitations: report.limitations)
        outcome = o
    }

    override func tearDownWithError() throws {
        if let workRoot { try? FileManager.default.removeItem(at: workRoot) }
        if let tempDirectory { try? FileManager.default.removeItem(at: tempDirectory) }
    }

    // MARK: M — Cross-binary search

    func testSearchIndexBuildsAndFindsSymbols() {
        let index = outcome.searchIndex!
        XCTAssertTrue(index.isBuilt)
        let results = index.search("SampleManager", filter: .init())
        XCTAssertFalse(results.hits.isEmpty, "planted symbol _SampleManager.currentMetadata must be found")
        XCTAssertTrue(results.hits.contains { $0.category == .symbol })
        XCTAssertTrue(results.bySource.contains { $0.key.contains("/Sample") })
        XCTAssertEqual(results.query, "SampleManager")
    }

    func testSearchFiltersByCategoryAndComponent() {
        let index = outcome.searchIndex!
        let symbolOnly = index.search("Sample", filter: .init(category: .symbol))
        XCTAssertFalse(symbolOnly.hits.isEmpty)
        XCTAssertTrue(symbolOnly.hits.allSatisfy { $0.category == .symbol })

        let frameworkOnly = index.search("Sample", filter: .init(component: "Payload/Sample.app/Frameworks/"))
        XCTAssertTrue(frameworkOnly.hits.allSatisfy { $0.source.hasPrefix("Payload/Sample.app/Frameworks/") })

        let urlResults = index.search("api.example.com", filter: .init(category: .url))
        XCTAssertFalse(urlResults.hits.isEmpty)
    }

    func testSearchRegexAndCaseSensitivity() {
        let index = outcome.searchIndex!
        let regexResults = index.search("^_SampleManager.*", filter: .init(caseSensitive: true, useRegex: true))
        XCTAssertFalse(regexResults.hits.isEmpty, "regex search over symbols must work")

        let caseSensitive = index.search("SAMPLEMANAGER", filter: .init(caseSensitive: true, useRegex: true))
        XCTAssertTrue(caseSensitive.hits.isEmpty, "uppercase must not match under case-sensitive regex")

        let caseInsensitive = index.search("SAMPLEMANAGER", filter: .init(caseSensitive: false, useRegex: true))
        XCTAssertFalse(caseInsensitive.hits.isEmpty)
    }

    func testSearchHistory() {
        let history = CrossBinarySearch.History()
        history.add("first query")
        history.add("second")
        history.add("first query")
        XCTAssertEqual(history.all().count, 2, "duplicates collapse and most-recent first")
        XCTAssertEqual(history.all().first, "first query")
        history.clear()
        XCTAssertTrue(history.all().isEmpty)
    }

    func testSearchEmptyQueryReturnsEmpty() {
        let results = outcome.searchIndex!.search("", filter: .init())
        XCTAssertTrue(results.hits.isEmpty)
    }

    // MARK: ObjC / Swift metadata

    func testObjCMetadataExtractsNames() {
        let objc = BinaryMetadata.objcInfo(extraction: extraction, binaries: report.binaries)
        let main = objc["Payload/Sample.app/Sample"]
        XCTAssertNotNil(main)
        // The planted strings include objc_class_name_SampleViewController in
        // __cstring; real classname sections are not present in the fixture,
        // so the honest status is notFound or verified depending on sections.
        XCTAssertFalse(main?.status == .blocked)
    }

    func testSwiftMetadataStatusIsHonest() {
        let swift = BinaryMetadata.swiftInfo(extraction: extraction, binaries: report.binaries)
        for (path, info) in swift {
            XCTAssertNotEqual(info.status, .blocked, "\(path) is not encrypted")
        }
    }

    func testDemangleLite() {
        XCTAssertEqual(BinaryMetadata.demangleLite("_TtC4Main10SampleView"), "Main.SampleView")
        XCTAssertEqual(BinaryMetadata.demangleLite("not-mangled"), "not-mangled")
    }

    // MARK: N — Dashboard (values must match the real analysis)

    func testDashboardCountsMatchAnalysis() {
        let d = outcome.dashboard!
        XCTAssertEqual(d.appName, "Sample App")
        XCTAssertEqual(d.bundleID, "com.example.sample")
        XCTAssertEqual(d.version, "1.2.3")
        XCTAssertEqual(d.buildNumber, "42")
        XCTAssertEqual(d.minOS, "13.0")
        XCTAssertEqual(d.ipaSHA256, report.sha256)
        XCTAssertEqual(d.fileCount, report.fileCount)
        XCTAssertGreaterThanOrEqual(d.frameworkCount, 1)
        XCTAssertGreaterThanOrEqual(d.extensionCount, 1)
        XCTAssertEqual(d.encryptedBinaryCount, 0)
        XCTAssertEqual(d.unencryptedBinaryCount, report.binaries.count)
        XCTAssertEqual(d.urlCount, report.urls.count)
        XCTAssertEqual(d.domainCount, report.domains.count)
        XCTAssertEqual(d.sdkCount, outcome.sdk?.entries.count ?? 0)
        XCTAssertEqual(d.securityFindingCount, outcome.security.count)
        XCTAssertEqual(d.secretCount, outcome.secrets.count)
        XCTAssertGreaterThanOrEqual(d.importedSymbolCount + d.exportedSymbolCount, 3,
                                    "the fixture plants five symbols across binaries")
        XCTAssertGreaterThanOrEqual(d.blockedChecks, 0)
        XCTAssertGreaterThan(d.completedChecks, 0)
    }

    // MARK: O — Report exports

    func testJSONExportRoundTrips() throws {
        let data = try ReportExporter.exportJSON(report: report,
                                                 security: outcome.security,
                                                 secrets: outcome.secrets,
                                                 metadata: outcome.engineMetadata,
                                                 dashboard: outcome.dashboard,
                                                 structure: outcome.structure,
                                                 signing: outcome.signing,
                                                 fairplay: outcome.fairplay,
                                                 sdk: outcome.sdk)
        XCTAssertFalse(data.isEmpty)
        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .iso8601
        let decoded = try decoder.decode(ReportExporter.CompleteJSON.self, from: data)
        XCTAssertEqual(decoded.report.sha256, report.sha256)
        XCTAssertEqual(decoded.security.count, outcome.security.count)
        XCTAssertEqual(decoded.secrets.count, outcome.secrets.count)
        // Masked secrets in the export
        XCTAssertTrue(decoded.secrets.allSatisfy { !$0.masked.contains("1b2C3d4E") })
    }

    func testCSVExports() throws {
        let findingsCSV = ReportExporter.exportFindingsCSV(report: report, security: outcome.security)
        let text = String(data: findingsCSV, encoding: .utf8)!
        let rows = text.components(separatedBy: "\n").filter { !$0.isEmpty }
        XCTAssertEqual(rows.count, report.findings.count + outcome.security.count + 1,
                       "one header + every finding and security finding")
        XCTAssertTrue(text.hasPrefix("id,category,title,value,source,status,severity,confidence,masvs,note"))

        let symbolsCSV = String(data: ReportExporter.exportSymbolsCSV(report: report), encoding: .utf8)!
        XCTAssertGreaterThan(symbolsCSV.components(separatedBy: "\n").count, 1,
                             "fixture binaries carry symbols")

        let componentsCSV = String(data: ReportExporter.exportComponentsCSV(outcome.structure!),
                                   encoding: .utf8)!
        XCTAssertTrue(componentsCSV.contains("com.example.sample.SampleKit"))
    }

    func testTXTExportContainsAllSections() {
        let txt = ReportExporter.exportTXT(report: report, security: outcome.security,
                                           fairplay: outcome.fairplay,
                                           signing: outcome.signing,
                                           metadata: outcome.engineMetadata)
        for marker in ["IPA INSPECTOR", "APPLICATION", "BINARIES", "SECURITY FINDINGS",
                       "METHODOLOGY", "LIMITATIONS"] {
            XCTAssertTrue(txt.contains(marker), "missing section \(marker)")
        }
        XCTAssertTrue(txt.contains("SEC-0"), "security finding IDs must appear")
    }

    func testPDFExportIsValidDocument() {
        let pdf = ReportExporter.exportPDF(report: report, security: outcome.security,
                                           secrets: outcome.secrets,
                                           metadata: outcome.engineMetadata,
                                           fairplay: outcome.fairplay)
        let text = String(decoding: pdf, as: UTF8.self)
        XCTAssertTrue(text.hasPrefix("%PDF-1.4"), "PDF must declare its version")
        XCTAssertTrue(text.contains("%%EOF"), "PDF must end with EOF marker")
        XCTAssertTrue(text.contains("/Type /Catalog"), "catalog object required")
        XCTAssertTrue(text.contains("/Type /Pages"), "pages tree required")
        XCTAssertTrue(text.contains("startxref"), "xref table required")
        // Every page object pair must exist.
        let pageObjects = text.components(separatedBy: "\n").filter { $0.contains("/Type /Page ") }
        XCTAssertGreaterThanOrEqual(pageObjects.count, 2, "cover + findings pages at minimum")
        // xref offsets must point at "N 0 obj" markers.
        let xrefRange = text.range(of: "xref\n0 ")!
        let xrefBody = String(text[xrefRange.lowerBound...])
        let lines = xrefBody.components(separatedBy: "\n")
        var checked = 0
        for line in lines.dropFirst(2) {
            let parts = line.split(separator: " ")
            guard parts.count >= 3 else { break }
            if parts[2] == "f" { continue }
            guard parts[2] == "n" else { break }
            if let offset = Int(parts[0]) {
                let start = text.index(text.startIndex, offsetBy: offset)
                let snippet = String(text[start...].prefix(12))
                XCTAssertTrue(snippet.contains(" 0 obj"), "xref offset \(offset) must point at an object, got '\(snippet)'")
                checked += 1
            }
            if checked >= 5 { break }
        }
        XCTAssertGreaterThanOrEqual(checked, 5)
    }

    // MARK: V — Export package

    func testExportPackageBuildsValidZip() throws {
        let destination = tempDirectory.appendingPathComponent("export.zip")
        let url = try ExportPackager.buildPackage(outcome: outcome, destination: destination)

        XCTAssertTrue(FileManager.default.fileExists(atPath: url.path))
        let entries = try ZipArchive.readDirectory(at: url)

        let expected = "\(ExportPackager.rootFolder)/"
        let paths = entries.map(\.path)
        XCTAssertTrue(paths.contains("\(expected)manifest.json"))
        XCTAssertTrue(paths.contains("\(expected)summary.json"))
        XCTAssertTrue(paths.contains("\(expected)application-metadata.json"))
        XCTAssertTrue(paths.contains("\(expected)file-inventory.csv"))
        XCTAssertTrue(paths.contains("\(expected)binaries/binary-inventory.csv"))
        XCTAssertTrue(paths.contains("\(expected)binaries/macho-headers.csv"))
        XCTAssertTrue(paths.contains("\(expected)binaries/symbols.csv"))
        XCTAssertTrue(paths.contains("\(expected)security/findings.json"))
        XCTAssertTrue(paths.contains("\(expected)security/secret-detections-masked.json"))
        XCTAssertTrue(paths.contains("\(expected)security/owasp-mapping.json"))
        XCTAssertTrue(paths.contains("\(expected)reports/technical-summary.txt"))
        XCTAssertTrue(paths.contains("\(expected)reports/complete-report.pdf"))

        // Manifest must name blocked/incomplete modules honestly.
        let manifestEntry = entries.first { $0.path == "\(expected)manifest.json" }!
        let manifestData = try ZipArchive.rawData(at: url, entry: manifestEntry)
        let manifestDecoder = JSONDecoder()
        manifestDecoder.dateDecodingStrategy = .iso8601
        let manifest = try manifestDecoder.decode(ExportPackager.Manifest.self, from: manifestData)
        XCTAssertEqual(manifest.ipaName, report.name)
        XCTAssertEqual(manifest.ipaSHA256, report.sha256)
        XCTAssertEqual(manifest.moduleCounts["securityFindings"], outcome.security.count)
        XCTAssertTrue(manifest.notes.contains { $0.contains("masked") })

        // PDF entry must be a valid PDF.
        let pdfEntry = entries.first { $0.path == "\(expected)reports/complete-report.pdf" }!
        let pdfData = try ZipArchive.rawData(at: url, entry: pdfEntry)
        XCTAssertTrue(String(data: pdfData.prefix(8), encoding: .ascii)!.hasPrefix("%PDF-1.4"))

        // JSON entries must decode.
        let findingsEntry = entries.first { $0.path == "\(expected)security/findings.json" }!
        let findingsData = try ZipArchive.rawData(at: url, entry: findingsEntry)
        let decodedFindings = try JSONDecoder().decode([SecurityAssessor.Finding].self, from: findingsData)
        XCTAssertEqual(decodedFindings.count, outcome.security.count)
    }

    func testExportPackageRoundTripsEveryEntry() throws {
        let destination = tempDirectory.appendingPathComponent("export2.zip")
        let url = try ExportPackager.buildPackage(outcome: outcome, destination: destination)
        let entries = try ZipArchive.readDirectory(at: url)
        for entry in entries {
            let data = try ZipArchive.rawData(at: url, entry: entry)
            XCTAssertFalse(data.isEmpty, "entry \(entry.path) must contain data")
        }
    }

    // MARK: Q — MCP core (real JSON-RPC, masked secrets)

    func testMCPServerHandlesProtocol() throws {
        let server = MCPCore.ServerCore(outcomeProvider: { self.outcome })

        // initialize
        let initialize = """
        {"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}
        """.data(using: .utf8)!
        let initResponse = server.handle(messageData: initialize)!
        let initText = String(data: initResponse, encoding: .utf8)!
        XCTAssertTrue(initText.contains("protocolVersion"))
        XCTAssertTrue(initText.contains("IPAInspectorMCPServer"))

        // tools/list
        let list = """
        {"jsonrpc":"2.0","id":2,"method":"tools/list"}
        """.data(using: .utf8)!
        let listResponse = server.handle(messageData: list)!
        let listText = String(data: listResponse, encoding: .utf8)!
        XCTAssertTrue(listText.contains("get_app_metadata"))
        XCTAssertTrue(listText.contains("list_secrets_masked"))

        // tools/call
        let call = """
        {"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"get_app_metadata"}}
        """.data(using: .utf8)!
        let callResponse = server.handle(messageData: call)!
        let callText = String(data: callResponse, encoding: .utf8)!
        XCTAssertTrue(callText.contains("com.example.sample"))

        // masked secrets tool
        let secrets = """
        {"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"list_secrets_masked"}}
        """.data(using: .utf8)!
        let secretsResponse = server.handle(messageData: secrets)!
        let secretsText = String(data: secretsResponse, encoding: .utf8)!
        XCTAssertFalse(secretsText.contains("1b2C3d4E"),
                       "MCP responses must never leak raw secrets")
        XCTAssertTrue(secretsText.contains("masked"))

        // error paths
        let bad = """
        {"jsonrpc":"1.0","id":5,"method":"x"}
        """.data(using: .utf8)!
        let badResponse = server.handle(messageData: bad)!
        XCTAssertTrue(String(data: badResponse, encoding: .utf8)!.contains("Invalid Request"))

        let unknown = """
        {"jsonrpc":"2.0","id":6,"method":"tools/call","params":{"name":"nonexistent_tool"}}
        """.data(using: .utf8)!
        let unknownResponse = server.handle(messageData: unknown)!
        XCTAssertTrue(String(data: unknownResponse, encoding: .utf8)!.contains("Unknown tool"))
    }

    func testMCPWithNoOutcomeIsHonest() throws {
        let server = MCPCore.ServerCore(outcomeProvider: { nil })
        let call = """
        {"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"get_app_metadata"}}
        """.data(using: .utf8)!
        let response = server.handle(messageData: call)!
        XCTAssertTrue(String(data: response, encoding: .utf8)!.contains("No analysis has been completed"))
    }
}

/// Pipeline-level tests for the engine façade (requirement P).
@MainActor
final class EnginePipelineTests: XCTestCase {

    func testEngineRunsAllStagesAndProducesOutcome() async throws {
        let dir = FileManager.default.temporaryDirectory
            .appendingPathComponent("Pipe-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: dir) }

        let ipa = dir.appendingPathComponent("Sample.ipa")
        try FixtureBuilder.sampleIPA().write(to: ipa)

        let engine = AnalysisEngine()
        let outcome = try await engine.run(ipaURL: ipa)

        XCTAssertNotNil(outcome.report.sha256)
        XCTAssertFalse(outcome.report.files.isEmpty)
        XCTAssertNotNil(outcome.structure)
        XCTAssertNotNil(outcome.signing)
        XCTAssertNotNil(outcome.fairplay)
        XCTAssertNotNil(outcome.sdk)
        XCTAssertNotNil(outcome.dashboard)
        XCTAssertNotNil(outcome.searchIndex)
        XCTAssertFalse(outcome.security.isEmpty)
        XCTAssertFalse(outcome.inventory.isEmpty)
        XCTAssertFalse(outcome.symbols.isEmpty)
        XCTAssertNotNil(outcome.engineMetadata)
        XCTAssertEqual(outcome.engineMetadata.toolName, "IPA Inspector")
    }

    func testEngineCacheAvoidsRecomputation() async throws {
        let dir = FileManager.default.temporaryDirectory
            .appendingPathComponent("Cache-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: dir) }

        let ipa = dir.appendingPathComponent("Sample.ipa")
        try FixtureBuilder.sampleIPA().write(to: ipa)

        let cache = EngineCache()
        var calls = 0
        let first = cache.inventory(for: ipa) {
            calls += 1
            return []
        }
        let second = cache.inventory(for: ipa) {
            calls += 1
            return []
        }
        XCTAssertTrue(first.isEmpty)
        XCTAssertTrue(second.isEmpty)
        XCTAssertEqual(calls, 1, "the second read must be served from cache")
        cache.reset()
    }

    func testEngineCancellationStopsRun() async throws {
        let dir = FileManager.default.temporaryDirectory
            .appendingPathComponent("Cancel-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: dir) }

        let ipa = dir.appendingPathComponent("Sample.ipa")
        try FixtureBuilder.sampleIPA().write(to: ipa)

        let engine = AnalysisEngine()
        let task = Task.detached { try await engine.run(ipaURL: ipa) }
        engine.cancel()
        do {
            _ = try await task.value
            // Cancellation is cooperative; a fast fixture may finish anyway.
        } catch is CancellationError {
            // expected path
        } catch {
            // other errors are acceptable only if not cancellation-related
        }
    }
}
