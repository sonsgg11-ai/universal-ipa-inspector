import Foundation

/// The analysis engine (requirement P): one façade that runs every module in
/// stages with real progress, cooperative cancellation and per-file caching.
///
/// Pure Foundation — no SwiftUI, no Combine — so the whole pipeline runs and
/// is tested identically on iOS and Linux. UI layers wrap this class with
/// their own observable adapter.
final class AnalysisEngine {

    enum Stage: String, CaseIterable, Sendable {
        case hash, extract, inventory, macho, metadata, security, secrets,
             structure, signing, fairplay, sdk, dashboard, searchIndex, exports
    }

    struct ProgressState: Sendable {
        let stage: Stage
        let message: String
        let fraction: Double
    }

    struct Outcome {
        var report: Report
        var inventory: [FileExplorer.FileMetadata] = []
        var structure: StructureAnalyzer.StructureReport?
        var security: [SecurityAssessor.Finding] = []
        var secrets: [SecretScanner.Hit] = []
        var signing: ProvisioningParser.SigningReport?
        var fairplay: FairPlayDetector.EncryptionReport?
        var sdk: SDKInventory.Inventory?
        var dashboard: DashboardProvider.Snapshot?
        var symbols: [String: [SymbolEntry]] = [:]
        var searchIndex: CrossBinarySearch.SearchIndex?
        var searchHistory: CrossBinarySearch.History = .init()
        var extractionRoot: URL?
        var archiveEntries: [ZipArchive.Entry] = []
        var engineMetadata: ReportExporter.EngineMetadata = ReportExporter.EngineMetadata(analysisStartedAt: Date(), analysisFinishedAt: Date(), limitations: [])
        init(report: Report) {
            self.report = report
        }
    }

    /// Progress callback, called from the analysis task.
    var onProgress: (@Sendable (ProgressState) -> Void)?

    private let cancelBox = CancelBox()
    private let cache = EngineCache()
    private let diagnosticsLock = NSLock()
    private var diagnosticsStorage: [String] = []

    init() {}

    func cancel() {
        cancelBox.set()
        diagnosticsLock.lock()
        diagnosticsStorage.append("[engine] cancellation requested")
        diagnosticsLock.unlock()
    }

    /// True when cancellation was requested on this engine. Readable from any
    /// thread, including from the staging copy before the engine task starts.
    var isCancelled: Bool { cancelBox.isSet }

    var diagnostics: [String] {
        diagnosticsLock.lock(); defer { diagnosticsLock.unlock() }
        return diagnosticsStorage
    }

    // MARK: Entry point

    /// Runs the complete analysis asynchronously with staged progress.
    func run(ipaURL: URL) async throws -> Outcome {
        let startedAt = Date()
        let analyzer = IPAAnalyzer()
        var outcome = try await runCore(ipaURL: ipaURL, analyzer: analyzer)
        outcome.engineMetadata = ReportExporter.EngineMetadata(
            analysisStartedAt: startedAt,
            analysisFinishedAt: Date(),
            limitations: outcome.report.limitations)
        outcome.engineMetadata.diagnosticsLog = diagnostics
        return outcome
    }

    private func runCore(ipaURL: URL, analyzer: IPAAnalyzer) async throws -> Outcome {
        var outcome = Outcome(report: Report(source: "IPA", name: ipaURL.lastPathComponent))
        try Task.checkCancellation()

        func reportProgress(_ stage: Stage, _ message: String) {
            let fraction = Double(Stage.allCases.firstIndex(of: stage)! + 1) / Double(Stage.allCases.count)
            onProgress?(ProgressState(stage: stage, message: message, fraction: fraction))
        }

        // ---- Stage 1-2: core pipeline (hash, extract, plist, Mach-O, resources) ----
        outcome.report = try await withCheckedThrowingContinuation { continuation in
            DispatchQueue.global(qos: .userInitiated).async {
                do {
                    let report = try analyzer.analyze(
                        ipaURL: ipaURL,
                        progress: { [weak self] message in
                            // Real-time messages from hashing, extraction and
                            // bundle inspection reach the UI as they happen.
                            self?.onProgress?(ProgressState(stage: .extract, message: message, fraction: 2.0 / 14.0))
                        },
                        isCancelled: { Task.isCancelled || self.cancelBox.isSet })
                    continuation.resume(returning: report)
                } catch {
                    continuation.resume(throwing: error)
                }
            }
        }
        reportProgress(.macho, "Mach-O parsing complete: \(outcome.report.binaries.count) binaries")
        try Task.checkCancellation()

        guard let workRoot = analyzer.currentWorkRoot else {
            throw EngineError.noWorkingRoot
        }
        outcome.extractionRoot = workRoot

        // ---- Stage 3: archive entries + extraction context ----
        let entries = (try? ZipArchive.readDirectory(at: ipaURL)) ?? []
        outcome.archiveEntries = entries
        let extraction = try rebuildExtraction(from: outcome.report, root: workRoot)
        reportProgress(.inventory, "File inventory: \(outcome.report.files.count) files")
        try Task.checkCancellation()

        // ---- Stage 4: file inventory (cached per IPA) ----
        outcome.inventory = cache.inventory(for: ipaURL) {
            FileExplorer.buildInventory(
                files: outcome.report.files,
                archiveEntries: entries,
                extractionRoot: workRoot,
                isCancelled: { Task.isCancelled || self.cancelBox.isSet })
        }
        try Task.checkCancellation()

        // ---- Stage 5: symbols (cached per file) ----
        for binary in outcome.report.binaries {
            if cancelBox.isSet { throw CancellationError() }
            let symbols = cache.symbols(for: binary.path) {
                BinaryMetadata.symbols(forBinaryAt: workRoot.appendingPathComponent(binary.path))
            }
            outcome.symbols[binary.path] = symbols
            if let index = outcome.report.binaries.firstIndex(where: { $0.path == binary.path }) {
                let newArchs = binary.archs.map { arch -> ArchInfo in
                    var copy = arch
                    copy.symbols = symbols
                    return copy
                }
                outcome.report.binaries[index] = BinaryInfo(
                    path: binary.path, archs: newArchs,
                    warnings: binary.warnings,
                    componentKind: binary.componentKind,
                    parentBundle: binary.parentBundle)
            }
        }
        reportProgress(.metadata, "Symbols and metadata extracted")

        // ---- Stage 6: structure ----
        outcome.structure = StructureAnalyzer.analyse(
            extraction: extraction, report: outcome.report,
            isCancelled: { Task.isCancelled || self.cancelBox.isSet })
        try Task.checkCancellation()

        // ---- Stage 7: signing ----
        outcome.signing = ProvisioningParser.analyse(
            extraction: extraction, report: outcome.report,
            isCancelled: { Task.isCancelled || self.cancelBox.isSet })

        // ---- Stage 8: FairPlay ----
        outcome.fairplay = FairPlayDetector.detect(report: outcome.report)
        reportProgress(.fairplay, "Encryption status: \(outcome.fairplay!.encryptedBinaryPaths.count) encrypted binaries")

        // ---- Stage 9: secrets ----
        outcome.secrets = cache.secrets(for: ipaURL) {
            SecretScan.collectAll(extraction: extraction, report: outcome.report)
        }
        try Task.checkCancellation()

        // ---- Stage 10: SDK inventory ----
        outcome.sdk = SDKInventory.build(
            extraction: extraction, report: outcome.report,
            structure: outcome.structure,
            isCancelled: { Task.isCancelled || self.cancelBox.isSet })

        // ---- Stage 11: security assessment ----
        outcome.security = SecurityAssessor.assess(
            .init(report: outcome.report,
                  structure: outcome.structure,
                  secrets: outcome.secrets,
                  extraction: extraction,
                  policyMaxFiles: analyzer.policy.maxFiles),
            isCancelled: { Task.isCancelled || self.cancelBox.isSet })
        reportProgress(.security, "Security assessment: \(outcome.security.count) findings")
        try Task.checkCancellation()

        // ---- Stage 12: dashboard ----
        outcome.dashboard = DashboardProvider.snapshot(
            report: outcome.report,
            structure: outcome.structure,
            security: outcome.security,
            secrets: outcome.secrets,
            sdk: outcome.sdk,
            fairplay: outcome.fairplay,
            searchIndex: nil,
            signing: outcome.signing)

        // ---- Stage 13: search index ----
        let index = CrossBinarySearch.SearchIndex()
        let objc = BinaryMetadata.objcInfo(extraction: extraction,
                                           binaries: outcome.report.binaries,
                                           isCancelled: { Task.isCancelled || self.cancelBox.isSet })
        let swift = BinaryMetadata.swiftInfo(extraction: extraction,
                                             binaries: outcome.report.binaries,
                                             isCancelled: { Task.isCancelled || self.cancelBox.isSet })
        index.build(extraction: extraction,
                    report: outcome.report,
                    symbols: outcome.symbols,
                    objc: objc,
                    swift: swift,
                    isCancelled: { Task.isCancelled || self.cancelBox.isSet })
        outcome.searchIndex = index
        reportProgress(.searchIndex, "Search index ready")

        diagnosticsLock.lock()
        diagnosticsStorage.append("[engine] analysis completed for \(ipaURL.lastPathComponent)")
        diagnosticsLock.unlock()
        return outcome
    }

    private func rebuildExtraction(from report: Report, root: URL) throws -> ExtractionResult {
        var layout = BundleLayout(appBundlePath: "Payload/unknown.app")
        if let first = report.files.first(where: { $0.path.contains(".app/") }),
           let range = first.path.range(of: ".app") {
            layout.appBundlePath = String(first.path[..<range.upperBound])
        }
        for file in report.files {
            let p = file.path
            if p.contains(".framework/"), let r = p.range(of: ".framework") {
                let f = String(p[..<r.upperBound])
                if !layout.frameworks.contains(f) { layout.frameworks.append(f) }
            }
            if p.contains(".appex/"), let r = p.range(of: ".appex") {
                let e = String(p[..<r.upperBound])
                if !layout.extensions.contains(e) { layout.extensions.append(e) }
            }
            if p.contains(".app/PlugIns/"), let r = p.range(of: ".app/PlugIns/") {
                let rest = p[r.upperBound...]
                if let sep = rest.firstIndex(of: "/") {
                    let plugin = String(p[..<sep])
                    if !layout.plugins.contains(plugin) { layout.plugins.append(plugin) }
                }
            }
        }
        layout.nestedBundles = layout.appBundles.filter { $0 != layout.appBundlePath }
        return ExtractionResult(
            root: root,
            layout: layout,
            files: report.files,
            totalBytes: report.totalBytes,
            rejectedEntries: [],
            hash: report.sha256,
            warnings: [])
    }

    enum EngineError: LocalizedError {
        case noWorkingRoot
        var errorDescription: String {
            switch self {
            case .noWorkingRoot: return "The analysis working directory is unavailable."
            }
        }
    }
}

/// Thread-safe cancellation flag shared between the UI and the engine task.
final class CancelBox: @unchecked Sendable {
    private let lock = NSLock()
    private var isCancelled = false
    func set() {
        lock.lock(); defer { lock.unlock() }
        isCancelled = true
    }
    var isSet: Bool {
        lock.lock(); defer { lock.unlock() }
        return isCancelled
    }
}

/// Thread-safe progress channel from the analyzer thread.
final class ProgressBox: @unchecked Sendable {
    private let lock = NSLock()
    private var last: String = ""
    func set(_ message: String) {
        lock.lock(); defer { lock.unlock() }
        last = message
    }
    func current() -> String {
        lock.lock(); defer { lock.unlock() }
        return last
    }
}

/// Per-file and per-run result caches so repeated views never re-parse.
final class EngineCache: @unchecked Sendable {
    private let lock = NSLock()
    private var inventoryCache: [URL: [FileExplorer.FileMetadata]] = [:]
    private var secretsCache: [URL: [SecretScanner.Hit]] = [:]
    private var symbolsCache: [String: [SymbolEntry]] = [:]

    func inventory(for ipa: URL, producer: () -> [FileExplorer.FileMetadata]) -> [FileExplorer.FileMetadata] {
        lock.lock()
        if let cached = inventoryCache[ipa] {
            lock.unlock()
            return cached
        }
        lock.unlock()
        let value = producer()
        lock.lock()
        inventoryCache[ipa] = value
        lock.unlock()
        return value
    }

    func secrets(for ipa: URL, producer: () -> [SecretScanner.Hit]) -> [SecretScanner.Hit] {
        lock.lock()
        if let cached = secretsCache[ipa] {
            lock.unlock()
            return cached
        }
        lock.unlock()
        let value = producer()
        lock.lock()
        secretsCache[ipa] = value
        lock.unlock()
        return value
    }

    func symbols(for path: String, producer: () -> [SymbolEntry]) -> [SymbolEntry] {
        lock.lock()
        if let cached = symbolsCache[path] {
            lock.unlock()
            return cached
        }
        lock.unlock()
        let value = producer()
        lock.lock()
        symbolsCache[path] = value
        lock.unlock()
        return value
    }

    func reset() {
        lock.lock(); defer { lock.unlock() }
        inventoryCache = [:]
        secretsCache = [:]
        symbolsCache = [:]
    }
}

// MARK: - Full-bundle secret collection (requirement I entry point)

enum SecretScan {
    /// Scans text resources and unencrypted binary strings, de-duplicated by
    /// masked value, with file+offset provenance on every hit.
    static func collectAll(extraction: ExtractionResult,
                           report: Report,
                           maxFiles: Int = 400) -> [SecretScanner.Hit] {
        var hits: [SecretScanner.Hit] = []
        var seen = Set<String>()

        let textExtensions: Set<String> = ["json", "plist", "js", "xml", "txt", "html",
                                           "strings", "cfg", "config", "ini", "yaml",
                                           "yml", "csv", "properties", "css"]
        var scanned = 0
        for file in extraction.files {
            guard scanned < maxFiles else { break }
            let ext = (file.path as NSString).pathExtension.lowercased()
            guard textExtensions.contains(ext) || file.path.contains("/Localizable") else { continue }
            guard file.size < 8 * 1024 * 1024 else { continue }
            guard let data = try? Data(contentsOf: extraction.root.appendingPathComponent(file.path), options: .mappedIfSafe) else { continue }
            scanned += 1
            var text = String(decoding: data, as: UTF8.self)
            if ext == "plist", let plist = NativePlist.parse(data),
               let xml = try? PropertyListSerialization.data(fromPropertyList: plist, format: .xml, options: 0) {
                text = String(decoding: xml, as: UTF8.self)
            }
            for hit in SecretScanner.scan(text: text, source: file.path) {
                if seen.insert(hit.masked).inserted {
                    hits.append(hit)
                }
            }
        }

        for binary in report.binaries where !binary.isEncrypted {
            let url = extraction.root.appendingPathComponent(binary.path)
            let scanner = StringScanner(url: url, maxBytes: 64 * 1024 * 1024)
            let strings = scanner.strings()
            if strings.isEmpty { continue }
            for hit in SecretScanner.scan(text: strings.joined(separator: "\n"),
                                          source: binary.path + " (binary strings)",
                                          limit: 12) {
                if seen.insert(hit.masked).inserted {
                    hits.append(hit)
                }
            }
        }
        return hits
    }
}
