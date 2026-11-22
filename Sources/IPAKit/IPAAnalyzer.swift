import Foundation

/// Which artefact a file inside the IPA belongs to.
enum BundleRole: String, Codable {
    case mainApp = "main app"
    case framework = "framework"
    case appExtension = "app extension"
    case appClip = "app clip"
    case plugin = "plug-in"
    case watchApp = "watch app"
    case resource = "resource"
}

/// Inventory + structure of the extracted bundle.
struct BundleLayout {
    var appBundlePath: String
    var appBundles: [String] = []
    var frameworks: [String] = []
    var extensions: [String] = []
    var plugins: [String] = []
    var watchApps: [String] = []
    var nestedBundles: [String] = []
    var mainExecutable: String?
    var warnings: [String] = []

    static func role(for path: String) -> BundleRole {
        if path.contains(".appex/") || path.hasSuffix(".appex") { return .appExtension }
        if path.contains(".app/PlugIns/") || path.contains(".appex/PlugIns/") { return .plugin }
        if path.contains(".framework/") || path.hasSuffix(".framework") { return .framework }
        if path.contains(".app/") && path != ".app" { return .mainApp }
        return .resource
    }
}

/// Everything the analyzer learned from the archive, before it becomes a Report.
struct ExtractionResult {
    var root: URL                       // temporary directory holding Payload/
    var layout: BundleLayout
    var files: [FileEntry]
    var totalBytes: Int64
    var rejectedEntries: [(entry: String, reason: String)]
    var hash: String?
    var warnings: [String]
}

final class IPAAnalyzer {

    // MARK: Policy

    struct Policy {
        /// Hard cap on the number of files we will enumerate and report. iOS
        /// will happily let a hostile archive contain millions of entries; the
        /// analyzer stops honest work at this point and says so.
        var maxFiles = 60_000
        /// Cap on how much we will decompress to disk in one run.
        var maxTotalUncompressed: Int64 = 4 * 1024 * 1024 * 1024
        /// Per-entry cap.
        var maxEntryUncompressed: Int64 = 2 * 1024 * 1024 * 1024
        /// Binaries larger than this are hashed and inventoried but not
        /// string-scanned, keeping peak memory bounded on a phone.
        var maxBinaryScanBytes = 64 * 1024 * 1024
        var maxTextResourceBytes = 8 * 1024 * 1024
        /// Upper bound on the number of URLs collected, so a pathological file
        /// cannot blow up the report.
        var maxURLs = 4_000
        static let `default` = Policy()
    }

    let policy: Policy
    private let fileManager = FileManager.default

    init(policy: Policy = .default) {
        self.policy = policy
    }

    // MARK: Entry point

    /// Runs the analysis. `progress` is called from the analyzer's own thread.
    /// `isCancelled` is polled at safe points; on cancellation the analyzer
    /// throws `CancellationError` and removes everything it created.
    func analyze(ipaURL: URL,
                 progress: @escaping (String) -> Void,
                 isCancelled: @escaping () -> Bool) throws -> Report {

        let workRoot = fileManager.temporaryDirectory
            .appendingPathComponent("IPAInspector-\(UUID().uuidString)", isDirectory: true)
        try fileManager.createDirectory(at: workRoot, withIntermediateDirectories: true)
        onWorkRootCreated?(workRoot)

        var analysis = Report(source: "IPA", name: ipaURL.lastPathComponent)
        var extraction: ExtractionResult?

        do {
            try checkCancellation(isCancelled)

            progress("Hashing archive…")
            let hash = try sha256(of: ipaURL)
            analysis.sha256 = hash
            analysis.findings.append(Finding(
                category: "Archive", title: "SHA-256 of the IPA",
                value: hash, source: ipaURL.lastPathComponent, status: .verified))

            let size = (try? fileManager.attributesOfItem(atPath: ipaURL.path)[.size] as? Int64) ?? 0
            analysis.findings.append(Finding(
                category: "Archive", title: "IPA size on disk",
                value: ByteCountFormatter.string(fromByteCount: size, countStyle: .file),
                source: ipaURL.lastPathComponent, status: .verified))

            progress("Reading archive directory…")
            let entries = try ZipArchive.readDirectory(at: ipaURL)
            let plan = ZipArchive.buildPlan(entries,
                                            maxEntryBytes: policy.maxEntryUncompressed,
                                            maxTotalBytes: policy.maxTotalUncompressed)

            if !plan.rejected.isEmpty {
                let grouped = Dictionary(grouping: plan.rejected, by: { $0.reason })
                    .mapValues(\.count)
                    .sorted { $0.value > $1.value }
                for (reason, count) in grouped {
                    let examples = plan.rejected.filter { $0.reason == reason }.prefix(5).map(\.entry)
                    analysis.findings.append(Finding(
                        category: "Archive safety",
                        title: "Rejected entries: \(reason)",
                        value: "\(count) entr\(count == 1 ? "y" : "ies"). e.g. \(examples.joined(separator: ", "))",
                        source: ipaURL.lastPathComponent,
                        status: .detected,
                        note: "Rejected entries are never written to disk."))
                }
            }

            try checkCancellation(isCancelled)

            progress("Extracting \(plan.accepted.count) files…")
            let result = try extract(plan: plan, archive: ipaURL, into: workRoot, isCancelled: isCancelled)
            extraction = result

            analysis.files = result.files
            analysis.fileCount = result.files.count
            analysis.totalBytes = result.totalBytes
            analysis.name = (result.layout.appBundlePath as NSString).lastPathComponent
                .replacingOccurrences(of: ".app", with: "")

            analysis.findings.append(Finding(
                category: "Archive", title: "Files extracted",
                value: "\(result.files.count) files, \(ByteCountFormatter.string(fromByteCount: result.totalBytes, countStyle: .file))",
                source: "Payload/", status: .verified))

            if result.files.count >= policy.maxFiles {
                analysis.limitations.append(
                    "The archive contains more than \(policy.maxFiles) files; the inventory stops there.")
            }
            for warning in result.warnings {
                analysis.findings.append(Finding(
                    category: "Archive safety", title: "Extraction note",
                    value: warning, source: ipaURL.lastPathComponent, status: .detected))
            }

            try checkCancellation(isCancelled)

            let inspector = BundleInspector(policy: policy)
            inspector.analyseBundle(extraction: result, into: &analysis,
                                    progress: progress, isCancelled: isCancelled)

            analysis.limitations.append(contentsOf: standardLimitations)
            currentWorkRoot = workRoot
            return analysis

        } catch {
            // A failed run must not leave analysis directories behind.
            cleanUp(workRoot)
            currentWorkRoot = nil
            throw error
        }
    }

    /// The working directory of the most recent successful run, kept on disk
    /// so the file explorer can serve previews without re-extracting.
    public private(set) var currentWorkRoot: URL?

    /// Optional observer for the working-directory creation. Lets callers
    /// (and tests) track exactly which directory this analyzer created, so
    /// cleanup can be verified without inspecting the shared temp folder.
    var onWorkRootCreated: ((URL) -> Void)?

    /// Removes the working directory. Safe to call repeatedly.
    func cleanUp(_ root: URL?) {
        guard let root else { return }
        try? fileManager.removeItem(at: root)
        if root == currentWorkRoot { currentWorkRoot = nil }
    }

    private func checkCancellation(_ isCancelled: () -> Bool) throws {
        if isCancelled() { throw CancellationError() }
    }

    // MARK: Hashing

    func sha256(of url: URL) throws -> String {
        let handle = try FileHandle(forReadingFrom: url)
        defer { try? handle.close() }
        var hasher = SHA256()
        while true {
            try Task.checkCancellation()
            guard let chunk = try handle.read(upToCount: 4 * 1024 * 1024), !chunk.isEmpty else { break }
            hasher.update(data: chunk)
        }
        return hasher.finalize().map { String(format: "%02x", $0) }.joined()
    }

    // MARK: Extraction

    private func extract(plan: ZipArchive.ExtractionPlan,
                         archive: URL,
                         into root: URL,
                         isCancelled: () -> Bool) throws -> ExtractionResult {

        let handle = try FileHandle(forReadingFrom: archive)
        defer { try? handle.close() }

        var files: [FileEntry] = []
        var total: Int64 = 0
        var warnings: [String] = []
        var layoutPath: String?

        let bufferSize = 1 << 20

        for entry in plan.accepted {
            try checkCancellation(isCancelled)

            // Normalise and re-verify right before writing. Defence in depth:
            // buildPlan already rejected bad paths, this catches a bug in it.
            let relative = entry.path
            let destination = root.appendingPathComponent(relative).standardizedFileURL
            let rootPath = root.standardizedFileURL.path
            guard destination.path == rootPath || destination.path.hasPrefix(rootPath + "/") else {
                warnings.append("Refused to write \(relative): resolved outside the working directory.")
                continue
            }

            try fileManager.createDirectory(at: destination.deletingLastPathComponent(),
                                            withIntermediateDirectories: true)

            // Raw stored bytes when the entry is uncompressed, so a huge IPA of
            // already-compressed assets never inflates in memory.
            let payload: Data
            do {
                payload = try ZipArchive.rawData(at: archive, entry: entry,
                                                 maxBytes: policy.maxEntryUncompressed)
            } catch {
                warnings.append("Could not read \(relative): \(error.localizedDescription)")
                continue
            }

            if entry.compressionMethod == 0 {
                try payload.write(to: destination, options: .atomic)
            } else {
                // Deflate path. ZIPFoundation handles stored and deflated
                // entries; we re-read the entry through it for correctness,
                // streamed to disk rather than into memory.
                if let extracted = try? extractWithZipFoundation(archive: archive,
                                                                 entryPath: relative,
                                                                 to: destination,
                                                                 bufferSize: bufferSize) {
                    guard extracted else {
                        warnings.append("Could not decompress \(relative)")
                        continue
                    }
                } else {
                    warnings.append("Skipped \(relative): decompression is unavailable for method \(entry.compressionMethod).")
                    continue
                }
            }

            let onDisk = (try? fileManager.attributesOfItem(atPath: destination.path)[.size] as? Int64) ?? 0
            total += onDisk ?? 0

            let role = BundleLayout.role(for: relative)
            files.append(FileEntry(path: relative, size: onDisk ?? 0, kind: role.rawValue))

            if relative.hasSuffix(".app/") == false, relative.contains("Payload/"),
               relative.hasSuffix(".app") || relative.contains(".app/") {
                if layoutPath == nil, let range = relative.range(of: ".app") {
                    layoutPath = String(relative[relative.startIndex...range.lowerBound]) + "app"
                }
            }

            if files.count >= policy.maxFiles {
                warnings.append("File limit reached at \(policy.maxFiles); remaining entries were not extracted.")
                break
            }
        }

        guard let appPath = layoutPath ?? files.first(where: { $0.path.hasPrefix("Payload/") && $0.path.contains(".app/") })
            .map({ String($0.path[..<$0.path.range(of: ".app")!.upperBound]) }) else {
            throw IPAAnalyzerError.noAppBundle
        }

        var layout = BundleLayout(appBundlePath: appPath)
        for file in files {
            let p = file.path
            if p.hasSuffix(".app") || p.contains(".app/") {
                if p.contains(".app/"), let r = p.range(of: ".app") {
                    let bundle = String(p[..<r.upperBound])
                    if !layout.appBundles.contains(bundle) { layout.appBundles.append(bundle) }
                }
            }
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
            if p.contains(".watchapp/"), p.contains(".app/"), let r = p.range(of: ".watchapp") {
                let w = String(p[..<r.upperBound])
                if !layout.watchApps.contains(w) { layout.watchApps.append(w) }
            }
        }
        layout.nestedBundles = layout.appBundles.filter { $0 != appPath }

        return ExtractionResult(root: root, layout: layout, files: files,
                                totalBytes: total, rejectedEntries: plan.rejected,
                                hash: nil, warnings: warnings)
    }

    /// Streams a deflated entry to disk through ZIPFoundation's `extract`.
    /// Returns nil when ZIPFoundation is unavailable or the entry is absent.
    private func extractWithZipFoundation(archive: URL,
                                          entryPath: String,
                                          to destination: URL,
                                          bufferSize: Int) throws -> Bool? {
        #if canImport(ZIPFoundation)
        guard let zip = try? Archive(url: archive, accessMode: .read) else { return nil }
        guard let entry = zip[entryPath] else { return true }
        do {
            _ = try zip.extract(entry, consumer: { chunk in
                try? (try? FileHandle(forWritingTo: destination))?.write(contentsOf: chunk)
            })
            return true
        } catch {
            return false
        }
        #else
        return nil
        #endif
    }

    private var standardLimitations: [String] {
        [
            "Static analysis cannot prove that an API endpoint list is complete: URLs assembled at runtime, obfuscated, or sent inside encrypted payloads will not appear.",
            "Secrets found in strings are candidates. A candidate is never proof that a credential is live.",
            "SDK fingerprints match names and paths. They show that a library is present in the bundle, not that its code runs.",
            "An encrypted (FairPlay) executable cannot be disassembled or string-scanned. The report marks every affected check as blocked rather than empty.",
            "Nothing here retrieves an IPA from an App Store link, and nothing here decrypts a FairPlay binary.",
        ]
    }
}

enum IPAAnalyzerError: LocalizedError, CustomStringConvertible {
    case noAppBundle
    case multipleAppBundles([String])
    case archiveTooLarge(String)

    var errorDescription: String? {
        switch self {
        case .noAppBundle:
            return "No Payload/*.app bundle was found in this archive. Is it an IPA?"
        case .multipleAppBundles(let list):
            return "The archive contains more than one application bundle (\(list.count)). Choose the one to analyse."
        case .archiveTooLarge(let detail):
            return "Archive exceeds a safety limit: \(detail)"
        }
    }

    var description: String { errorDescription ?? String(describing: self) }
}

#if canImport(CryptoKit)
import CryptoKit
#elseif canImport(Crypto)
import Crypto
#endif
#if canImport(ZIPFoundation)
import ZIPFoundation
#endif
// MARK: - File hashing

/// Streaming SHA-256 used for the IPA and individual files. The hash runs in
/// fixed-size chunks, so peak memory does not depend on file size.
enum FileHasher {
    static func sha256(of url: URL) throws -> String {
        let handle = try FileHandle(forReadingFrom: url)
        defer { try? handle.close() }
        var hasher = SHA256()
        while true {
            guard let chunk = try handle.read(upToCount: 4 * 1024 * 1024), !chunk.isEmpty else { break }
            hasher.update(data: chunk)
        }
        return hasher.finalize().map { String(format: "%02x", $0) }.joined()
    }
}

