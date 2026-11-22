import Foundation
import SwiftUI

/// Owns the lifecycle of one analysis run and is the only thing the UI observes.
///
/// All mutation happens on the main actor. The analyzer runs in a detached task
/// and reports back through `await MainActor.run`, so there is no path for a
/// background thread to touch published state directly.
@MainActor
final class AnalysisSession: ObservableObject {

    enum Phase: Equatable {
        case idle
        case running(String)
        case finished
        case failed(String)
        case cancelled
    }

    @Published private(set) var phase: Phase = .idle
    @Published private(set) var report: Report?
    @Published private(set) var progressFraction: Double = 0
    @Published private(set) var log: [String] = []
    @Published var storefront: String = "us"

    private var task: Task<Void, Never>?
    private var workingRoot: URL?

    var isRunning: Bool {
        if case .running = phase { return true }
        return false
    }

    // MARK: App Store lookup

    func lookup(_ input: String) {
        guard !isRunning else { return }
        cancel()
        report = nil
        progressFraction = 0
        log = ["Looking up \(input)"]
        phase = .running("Contacting the App Store…")

        let requested = storefront
        task = Task { [weak self] in
            do {
                let result = try await AppStoreClient.lookup(input: input, storefront: requested)
                guard !Task.isCancelled else { return }
                await MainActor.run {
                    guard let self else { return }
                    self.report = result
                    self.log.append("Received listing data for \(result.name).")
                    self.progressFraction = 1
                    self.phase = .finished
                }
            } catch {
                guard !Task.isCancelled else { return }
                await MainActor.run {
                    guard let self else { return }
                    self.phase = .failed(error.localizedDescription)
                    self.log.append("Lookup failed: \(error.localizedDescription)")
                }
            }
        }
    }

    // MARK: IPA analysis

    func analyse(ipaURL: URL, policy: IPAAnalyzer.Policy = .default) {
        guard !isRunning else { return }
        cancel()
        report = nil
        progressFraction = 0

        let name = ipaURL.lastPathComponent
        log = ["Importing \(name)"]
        phase = .running("Preparing…")

        // Copy out of the importer's sandbox first, on the main actor, while the
        // security scope is held. The copy is what the analyzer reads.
        let staged = FileManager.default.temporaryDirectory
            .appendingPathComponent("IPAInspector-input-\(UUID().uuidString)")
            .appendingPathComponent(name)

        let accessed = ipaURL.startAccessingSecurityScopedResource()
        defer { if accessed { ipaURL.stopAccessingSecurityScopedResource() } }

        do {
            try FileManager.default.createDirectory(at: staged.deletingLastPathComponent(),
                                                    withIntermediateDirectories: true)
            try? FileManager.default.removeItem(at: staged)
            try FileManager.default.copyItem(at: ipaURL, to: staged)
        } catch {
            phase = .failed("Could not read the selected file: \(error.localizedDescription)")
            return
        }
        log.append("Staged a working copy (\(ByteCountFormatter.string(fromByteCount: (try? FileManager.default.attributesOfItem(atPath: staged.path)[.size] as? Int64).flatMap { $0 } ?? 0, countStyle: .file))).")

        let analyzer = IPAAnalyzer(policy: policy)
        let totalSteps = 10
        let counter = ProgressCounter(total: totalSteps)

        task = Task.detached(priority: .userInitiated) { [weak self, staged] in
            let workRootBox = RootBox()
            do {
                let result = try analyzer.analyze(
                    ipaURL: staged,
                    progress: { message in
                        let done = counter.increment()
                        Task { @MainActor [weak self] in
                            guard let self else { return }
                            self.phase = .running(message)
                            self.progressFraction = min(0.95, Double(done) / Double(totalSteps + 2))
                            self.log.append(message)
                        }
                    },
                    isCancelled: { Task.isCancelled })

                await MainActor.run {
                    guard let self else { return }
                    self.workingRoot = workRootBox.value
                    self.report = result
                    self.progressFraction = 1
                    self.log.append("Analysis complete: \(result.findings.count) findings, \(result.fileCount) files.")
                    self.phase = .finished
                }
            } catch is CancellationError {
                analyzer.cleanUp(workRootBox.value)
                await MainActor.run { [weak self] in
                    self?.phase = .cancelled
                    self?.log.append("Cancelled. Temporary files were removed.")
                }
            } catch {
                analyzer.cleanUp(workRootBox.value)
                await MainActor.run { [weak self] in
                    self?.phase = .failed(error.localizedDescription)
                    self?.log.append("Analysis failed: \(error.localizedDescription)")
                }
            }
            try? FileManager.default.removeItem(at: staged.deletingLastPathComponent())
        }
    }

    func cancel() {
        task?.cancel()
        task = nil
        if let workingRoot {
            try? FileManager.default.removeItem(at: workingRoot)
            self.workingRoot = nil
        }
        if isRunning { phase = .cancelled }
    }

    func reset() {
        cancel()
        report = nil
        log = []
        progressFraction = 0
        phase = .idle
    }
}

/// Small locked counter so progress from the analyzer thread is ordered.
private final class ProgressCounter: @unchecked Sendable {
    private let lock = NSLock()
    private var value = 0
    private let total: Int
    init(total: Int) { self.total = total }
    func increment() -> Int {
        lock.lock(); defer { lock.unlock() }
        value += 1
        return min(value, total)
    }
}

/// Carries the analyzer's working directory back to the main actor for cleanup.
private final class RootBox: @unchecked Sendable {
    private let lock = NSLock()
    private var stored: URL?
    var value: URL? {
        get { lock.lock(); defer { lock.unlock() }; return stored }
        set { lock.lock(); defer { lock.unlock() }; stored = newValue }
    }
}
