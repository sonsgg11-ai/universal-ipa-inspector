import Foundation
import SwiftUI

/// Owns the lifecycle of one analysis run and is the only thing the UI
/// observes. All mutation happens on the main actor; the engine runs its own
/// task and reports progress through its callback.
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
    @Published private(set) var outcome: AnalysisEngine.Outcome?
    /// The store-listing report (App Store lookups), kept separate from IPA outcomes.
    @Published private(set) var storeReport: Report?
    @Published private(set) var progressFraction: Double = 0
    @Published private(set) var progressStage: String = ""
    @Published private(set) var log: [String] = []
    @Published var storefront: String = "us"

    private var engine: AnalysisEngine?
    private var task: Task<Void, Never>?
    private var workingRoot: URL?
    /// The staged working copy of the imported IPA; removed when the run ends.
    private var stagedInput: URL?

    var isRunning: Bool {
        if case .running = phase { return true }
        return false
    }

    /// The report the summary screens show: an IPA outcome when present,
    /// otherwise a store listing.
    var activeReport: Report? {
        outcome?.report ?? storeReport
    }

    // MARK: App Store lookup (kept from the original app)

    func lookup(_ input: String) {
        guard !isRunning else { return }
        cancel()
        outcome = nil
        storeReport = nil
        progressFraction = 0
        log = ["Looking up \(input)"]
        phase = .running("Contacting the App Store…")

        let requested = storefront
        task = Task { [weak self] in
            do {
                let result = try await AppStoreClient.lookup(input: input, storefront: requested)
                guard !Task.isCancelled else { return }
                self?.storeReport = result
                self?.log.append("Received listing data for \(result.name).")
                self?.progressFraction = 1
                self?.phase = .finished
            } catch {
                guard !Task.isCancelled else { return }
                self?.phase = .failed(error.localizedDescription)
                self?.log.append("Lookup failed: \(error.localizedDescription)")
            }
        }
    }

    // MARK: IPA analysis (requirement P pipeline)

    func analyse(ipaURL: URL) {
        guard !isRunning else { return }
        cancel()
        outcome = nil
        storeReport = nil
        progressFraction = 0

        let name = ipaURL.lastPathComponent
        log = ["Importing \(name)"]
        phase = .running("Preparing…")

        let newEngine = AnalysisEngine()
        engine = newEngine
        newEngine.onProgress = { [weak self] state in
            Task { @MainActor [weak self] in
                self?.progressFraction = state.fraction
                self?.progressStage = state.message
                self?.log.append(state.message)
            }
        }

        task = Task { [weak self] in
            do {
                // Staging runs off the main actor: the IPA is copied in fixed
                // chunks with live progress, so a 1 GB import never freezes
                // the interface and never doubles in memory. Storage is
                // checked up front and the failure names the fix.
                let staged = try await IPAStager.stage(
                    ipaURL: ipaURL,
                    isCancelled: { newEngine.isCancelled },
                    onProgress: { copied, total in
                        let fraction = total > 0 ? Double(copied) / Double(total) : 0
                        Task { @MainActor [weak self] in
                            self?.progressFraction = fraction * 0.12
                            self?.progressStage = "Copying \(name)… \(Int(fraction * 100))%"
                        }
                    })
                guard !Task.isCancelled, !newEngine.isCancelled else { throw CancellationError() }
                self?.stagedInput = staged
                let stagedSize = (try? FileManager.default.attributesOfItem(atPath: staged.path)[.size] as? Int64) ?? 0
                self?.log.append("Staged a working copy (\(ByteFormat.string(stagedSize))).")
                self?.progressStage = "Analysing…"

                let result = try await newEngine.run(ipaURL: staged)
                guard !Task.isCancelled else { return }
                self?.workingRoot = result.extractionRoot
                self?.outcome = result
                self?.progressFraction = 1
                self?.log.append("Analysis complete: \(result.report.findings.count) findings, \(result.report.fileCount) files.")
                self?.phase = .finished
                self?.discardStagedInput()
            } catch is CancellationError {
                self?.log.append("Cancelled. Temporary files were removed.")
                self?.phase = .cancelled
                self?.discardStagedInput()
            } catch {
                self?.log.append("Analysis failed: \(error.localizedDescription)")
                self?.phase = .failed(error.localizedDescription)
                self?.discardStagedInput()
            }
        }
    }

    func cancel() {
        task?.cancel()
        task = nil
        engine?.cancel()
        engine = nil
        if let workingRoot {
            try? FileManager.default.removeItem(at: workingRoot)
            self.workingRoot = nil
        }
        discardStagedInput()
        if isRunning { phase = .cancelled }
    }

    /// Removes the staged working copy of the IPA. Safe to call repeatedly.
    private func discardStagedInput() {
        if let stagedInput {
            try? FileManager.default.removeItem(at: stagedInput.deletingLastPathComponent())
            self.stagedInput = nil
        }
    }

    func reset() {
        cancel()
        outcome = nil
        storeReport = nil
        log = []
        progressFraction = 0
        phase = .idle
    }

    // MARK: Export helpers (requirement V)

    /// Builds the complete-analysis ZIP and returns its URL for the share sheet.
    func buildExportPackage() throws -> URL {
        guard let outcome else { throw ExportError.noOutcome }
        return try ExportPackager.buildPackage(outcome: outcome)
    }

    enum ExportError: LocalizedError {
        case noOutcome
        var errorDescription: String? {
            switch self {
            case .noOutcome: return "There is no completed analysis to export."
            }
        }
    }
}
