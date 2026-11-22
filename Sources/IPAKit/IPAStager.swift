import Foundation

/// Moves an imported IPA into the analyzer's own working area.
///
/// Everything here is streaming and off the UI thread: the security-scoped
/// copy reads fixed-size chunks and writes them straight out, so even a 1 GB
/// IPA never doubles in memory and the interface keeps responding. Storage is
/// checked up front with an honest estimate of what the analysis will need,
/// and failures name the fix instead of showing a bare error.
enum IPAStager {

    enum StagingError: LocalizedError {
        case notEnoughStorage(needed: Int64, available: Int64)
        case sourceUnreadable(underlying: String)

        var errorDescription: String? {
            switch self {
            case .notEnoughStorage(let needed, let available):
                return "Not enough free storage for this IPA. About "
                    + ByteCountFormatter.string(fromByteCount: needed, countStyle: .file)
                    + " is needed for the working copy and the extracted bundle, but only "
                    + ByteCountFormatter.string(fromByteCount: available, countStyle: .file)
                    + " is free. Remove some files (or pick a smaller IPA) and try again."
            case .sourceUnreadable(let underlying):
                return "Could not read the selected file: \(underlying). If it lives in iCloud Drive, this usually means the download could not complete — try again, or make sure the file is stored on this iPhone."
            }
        }
    }

    /// Planning estimate for one import: the staged copy, the uncompressed
    /// bundle (capped at the analyzer's extraction policy) and a margin for
    /// the archive's own metadata. Conservative, never optimistic.
    static func requiredCapacity(compressedSize: Int64,
                                 maxTotalUncompressed: Int64 = 4 * 1024 * 1024 * 1024) -> Int64 {
        let expansion = min(max(compressedSize, compressedSize * 2), maxTotalUncompressed)
        return compressedSize + expansion + (256 * 1024 * 1024)
    }

    /// Free space at the volume that will hold the working files. Returns nil
    /// when the platform cannot tell us (e.g. Linux) — the caller proceeds
    /// rather than blocking an analysis that would have worked.
    static func availableCapacity(near url: URL) -> Int64? {
        #if os(iOS) || os(macOS)
        let values = try? url.resourceValues(forKeys: [.volumeAvailableCapacityForImportantUsageKey])
        if let v = values?.volumeAvailableCapacityForImportantUsage, v > 0 { return v }
        let legacy = try? url.resourceValues(forKeys: [.volumeAvailableCapacityKey])
        if let v = legacy?.volumeAvailableCapacity, v > 0 { return Int64(v) }
        return nil
        #else
        return nil
        #endif
    }

    /// The storage guard itself, split from the volume query so tests can
    /// drive it with exact numbers.
    static func guardStorage(compressedSize: Int64, available: Int64?) throws {
        guard let available else { return }
        let required = requiredCapacity(compressedSize: compressedSize)
        guard available >= required else {
            throw StagingError.notEnoughStorage(needed: required, available: available)
        }
    }

    /// Checks free space at `url`'s volume against the IPA's compressed size.
    static func guardStorage(compressedSize: Int64, near url: URL) throws {
        try guardStorage(compressedSize: compressedSize, available: availableCapacity(near: url))
    }

    /// Copies the IPA into the analyzer's staging area.
    ///
    /// The security scope is held for the whole operation. The copy is
    /// chunked, reports progress, honours cancellation, and removes its own
    /// partial output on failure. Returns the staged file URL; the caller is
    /// responsible for removing the parent directory when done.
    static func stage(ipaURL: URL,
                      isCancelled: @escaping @Sendable () -> Bool,
                      onProgress: @escaping @Sendable (_ copied: Int64, _ total: Int64) -> Void,
                      onMessage: @escaping @Sendable (String) -> Void = { _ in }) async throws -> URL {
        try await withCheckedThrowingContinuation { continuation in
            DispatchQueue.global(qos: .userInitiated).async {
                // Security scope is a Darwin concept; Linux tests exercise the
                // same copy logic without it.
                #if os(iOS) || os(macOS)
                let accessed = ipaURL.startAccessingSecurityScopedResource()
                defer { if accessed { ipaURL.stopAccessingSecurityScopedResource() } }
                #endif
                do {
                    // A file picked straight out of iCloud Drive can be a
                    // placeholder with no bytes on disk. Make sure it is
                    // materialised before opening it, with live progress.
                    try IPAStager.ensureDownloaded(ipaURL,
                                                   isCancelled: isCancelled,
                                                   onFraction: { fraction in
                                                       onMessage("Downloading from iCloud… \(Int(fraction * 100))%")
                                                   })

                    let attributes = try FileManager.default.attributesOfItem(atPath: ipaURL.path)
                    guard let compressedSize = (attributes[.size] as? NSNumber)?.int64Value, compressedSize > 0 else {
                        throw StagingError.sourceUnreadable(underlying: "the file has no readable size")
                    }

                    try guardStorage(compressedSize: compressedSize, near: FileManager.default.temporaryDirectory)

                    let stagingRoot = FileManager.default.temporaryDirectory
                        .appendingPathComponent("IPAInspector-input-\(UUID().uuidString)", isDirectory: true)
                    let staged = stagingRoot.appendingPathComponent(ipaURL.lastPathComponent)
                    try FileManager.default.createDirectory(at: stagingRoot, withIntermediateDirectories: true)

                    do {
                        try copyStreaming(from: ipaURL,
                                          to: staged,
                                          isCancelled: isCancelled,
                                          progress: onProgress)
                    } catch {
                        try? FileManager.default.removeItem(at: stagingRoot)
                        throw error
                    }
                    continuation.resume(returning: staged)
                } catch {
                    continuation.resume(throwing: error)
                }
            }
        }
    }

    // MARK: iCloud materialisation (Darwin only)
    //
    // iOS does not expose the per-item download-percent resource keys (they
    // are macOS-only and deprecated on iOS in favour of NSMetadataQuery), so
    // materialisation uses the documented NSFileCoordinator path instead:
    // coordinating a read with `.forUploading` makes the file provider fetch
    // the bytes and hands the accessor a URL that can actually be read.

    #if os(iOS) || os(macOS)
    /// True when the file already has readable bytes on disk (a quick probe
    /// read of the first bytes). A dataless iCloud placeholder fails this.
    static func hasLocalBytes(_ url: URL) -> Bool {
        guard let handle = try? FileHandle(forReadingFrom: url) else { return false }
        defer { try? handle.close() }
        guard let head = try? handle.read(upToCount: 8) else { return false }
        return !head.isEmpty
    }

    /// Makes sure a picked iCloud Drive file has real bytes on disk before the
    /// copy starts. The coordinator blocks until the provider finishes the
    /// download; progress is reported as 0 → 1 because iOS gives no percent
    /// for a one-shot coordinated read.
    static func ensureDownloaded(_ url: URL,
                                 isCancelled: () -> Bool,
                                 onFraction: (Double) -> Void = { _ in }) throws {
        if hasLocalBytes(url) { return } // local file: nothing to wait for
        if isCancelled() { throw CancellationError() }

        onFraction(0)
        try? FileManager.default.startDownloadingUbiquitousItem(at: url)

        var coordinatorError: NSError?
        var readError: Error?
        let coordinator = NSFileCoordinator(filePresenter: nil)
        coordinator.coordinate(readingItemAt: url,
                               options: [.forUploading],
                               error: &coordinatorError) { coordinatedURL in
            do {
                let handle = try FileHandle(forReadingFrom: coordinatedURL)
                _ = try handle.read(upToCount: 8)
                try? handle.close()
            } catch {
                readError = error
            }
        }
        if let readError {
            throw StagingError.sourceUnreadable(underlying: readError.localizedDescription)
        }
        if let coordinatorError {
            throw StagingError.sourceUnreadable(underlying: coordinatorError.localizedDescription)
        }
        if isCancelled() { throw CancellationError() }
        onFraction(1)
    }
    #else
    /// Linux builds have no iCloud: every file is already "downloaded".
    static func ensureDownloaded(_ url: URL,
                                 isCancelled: () -> Bool,
                                 onFraction: (Double) -> Void = { _ in }) throws {
        _ = url; _ = isCancelled; _ = onFraction
    }
    #endif

    /// Chunked copy with progress. Never loads more than one chunk into
    /// memory, whatever the file size.
    static func copyStreaming(from source: URL,
                              to destination: URL,
                              chunkSize: Int = 4 * 1024 * 1024,
                              isCancelled: @escaping @Sendable () -> Bool = { false },
                              progress: @escaping @Sendable (_ copied: Int64, _ total: Int64) -> Void = { _, _ in }) throws {
        let inHandle: FileHandle
        do { inHandle = try FileHandle(forReadingFrom: source) }
        catch { throw StagingError.sourceUnreadable(underlying: error.localizedDescription) }
        defer { try? inHandle.close() }

        let total = Int64((try? inHandle.seekToEnd()) ?? 0)
        try? inHandle.seek(toOffset: 0)

        FileManager.default.createFile(atPath: destination.path, contents: nil, attributes: nil)
        let out = try FileHandle(forWritingTo: destination)
        var copied: Int64 = 0
        do {
            while true {
                if isCancelled() { throw CancellationError() }
                guard let chunk = try inHandle.read(upToCount: chunkSize), !chunk.isEmpty else { break }
                try out.write(contentsOf: chunk)
                copied += Int64(chunk.count)
                if total > 0 { progress(copied, total) }
            }
        } catch {
            try? out.close()
            try? FileManager.default.removeItem(at: destination)
            throw error
        }
        try? out.close()
        progress(copied, copied)
    }
}
