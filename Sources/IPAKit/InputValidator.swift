import Foundation

/// Decides whether a picked/opened file is an archive this app can analyse.
///
/// The old guard matched the filename extension only. That failed in the
/// field: files handed over by the share sheet, iCloud re-downloads, or
/// pickers that resolve a different name were rejected with "Choose an .ipa"
/// even when they were perfectly valid ZIP containers. The rule now is:
/// accept by ZIP magic bytes first, fall back to the extension, and never
/// read more than a few bytes to decide.
enum InputValidator {

    enum Verdict: Equatable {
        /// A ZIP container (or an .ipa/.zip by name): start analysis.
        case accepted(String)
        /// Not an archive at all: refuse with a human explanation.
        case rejected(String)
    }

    // The four-byte "local file header" signatures plus the empty-archive
    // end-of-central-directory marker. Anything beginning with one of these
    // is a ZIP that the analyzer can open.
    static let zipSignatures: [Data] = [
        Data([0x50, 0x4B, 0x03, 0x04]), // PK\x03\x04 — normal archive
        Data([0x50, 0x4B, 0x05, 0x06]), // PK\x05\x06 — empty archive
        Data([0x50, 0x4B, 0x07, 0x08]), // PK\x07\x08 — spanned marker
    ]

    static let acceptedExtensions: Set<String> = ["ipa", "zip"]

    /// Reads the first few bytes of `url` and matches them against the ZIP
    /// signatures. Returns nil when the file cannot be opened at all.
    ///
    /// Share-sheet and open-in-place URLs are security scoped: the scope is
    /// taken here, around the read only, so validation never fails merely
    /// because the bytes were not accessible yet.
    static func magicBytes(at url: URL, byteCount: Int = 8) -> Data? {
        guard FileManager.default.fileExists(atPath: url.path) else { return nil }
        #if os(iOS) || os(macOS)
        let accessed = url.startAccessingSecurityScopedResource()
        defer { if accessed { url.stopAccessingSecurityScopedResource() } }
        #endif
        guard let handle = try? FileHandle(forReadingFrom: url) else { return nil }
        defer { try? handle.close() }
        guard let head = try? handle.read(upToCount: byteCount), !head.isEmpty else { return nil }
        return head
    }

    static func looksLikeZip(at url: URL) -> Bool {
        guard let head = magicBytes(at: url) else { return false }
        return zipSignatures.contains { head.prefix($0.count) == $0 }
    }

    /// Full decision for a picked or handed-over file. `displayName` is the
    /// name shown to the user in the refusal message (the URL may carry an
    /// opaque temporary name).
    static func validate(url: URL, displayName: String? = nil) -> Verdict {
        let shown = displayName ?? url.lastPathComponent
        let ext = url.pathExtension.lowercased()

        // 1. Content wins: a real ZIP is analysed whatever it is called.
        if looksLikeZip(at: url) {
            return .accepted(shown)
        }

        // 2. Extension fallback: .ipa/.zip names are accepted even when the
        //    bytes cannot be read right now (e.g. an iCloud file that is not
        //    downloaded yet) — the stager gives the honest download error.
        if acceptedExtensions.contains(ext) {
            return .accepted(shown)
        }

        // 3. Everything else is refused with the reason stated.
        if magicBytes(at: url) == nil {
            return .rejected(
                "“\(shown)” could not be opened. If it lives in iCloud Drive, download it in the Files app first, then import again.")
        }
        return .rejected(
            "“\(shown)” is not an .ipa or .zip archive. Pick the app package you want to analyse.")
    }
}
