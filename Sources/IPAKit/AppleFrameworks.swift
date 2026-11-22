import Foundation

/// Classifies linked-library paths as Apple system code or third-party.
enum AppleFrameworks {

    /// True when the dylib install name points into Apple's system libraries.
    /// Everything else (embedded frameworks, @rpath entries, unknown roots) is
    /// reported as third-party or embedded.
    static func isSystemPath(_ path: String) -> Bool {
        let lowered = path.lowercased()
        if lowered.hasPrefix("/system/library/") { return true }
        if lowered.hasPrefix("/system/") { return true }
        if lowered.hasPrefix("/usr/lib/") { return true }
        if lowered == "/usr/lib/libsystem.b.dylib" { return true }
        return false
    }
}
