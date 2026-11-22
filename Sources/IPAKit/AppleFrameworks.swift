import Foundation

/// Knows which linked libraries are Apple's own, so third-party dependencies
/// can be separated from system frameworks.
enum AppleFrameworks {

    /// Paths that are part of the operating system rather than the app.
    static let systemPrefixes: [String] = [
        "/System/Library/",
        "/System/iOSSupport/System/Library/",
        "/usr/lib/",
        "/usr/libexec/",
        "/Applications/Xcode.app/",
        "@rpath/XCTest.framework",
        "@rpath/libXCTestSwiftSupport.dylib",
    ]

    /// A linker path is "system" when it points into the OS. `@rpath` entries
    /// resolve inside the bundle, so they are treated as app-provided.
    static func isSystemPath(_ path: String) -> Bool {
        let p = path.lowercased()
        return systemPrefixes.contains { p.hasPrefix($0.lowercased()) }
    }

    /// Well-known Apple framework names that apps link directly. Used for
    /// capability hints (e.g. linking LocalAuthentication implies biometrics).
    static let capabilityHints: [String: [String]] = [
        "LocalAuthentication": ["biometric authentication"],
        "CoreBluetooth": ["Bluetooth"],
        "CoreLocation": ["location"],
        "UserNotifications": ["local/remote notifications"],
        "HealthKit": ["health data"],
        "HomeKit": ["HomeKit accessories"],
        "AVFoundation": ["camera/microphone/media"],
        "WebKit": ["embedded web content"],
        "CloudKit": ["iCloud data"],
        "PushKit": ["VoIP push"],
        "CallKit": ["call integration"],
        "StoreKit": ["in-app purchases"],
        "CoreNFC": ["NFC"],
        "EventKit": ["calendar/reminders"],
        "Contacts": ["contacts data"],
        "CoreML": ["on-device machine learning"],
        "Vision": ["computer vision"],
        "NaturalLanguage": ["language processing"],
    ]

    static func capability(forFrameworkName name: String) -> [String] {
        capabilityHints[name] ?? []
    }
}
