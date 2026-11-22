import Foundation

/// A fingerprint for one known third-party SDK.
struct SDKSignature: Sendable {
    let name: String
    let category: String
    /// Lowercase substrings matched against bundle paths, framework names and
    /// linked library paths.
    let patterns: [String]
    let notes: String
    /// Whether this SDK is known to collect analytics/tracking data.
    let tracksUsers: Bool
}

/// Database of SDK fingerprints used by the supply-chain inventory.
///
/// The database is a local snapshot. It says a library is present; it never
/// claims the library runs, and it carries no version or vulnerability data
/// unless the bundle itself provides the version.
enum SDKDatabase {

    static let all: [SDKSignature] = [
        .init(name: "Unity", category: "Game engine", patterns: ["unityframework.framework", "/data/managed/", "global-metadata.dat"],
              notes: "Unity engine runtime detected.", tracksUsers: false),
        .init(name: "Unreal Engine", category: "Game engine", patterns: [".pak", "/cookeddata/", "ue4commandline", "uecommandline"],
              notes: "Unreal Engine runtime detected.", tracksUsers: false),
        .init(name: "Cocos2d-x", category: "Game engine", patterns: ["cocos2d", "libcocos"],
              notes: "Cocos2d-x engine detected.", tracksUsers: false),
        .init(name: "Godot", category: "Game engine", patterns: [".pck", "godot"],
              notes: "Godot engine detected.", tracksUsers: false),
        .init(name: "SpriteKit", category: "Apple framework", patterns: ["spritekit.framework"],
              notes: "Apple 2D graphics framework.", tracksUsers: false),
        .init(name: "SceneKit", category: "Apple framework", patterns: ["scenekit.framework", ".scn"],
              notes: "Apple 3D graphics framework.", tracksUsers: false),
        .init(name: "Flutter", category: "Cross-platform", patterns: ["flutter.framework", "app.framework/flutter_assets"],
              notes: "Flutter cross-platform runtime.", tracksUsers: false),
        .init(name: "React Native", category: "Cross-platform", patterns: ["main.jsbundle", "react.framework", "hermes.framework"],
              notes: "React Native cross-platform runtime.", tracksUsers: false),
        .init(name: "Firebase", category: "Backend/Analytics", patterns: ["googleservice-info.plist", "firebasecore"],
              notes: "Firebase configuration and core are present. Firebase components commonly collect analytics data; check the privacy manifest for what is declared.", tracksUsers: true),
        .init(name: "Firebase Analytics", category: "Analytics", patterns: ["firebaseanalytics", "firebaseinstanceid", "firebasemessaging"],
              notes: "Firebase analytics/messaging components detected.", tracksUsers: true),
        .init(name: "Firebase Crashlytics", category: "Crash reporting", patterns: ["firebasecrashlytics"],
              notes: "Crashlytics collects device and crash data.", tracksUsers: true),
        .init(name: "Sentry", category: "Crash reporting", patterns: ["sentry.framework", "sentrycrash"],
              notes: "Sentry crash reporting detected.", tracksUsers: false),
        .init(name: "Bugsnag", category: "Crash reporting", patterns: ["bugsnag"],
              notes: "Bugsnag crash reporting detected.", tracksUsers: false),
        .init(name: "Facebook SDK", category: "Analytics/Auth", patterns: ["fbsdkcorekit", "fbaemkit", "fbsdksharekit"],
              notes: "Meta SDK detected. It is commonly used for login and attribution and is known to collect data for advertising; check the privacy manifest.", tracksUsers: true),
        .init(name: "AppsFlyer", category: "Attribution", patterns: ["appsflyerlib"],
              notes: "AppsFlyer is a mobile attribution provider.", tracksUsers: true),
        .init(name: "Adjust", category: "Attribution", patterns: ["adjustsdk", "adjust.framework"],
              notes: "Adjust is a mobile attribution provider.", tracksUsers: true),
        .init(name: "Branch", category: "Attribution", patterns: ["branch.framework", "branchio"],
              notes: "Branch deep-link attribution detected.", tracksUsers: true),
        .init(name: "Google Mobile Ads", category: "Advertising", patterns: ["googlemobileads"],
              notes: "Google Mobile Ads SDK (AdMob) detected.", tracksUsers: true),
        .init(name: "AppLovin", category: "Advertising", patterns: ["applovinsdk"],
              notes: "AppLovin advertising SDK detected.", tracksUsers: true),
        .init(name: "IronSource", category: "Advertising", patterns: ["ironsource"],
              notes: "ironSource advertising SDK detected.", tracksUsers: true),
        .init(name: "Unity Ads", category: "Advertising", patterns: ["unityads.framework"],
              notes: "Unity Ads detected.", tracksUsers: true),
        .init(name: "RevenueCat", category: "Payments", patterns: ["revenuecat"],
              notes: "RevenueCat subscription infrastructure detected.", tracksUsers: false),
        .init(name: "Stripe", category: "Payments", patterns: ["stripe"],
              notes: "Stripe SDK detected. Short pattern: may match unrelated strings.", tracksUsers: false),
        .init(name: "Google Sign-In", category: "Auth", patterns: ["googlesignin"],
              notes: "Google Sign-In detected.", tracksUsers: false),
        .init(name: "Sign in with Apple", category: "Auth", patterns: ["authenticationservices.framework"],
              notes: "AuthenticationServices linked (Apple sign-in/credential provider).", tracksUsers: false),
        .init(name: "Alamofire", category: "Networking", patterns: ["alamofire"],
              notes: "Alamofire HTTP library detected.", tracksUsers: false),
        .init(name: "Realm", category: "Database", patterns: ["realm.framework", "realmswift"],
              notes: "Realm local database detected.", tracksUsers: false),
        .init(name: "OneSignal", category: "Push", patterns: ["onesignal"],
              notes: "OneSignal push/analytics detected.", tracksUsers: true),
        .init(name: "Amplitude", category: "Analytics", patterns: ["amplitude"],
              notes: "Amplitude product analytics detected.", tracksUsers: true),
        .init(name: "Mixpanel", category: "Analytics", patterns: ["mixpanel"],
              notes: "Mixpanel product analytics detected.", tracksUsers: true),
        .init(name: "Segment", category: "Analytics", patterns: ["segment.framework", "analytics-swift"],
              notes: "Segment analytics pipeline detected.", tracksUsers: true),
        .init(name: "Braze", category: "Analytics", patterns: ["braze", "appboy"],
              notes: "Braze engagement platform detected.", tracksUsers: true),
        .init(name: "CleverTap", category: "Analytics", patterns: ["clevertap"],
              notes: "CleverTap engagement platform detected.", tracksUsers: true),
        .init(name: "Kochava", category: "Attribution", patterns: ["kochava"],
              notes: "Kochava attribution detected.", tracksUsers: true),
        .init(name: "Tencent/WeChat SDK", category: "Social", patterns: ["wechatopensdk"],
              notes: "WeChat SDK detected.", tracksUsers: false),
        .init(name: "Twitter/X SDK", category: "Social", patterns: ["twitterkit", "twittercore"],
              notes: "X (Twitter) SDK detected.", tracksUsers: false),
        .init(name: "Line SDK", category: "Social", patterns: ["linesdk"],
              notes: "LINE SDK detected.", tracksUsers: false),
    ]

    /// A fingerprint is "weak" when its patterns are short and common, which
    /// risks matching unrelated strings. Weak matches are reported with
    /// estimated evidence status.
    static func isWeakFingerprint(_ signature: SDKSignature) -> Bool {
        let short = signature.patterns.filter { $0.count <= 8 }
        return !short.isEmpty && Double(short.count) / Double(signature.patterns.count) > 0.5
    }
}
