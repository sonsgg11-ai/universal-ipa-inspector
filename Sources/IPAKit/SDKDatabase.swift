import Foundation

/// One SDK fingerprint: a name, a reporting category, and lowercase substring
/// patterns matched against bundle paths and linked-library names.
struct SDKSignature {
    let name: String
    let category: String
    let patterns: [String]
    /// What a match does and does not mean, shown to the reader.
    let notes: String
}

/// Known third-party fingerprints. Presence of a library in the bundle is a
/// fact about the bundle, not about what the app does with it — every note
/// says so, because over-claiming here is the classic analyzer mistake.
enum SDKDatabase {

    /// Fingerprints whose patterns are short enough to collide with unrelated
    /// symbols or generic words. They are reported as `estimated` evidence.
    static func isWeakFingerprint(_ signature: SDKSignature) -> Bool {
        signature.patterns.contains { $0.count < 6 }
    }

    static let all: [SDKSignature] = [
        .init(name: "Unity", category: "Game engine",
              patterns: ["unityframework.framework", "/data/managed/", "global-metadata.dat"],
              notes: "Unity embeds managed data and a native runtime; their presence shows an Unity build but not which engine features are used."),
        .init(name: "Unreal Engine", category: "Game engine",
              patterns: [".pak", "/cookeddata/", "ue4commandline", "uecommandline"],
              notes: "Unreal ships cooked content in .pak archives; loose assets outside .pak files are not detected."),
        .init(name: "Cocos2d-x", category: "Game engine",
              patterns: ["cocos2d", "libcocos"],
              notes: "Cocos2d-x is often statically linked, so symbol-level checks would be needed for certainty."),
        .init(name: "Godot", category: "Game engine",
              patterns: [".pck", "godot"],
              notes: "The short 'godot' pattern can appear in unrelated words; treat a lone match with care."),
        .init(name: "SpriteKit", category: "Game engine",
              patterns: ["spritekit.framework"],
              notes: "A system framework; linking does not mean the app renders with it."),
        .init(name: "SceneKit", category: "Game engine",
              patterns: ["scenekit.framework", ".scn"],
              notes: "A system framework; .scn assets indicate 3D content authored for SceneKit."),
        .init(name: "Flutter", category: "Cross-platform",
              patterns: ["flutter.framework", "app.framework/flutter_assets"],
              notes: "Dart code is compiled to native instructions plus an assets blob; no interpreter is present."),
        .init(name: "React Native", category: "Cross-platform",
              patterns: ["main.jsbundle", "react.framework", "hermes.framework"],
              notes: "JavaScript runs in JavaScriptCore or Hermes; business logic may be inspectable in the bundle."),
        .init(name: "Firebase", category: "Backend/Analytics",
              patterns: ["googleservice-info.plist", "firebasecore", "firebaseanalytics"],
              notes: "The plist usually carries project IDs and API keys; the Secrets scan covers the key patterns."),
        .init(name: "Firebase Crashlytics", category: "Crash reporting",
              patterns: ["firebasecrashlytics"],
              notes: "Crash reporters upload device state; the privacy manifest should declare it."),
        .init(name: "Sentry", category: "Crash reporting",
              patterns: ["sentry.framework"],
              notes: "Crash reporters upload device state; the privacy manifest should declare it."),
        .init(name: "Facebook SDK", category: "Analytics/Auth",
              patterns: ["fbsdkcorekit", "fbaemkit"],
              notes: "Meta SDKs collect device and usage data; check the privacy manifest for declarations."),
        .init(name: "AppsFlyer", category: "Attribution",
              patterns: ["appsflyerlib"],
              notes: "Attribution SDKs correlate installs with ad clicks; typically declared in the privacy manifest."),
        .init(name: "Adjust", category: "Attribution",
              patterns: ["adjustsdk", "adjust.framework"],
              notes: "Attribution SDKs correlate installs with ad clicks; typically declared in the privacy manifest."),
        .init(name: "Google Mobile Ads", category: "Advertising",
              patterns: ["googlemobileads"],
              notes: "Ad SDKs bundle many sub-frameworks; only the umbrella is fingerprinted here."),
        .init(name: "AppLovin", category: "Advertising",
              patterns: ["applovinsdk"],
              notes: "Ad mediation SDKs; embedded adapters may not all be fingerprinted."),
        .init(name: "IronSource", category: "Advertising",
              patterns: ["ironsource"],
              notes: "Ad mediation SDKs; embedded adapters may not all be fingerprinted."),
        .init(name: "Unity Ads", category: "Advertising",
              patterns: ["unityads.framework"],
              notes: "Part of the Unity distribution; only meaningful when Unity is also present."),
        .init(name: "RevenueCat", category: "Payments",
              patterns: ["revenuecat"],
              notes: "In-app purchase infrastructure; receipt validation happens server-side."),
        .init(name: "Stripe", category: "Payments",
              patterns: ["stripe"],
              notes: "The short pattern can match unrelated strings like 'stripe' in assets; check the evidence path."),
        .init(name: "Google Sign-In", category: "Auth",
              patterns: ["googlesignin"],
              notes: "OAuth sign-in typically pairs with a client ID in the plist or entitlements."),
        .init(name: "Alamofire", category: "Networking",
              patterns: ["alamofire"],
              notes: "A Swift HTTP library; its presence says nothing about which endpoints are used."),
        .init(name: "Realm", category: "Database",
              patterns: ["realm.framework", "realmswift"],
              notes: "Local database files may sit in the app container, not the bundle."),
        .init(name: "OneSignal", category: "Push",
              patterns: ["onesignal"],
              notes: "Push SDKs tie devices to user identities; the privacy manifest should declare it."),
    ]
}
