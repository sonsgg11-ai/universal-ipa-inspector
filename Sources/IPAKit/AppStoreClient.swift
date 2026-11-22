import Foundation
#if canImport(FoundationNetworking)
import FoundationNetworking
#endif

/// Reads public App Store listing metadata through Apple's iTunes Lookup API.
///
/// This is metadata only. Nothing in the lookup response contains the binary;
/// an IPA is never downloaded from a store link and this client never tries.
enum AppStoreClient {

    /// Storefronts offered in the UI. The lookup endpoint accepts any ISO
    /// two-letter country code; these are the common ones.
    static let knownStorefronts = [
        "au", "br", "ca", "cn", "de", "es", "fr", "gb", "in", "it",
        "jp", "kr", "mx", "nl", "ru", "se", "tr", "us", "za",
    ]

    /// Extracts an app ID from a bare numeric ID or a store URL.
    /// Returns the ID and the country inferred from the URL, if any.
    static func parse(_ input: String) -> (id: String, country: String)? {
        let trimmed = input.trimmingCharacters(in: .whitespaces)
        if !trimmed.isEmpty, trimmed.count >= 6, trimmed.allSatisfy(\.isNumber) {
            return (trimmed, "us")
        }
        guard let regex = try? NSRegularExpression(pattern: #"id(\d{6,})"#),
              let match = regex.firstMatch(
                in: trimmed,
                range: NSRange(location: 0, length: (trimmed as NSString).length))
        else { return nil }

        let id = (trimmed as NSString).substring(with: match.range(at: 1))
        var country = "us"
        if let url = URL(string: trimmed), url.pathComponents.count > 1,
           url.pathComponents[1].count == 2 {
            country = url.pathComponents[1].lowercased()
        }
        return (id, country)
    }

    /// Performs the lookup and turns the listing into a report. Fields the
    /// store does not publish are listed as blocked, with the reason stated.
    static func lookup(input: String, storefront: String = "us") async throws -> Report {
        guard let (id, _) = parse(input) else {
            throw NSError(
                domain: "AppStore", code: 1,
                userInfo: [NSLocalizedDescriptionKey:
                    "Could not find an App Store ID in that link. Paste a link containing id123456789 or a bare numeric ID."])
        }

        let country = storefront.lowercased()
        guard let url = URL(string: "https://itunes.apple.com/lookup?id=\(id)&country=\(country)&entity=software") else {
            throw NSError(
                domain: "AppStore", code: 3,
                userInfo: [NSLocalizedDescriptionKey: "Could not build the lookup URL for ID \(id)."])
        }

        let (data, response) = try await URLSession.shared.data(from: url)
        guard (response as? HTTPURLResponse)?.statusCode == 200,
              let json = try JSONSerialization.jsonObject(with: data) as? [String: Any],
              let app = (json["results"] as? [[String: Any]])?.first
        else {
            throw NSError(
                domain: "AppStore", code: 2,
                userInfo: [NSLocalizedDescriptionKey:
                    "No app found for ID \(id) in storefront \(country.uppercased())."])
        }

        let source = "iTunes Lookup API (\(country.uppercased()))"
        var report = Report(source: "App Store", name: app["trackName"] as? String ?? id)
        report.findings.append(Finding(
            category: "App Store", title: "App Store ID", value: id, source: source, status: .verified))

        let fields: [(String, String)] = [
            ("bundleId", "Bundle ID"),
            ("trackName", "Name"),
            ("artistName", "Developer"),
            ("sellerName", "Seller"),
            ("version", "Version"),
            ("currentVersionReleaseDate", "Current version released"),
            ("releaseDate", "First released"),
            ("minimumOsVersion", "Minimum iOS"),
            ("primaryGenreName", "Category"),
            ("averageUserRating", "Average rating"),
            ("userRatingCount", "Rating count"),
            ("formattedPrice", "Price"),
            ("contentAdvisoryRating", "Age rating"),
            ("fileSizeBytes", "Download size (bytes)"),
            ("releaseNotes", "Release notes"),
        ]
        for (key, title) in fields {
            if let value = app[key] {
                report.findings.append(Finding(
                    category: "App Store", title: title,
                    value: NativePlist.describe(value), source: source, status: .verified))
            }
        }
        if let languages = app["languageCodesISO2A"] as? [String] {
            report.findings.append(Finding(
                category: "App Store", title: "Languages",
                value: languages.joined(separator: ", "), source: source, status: .verified))
        }
        if let devices = app["supportedDevices"] as? [String] {
            report.findings.append(Finding(
                category: "App Store", title: "Supported devices",
                value: "\(devices.count) models", source: source, status: .verified))
        }
        if let url_display = app["trackViewUrl"] as? String {
            report.findings.append(Finding(
                category: "App Store", title: "Store URL",
                value: url_display, source: source, status: .verified))
        }

        // Be explicit about what a store link cannot provide.
        for (title, why) in [
            ("Binary / Mach-O analysis", "The store distributes an encrypted download that is only decryptable on a licensed device."),
            ("Frameworks & SDKs", "The bundle layout is not part of the listing data."),
            ("Entitlements", "Entitlements live in the code signature of the binary."),
            ("Embedded URLs & endpoints", "Endpoints are strings inside the bundle, not listing fields."),
            ("Resources & assets", "Resources are inside the bundle, not the listing."),
        ] {
            report.findings.append(Finding(
                category: "Requires IPA", title: title,
                value: "Not obtainable from a store link. Import an IPA you are authorised to analyse.",
                source: "—", status: .blocked, note: why))
        }
        return report
    }
}
