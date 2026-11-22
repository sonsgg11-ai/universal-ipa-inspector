import Foundation
#if canImport(FoundationNetworking)
import FoundationNetworking
#endif

/// Talks to the public iTunes Lookup API.
///
/// This is the only network surface in the whole app, and it only ever
/// fetches public store listings. IPA bytes and analysis results are never
/// transmitted anywhere.
enum AppStoreClient {

    static let knownStorefronts: Set<String> = [
        "us", "gb", "de", "fr", "it", "es", "nl", "se", "pl", "jp", "kr", "cn",
        "in", "au", "ca", "br", "mx", "ru", "tr", "ae", "sa", "za", "ng", "hk",
        "tw", "th", "sg", "id", "vn", "ph", "my", "ar", "cl", "co", "dk", "fi",
        "no", "ie", "at", "ch", "be", "pt", "gr", "cz", "hu", "ro", "il",
    ]

    /// Accepts "123456789", a full store URL, or a URL containing `id…`.
    static func parse(_ input: String) -> (id: String, country: String)? {
        let s = input.trimmingCharacters(in: .whitespaces)
        if s.allSatisfy(\.isNumber), s.count >= 6 { return (s, "us") }
        guard let regex = try? NSRegularExpression(pattern: #"id(\d{6,})"#),
              let match = regex.firstMatch(in: s,
                                          range: NSRange(location: 0, length: (s as NSString).length))
        else { return nil }
        let id = (s as NSString).substring(with: match.range(at: 1))
        var country = "us"
        if let url = URL(string: s), url.pathComponents.count > 1, url.pathComponents[1].count == 2 {
            country = url.pathComponents[1].lowercased()
        }
        return (id, country)
    }

    /// Fetches public listing metadata. Returns a Report with verified store
    /// fields and explicit "blocked" entries for everything that requires an
    /// IPA, so the distinction is visible in the UI.
    static func lookup(input: String, storefront: String = "us") async throws -> Report {
        guard let (id, country) = parse(input) else {
            throw StoreError.badLink
        }
        var components = URLComponents(string: "https://itunes.apple.com/lookup")!
        components.queryItems = [
            URLQueryItem(name: "id", value: id),
            URLQueryItem(name: "country", value: country),
            URLQueryItem(name: "entity", value: "software"),
        ]
        guard let url = components.url else { throw StoreError.badLink }

        let (data, response) = try await URLSession.shared.data(from: url)
        guard (response as? HTTPURLResponse)?.statusCode == 200,
              let json = try JSONSerialization.jsonObject(with: data) as? [String: Any],
              let app = (json["results"] as? [[String: Any]])?.first
        else {
            throw StoreError.noResult(id: id, country: country)
        }

        let source = "iTunes Lookup API (\(country.uppercased()))"
        var report = Report(source: "App Store", name: app["trackName"] as? String ?? id)
        let fields: [(String, String)] = [
            ("trackName", "Name"),
            ("bundleId", "Bundle ID"),
            ("trackId", "App Store ID"),
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
        for title in ["Binary / Mach-O analysis", "Frameworks & SDKs", "Entitlements",
                      "Embedded URLs & endpoints", "Resources & assets"] {
            report.findings.append(Finding(
                category: "Requires IPA", title: title,
                value: "Not obtainable from a store link. Import an IPA you are authorised to analyse.",
                source: "—", status: .blocked))
        }
        return report
    }

    enum StoreError: LocalizedError {
        case badLink
        case noResult(id: String, country: String)

        var errorDescription: String? {
            switch self {
            case .badLink:
                return "Could not find an App Store ID in that link."
            case .noResult(let id, let country):
                return "No app found for ID \(id) in storefront \(country.uppercased())."
            }
        }
    }
}
