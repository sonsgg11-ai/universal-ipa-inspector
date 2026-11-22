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
        var fields: [(String, String)] = [
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
            ("fileSizeBytes", "Download size"),
            ("releaseNotes", "Release notes"),
            ("sellerUrl", "Developer website"),
            ("privacyPolicyUrl", "Privacy policy"),
            ("trackViewUrl", "Store page"),
            ("artistId", "Developer (artist) ID"),
            ("userRatingCountForCurrentVersion", "Rating count (current version)"),
        ]
        for (key, title) in fields {
            if let value = app[key] {
                report.findings.append(Finding(
                    category: "App Store", title: title,
                    value: AppStoreClient.humanisedValue(key, value),
                    source: source, status: .verified))
            }
        }
        if let languages = app["languageCodesISO2A"] as? [String] {
            report.findings.append(Finding(
                category: "App Store", title: "Languages",
                value: languages.joined(separator: ", "), source: source, status: .verified))
        }
        if let genres = app["genres"] as? [String], !genres.isEmpty {
            report.findings.append(Finding(
                category: "App Store", title: "Genres",
                value: genres.joined(separator: ", "), source: source, status: .verified))
        }
        if let devices = app["supportedDevices"] as? [String] {
            report.findings.append(Finding(
                category: "App Store", title: "Supported devices",
                value: "\(devices.count) models", source: source, status: .verified))
        }
        if let description = app["description"] as? String {
            let trimmed = description.trimmingCharacters(in: .whitespacesAndNewlines)
            let shortened = trimmed.count > 800 ? String(trimmed.prefix(800)) + "…" : trimmed
            report.findings.append(Finding(
                category: "App Store", title: "Store description",
                value: shortened, source: source, status: .verified))
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

    /// Formats listing values for humans: byte counts become MB/GB, numbers
    /// lose their fractional noise, everything else passes through unchanged.
    static func humanisedValue(_ key: String, _ value: Any) -> String {
        if key == "fileSizeBytes" {
            let bytes: Int64?
            if let n = value as? Int { bytes = Int64(n) }
            else if let n = value as? Double { bytes = Int64(n) }
            else { bytes = (value as? NSString)?.longLongValue }
            if let bytes { return ByteCountFormatter.string(fromByteCount: bytes, countStyle: .file) }
        }
        if let number = value as? Int { return String(number) }
        if let number = value as? Double {
            if number == number.rounded() && abs(number) < 1e15 { return String(Int(number)) }
            return String(format: "%g", number)
        }
        return NativePlist.describe(value)
    }

    enum StoreError: LocalizedError {
        case badLink
        case noResult(id: String, country: String)

        var errorDescription: String? {
            switch self {
            case .badLink:
                return "Could not find an App Store ID in that link."
            case .noResult(let id, let country):
                return "No app found for ID \(id) in storefront \(country.uppercased()). Some apps are not listed in every storefront — try switching the storefront picker (for example to the developer's home country), or paste the full App Store link including the id number."
            }
        }
    }
}
