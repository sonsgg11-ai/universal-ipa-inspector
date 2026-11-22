import Foundation

/// Scans text for credential-shaped strings.
///
/// Matches are *candidates*, never proof: a pattern hit can be a test key, an
/// example string, or a truncated fragment. Every hit is redacted before it
/// enters the report — the report never contains a complete secret.
struct SecretScanner {

    struct Hit {
        let name: String
        let redacted: String
        let source: String
        let note: String?
    }

    /// (name, pattern, note) — patterns are matched with NSRegularExpression.
    static let patterns: [(name: String, pattern: String, note: String)] = [
        ("Google API key",
         #"AIza[0-9A-Za-z\-]{35}"#,
         "Google API keys are project-scoped. Treat any hit as a candidate: verify the key server-side, then rotate it if it ships in a distributed binary."),
        ("AWS access key ID",
         #"AKIA[0-9A-Z]{16}"#,
         "An AWS access key ID. It is useless without the matching secret, but the pair may be nearby — search the same file for a 40-character secret key."),
        ("Private key block",
         #"-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----"#,
         "A PEM private key in a shipped bundle is almost always a mistake, whichever key it is."),
        ("Stripe live secret key",
         #"sk_live_[0-9A-Za-z]{20,}"#,
         "A live Stripe secret key must never leave the server. A hit here is a serious finding."),
    ]

    /// Returns up to `limit` hits found in `text`, in pattern order.
    static func scan(text: String, source: String, limit: Int = 8) -> [Hit] {
        var hits: [Hit] = []
        let nsText = text as NSString
        let fullRange = NSRange(location: 0, length: nsText.length)

        for (name, pattern, note) in patterns {
            guard hits.count < limit else { break }
            guard let regex = try? NSRegularExpression(pattern: pattern) else { continue }
            regex.enumerateMatches(in: text, range: fullRange) { match, _, stop in
                guard let match else { return }
                let candidate = nsText.substring(with: match.range)
                let redacted = redact(candidate)
                hits.append(Hit(name: name, redacted: redacted, source: source, note: note))
                if hits.count >= limit { stop.pointee = true }
            }
        }
        return hits
    }

    /// Keeps a short prefix for recognisability and hides the rest.
    static func redact(_ candidate: String) -> String {
        String(candidate.prefix(6)) + "…[redacted]"
    }
}
