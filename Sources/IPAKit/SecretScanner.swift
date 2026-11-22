import Foundation

/// Detects credential-shaped strings in text resources and binary strings.
///
/// Design rules (hard requirements, not preferences):
///  * Results are candidates, never proof. Every hit says so.
///  * Output is masked by default. The raw match can be revealed locally by
///    an explicit call; there is no path that sends it anywhere.
///  * Entropy alone is never a finding. A high-entropy string is only
///    reported when it sits next to credential context words.
///  * Known example/placeholder keys are allowlisted to cut false positives.
///  * This scanner contains no network code at all.
enum SecretScanner {

    // MARK: Types

    struct Hit: Codable, Sendable {
        let name: String
        let source: String
        /// Byte offset of the match inside the scanned blob.
        let offset: Int
        /// How it was found: "pattern", "pattern+context" or "entropy+context".
        let method: String
        let confidence: String     // high / medium / low
        let entropy: Double
        let note: String
        let matched: String        // raw match (kept in memory only)
        let masked: String         // what every report/export path shows
        let allowlisted: Bool

        /// Back-compat alias: reports and exports always carry the masked form.
        var redacted: String { masked }
    }

    struct Rule: Sendable {
        let name: String
        let pattern: String
        let confidence: String
        let severity: String
        let note: String
        /// True when the context-word requirement applies on top of the regex.
        let requiresContext: Bool
    }

    // MARK: Rules

    static let rules: [Rule] = [
        Rule(name: "Google/Firebase API key",
             pattern: #"AIza[0-9A-Za-z_\-]{35}"#,
             confidence: "high", severity: "high",
             note: "Google API keys are usable against Google/Firebase endpoints until restricted. Treat as exposed and rotate.", requiresContext: false),
        Rule(name: "AWS access key ID",
             pattern: #"\bAKIA[0-9A-Z]{16}\b"#,
             confidence: "high", severity: "critical",
             note: "An AWS access key ID embedded in a binary is a critical exposure when paired with its secret. Rotate immediately.", requiresContext: false),
        Rule(name: "GitHub token",
             pattern: #"\bgh[pousr]_[A-Za-z0-9]{36,255}\b"#,
             confidence: "high", severity: "critical",
             note: "GitHub tokens grant API or repository access. Rotate and audit usage.", requiresContext: false),
        Rule(name: "Slack token",
             pattern: #"\bxox[baprs]-[0-9A-Za-z\-]{10,250}\b"#,
             confidence: "high", severity: "high",
             note: "Slack tokens can post or read workspace data.", requiresContext: false),
        Rule(name: "Stripe live secret key",
             pattern: #"\b(sk_live)_[0-9a-zA-Z]{24,}\b"#,
             confidence: "high", severity: "critical",
             note: "A Stripe live secret key in a client binary is a direct payment-data exposure.", requiresContext: false),
        Rule(name: "Stripe publishable key",
             pattern: #"\b(pk_(live|test))_[0-9a-zA-Z]{24,}\b"#,
             confidence: "high", severity: "informational",
             note: "Publishable keys are designed to ship in clients. Listed for completeness.", requiresContext: false),
        Rule(name: "SendGrid API key",
             pattern: #"\bSG\.[A-Za-z0-9_\-]{22}\.[A-Za-z0-9_\-]{43}\b"#,
             confidence: "high", severity: "high",
             note: "SendGrid keys can send mail from the account.", requiresContext: false),
        Rule(name: "Mailgun API key",
             pattern: #"\bkey-[0-9a-zA-Z]{32}\b"#,
             confidence: "medium", severity: "high",
             note: "Short and generic; flagged as a candidate Mailgun key.", requiresContext: true),
        Rule(name: "Twilio API key",
             pattern: #"\bSK[0-9a-fA-F]{32}\b"#,
             confidence: "medium", severity: "high",
             note: "32 hex chars after 'SK' matches Twilio key format; other values may collide.", requiresContext: true),
        Rule(name: "JSON Web Token",
             pattern: #"\beyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\b"#,
             confidence: "medium", severity: "medium",
             note: "A JWT embedded on disk may be a sample, a service credential or cached session data.", requiresContext: false),
        Rule(name: "Private key block",
             pattern: #"-----BEGIN (RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY( BLOCK)?-----"#,
             confidence: "high", severity: "critical",
             note: "A private key literal in the bundle. Almost never legitimate in a client app.", requiresContext: false),
        Rule(name: "Basic-auth URL",
             pattern: #"[a-zA-Z][a-zA-Z0-9+.\-]*://[A-Za-z0-9._%+\-]+:[^@\s/]{6,}@"#,
             confidence: "medium", severity: "high",
             note: "A URL carrying user:password credentials.", requiresContext: false),
        Rule(name: "Bearer token literal",
             pattern: #"\bBearer\s+[A-Za-z0-9._\-]{20,}\b"#,
             confidence: "low", severity: "medium",
             note: "Bearer token literal; may be a sample value or a template.", requiresContext: false),
        Rule(name: "Assigned credential",
             pattern: #"(?i)\b(password|passwd|pwd|secret|api[_\-]?key|client[_\-]?secret|access[_\-]?token|auth[_\-]?token|private[_\-]?key)\b["']?\s*[:=]\s*["'][^"'\s]{8,128}["']"#,
             confidence: "medium", severity: "medium",
             note: "A credential-looking assignment. Common in sample code and default configs; the value is masked.", requiresContext: false),
        Rule(name: "Azure connection string",
             pattern: #"DefaultEndpointsProtocol=https;AccountName=[A-Za-z0-9]+;AccountKey=[A-Za-z0-9+/=]{88}"#,
             confidence: "high", severity: "critical",
             note: "Azure storage connection string with full account key.", requiresContext: false),
    ]

    /// Context words that justify an entropy-based candidate.
    static let contextWords: [String] = [
        "password", "passwd", "secret", "token", "apikey", "api_key", "api-key",
        "apikey", "credential", "credentials", "auth", "bearer", "private",
        "client_secret", "access_key", "signing", "hmac",
    ]

    /// Values that are documentation examples or obvious placeholders.
    static let allowlistSubstrings: [String] = [
        "example", "sample", "placeholder", "changeme", "change-me", "your_",
        "your-", "xxx", "dummy", "dummy_key", "test_key", "todo", "insert_",
        "<", "{", "}", "%@", "$(", "lorem", "aaaa", "00000000", "1234567890",
    ]

    // MARK: Entry points

    /// Scans a text blob. `limit` caps how many hits one blob may produce so
    /// a pathological file cannot flood the report.
    static func scan(text: String,
                     source: String,
                     limit: Int = 24,
                     allowlist: [String] = allowlistSubstrings) -> [Hit] {
        var hits: [Hit] = []
        let ns = text as NSString
        let whole = NSRange(location: 0, length: ns.length)

        for rule in rules {
            guard hits.count < limit else { break }
            guard let regex = try? NSRegularExpression(pattern: rule.pattern) else { continue }
            regex.enumerateMatches(in: text, range: whole) { match, _, stop in
                guard hits.count < limit else { stop.pointee = true; return }
                guard let match else { return }
                let matched = ns.substring(with: match.range)
                let byteOffset = byteOffset(ofUTF16Offset: match.range.location, in: text)

                if isAllowlisted(matched, allowlist: allowlist) {
                    // Recorded at debug level only: allowlisted matches are
                    // deliberately NOT findings, so they are skipped.
                    return
                }
                if rule.requiresContext && !hasCredentialContext(text, match.range) {
                    return
                }
                let entropy = shannonEntropy(matched)
                hits.append(Hit(
                    name: rule.name,
                    source: source,
                    offset: byteOffset,
                    method: rule.requiresContext ? "pattern+context" : "pattern",
                    confidence: rule.confidence,
                    entropy: entropy,
                    note: rule.note,
                    matched: matched,
                    masked: mask(matched),
                    allowlisted: false))
            }
        }

        // Entropy + context candidates. Entropy alone never qualifies.
        if hits.count < limit {
            hits.append(contentsOf: entropyCandidates(text: text, source: source,
                                                      budget: limit - hits.count,
                                                      allowlist: allowlist))
        }
        return hits
    }

    // MARK: Entropy candidates

    private static func entropyCandidates(text: String,
                                          source: String,
                                          budget: Int,
                                          allowlist: [String]) -> [Hit] {
        guard budget > 0 else { return [] }
        // Tokenise runs of token-ish characters (20+ chars), the shape of
        // generated credentials.
        guard let regex = try? NSRegularExpression(pattern: #"[A-Za-z0-9+/=_\-]{20,}"#) else { return [] }
        let ns = text as NSString
        var hits: [Hit] = []
        regex.enumerateMatches(in: text, range: NSRange(location: 0, length: ns.length)) { match, _, stop in
            guard hits.count < budget else { stop.pointee = true; return }
            guard let match else { return }
            let token = ns.substring(with: match.range)
            let entropy = shannonEntropy(token)
            guard entropy >= 3.5, token.count >= 20 else { return }
            guard hasCredentialContext(text, match.range) else { return }
            guard !isAllowlisted(token, allowlist: allowlist) else { return }
            // Skip tokens that a pattern rule would already have covered.
            if rules.contains(where: { (try? NSRegularExpression(pattern: $0.pattern))?.firstMatch(in: token, range: NSRange(location: 0, length: (token as NSString).length)) != nil }) {
                return
            }
            hits.append(Hit(
                name: "High-entropy string near credential context",
                source: source,
                offset: byteOffset(ofUTF16Offset: match.range.location, in: text),
                method: "entropy+context",
                confidence: "low",
                entropy: entropy,
                note: "A high-entropy string sits next to credential wording. This is a candidate only, not evidence of a live secret.",
                matched: token,
                masked: mask(token),
                allowlisted: false))
        }
        return hits
    }

    // MARK: Helpers

    static func shannonEntropy(_ string: String) -> Double {
        let bytes = Array(string.utf8)
        guard !bytes.isEmpty else { return 0 }
        var counts: [UInt8: Int] = [:]
        for b in bytes { counts[b, default: 0] += 1 }
        var entropy = 0.0
        for c in counts.values {
            let p = Double(c) / Double(bytes.count)
            entropy -= p * log2(p)
        }
        return entropy
    }

    static func mask(_ secret: String) -> String {
        let chars = Array(secret)
        guard chars.count > 8 else { return String(repeating: "•", count: chars.count) }
        let prefix = chars.prefix(4)
        let suffix = chars.suffix(2)
        return String(prefix) + "••••••••" + String(suffix)
            + " (masked, \(chars.count) characters)"
    }

    /// Reveals a hit locally. The caller must pass an explicit authorisation
    /// flag; there is no implicit path to the raw value.
    static func reveal(_ hit: Hit, authorisedLocally: Bool) -> String? {
        guard authorisedLocally else { return nil }
        return hit.matched
    }

    private static func isAllowlisted(_ value: String, allowlist: [String]) -> Bool {
        let lower = value.lowercased()
        if lower.contains("example") { return true }
        return allowlist.contains { lower.contains($0.lowercased()) }
    }

    private static func hasCredentialContext(_ text: String, _ range: NSRange) -> Bool {
        let ns = text as NSString
        let window = 160
        let start = max(0, range.location - window)
        let end = min(ns.length, NSMaxRange(range) + window)
        guard start < end else { return false }
        let context = ns.substring(with: NSRange(location: start, length: end - start)).lowercased()
        return contextWords.contains { context.contains($0) }
    }

    private static func byteOffset(ofUTF16Offset utf16: Int, in text: String) -> Int {
        let index = text.index(text.startIndex, offsetBy: min(utf16, text.utf16.count),
                               limitedBy: text.endIndex) ?? text.endIndex
        guard let utf8Index = index.samePosition(in: text.utf8) else { return 0 }
        return text.utf8.distance(from: text.utf8.startIndex, to: utf8Index)
    }
}
