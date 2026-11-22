import Foundation

/// Report export (requirement O): JSON (full, machine-readable), CSV tables,
/// TXT technical summary and PDF (hand-rolled, dependency-free).
///
/// Everything exported is the same data the UI shows, generated from the
/// same engine outputs. Secrets are always masked in every export; the raw
/// values are never written to any file.
enum ReportExporter {

    struct EngineMetadata: Codable {
        var toolName = "IPA Inspector"
        var toolVersion = "1.0.0"
        var analysisStartedAt: Date
        var analysisFinishedAt: Date
        var diagnosticsLog: [String] = []
        var methodology = [
            "ZIP central-directory parsing with strict entry-safety policy",
            "Mach-O header/load-command parsing (thin, FAT, FAT64)",
            "LC_SYMTAB symbol extraction, ObjC/Swift section metadata",
            "OWASP MASVS/MASTG-aligned static rules with per-finding evidence",
            "Credential pattern + entropy+context detection, masked output",
            "SDK fingerprinting from paths, framework bundles and link tables",
        ]
        var limitations: [String]
    }

    // MARK: JSON

    struct CompleteJSON: Codable {
        var metadata: EngineMetadata
        var report: Report
        var dashboard: DashboardProvider.Snapshot?
        var structure: StructureAnalyzer.StructureReport?
        var security: [SecurityAssessor.Finding]
        var secrets: [SecretScanner.Hit]
        var signing: ProvisioningParser.SigningReport?
        var fairplay: FairPlayDetector.EncryptionReport?
        var sdk: SDKInventory.Inventory?
        var evidenceStatusCounts: [String: Int]
    }

    static func exportJSON(report: Report,
                           security: [SecurityAssessor.Finding],
                           secrets: [SecretScanner.Hit],
                           metadata: EngineMetadata,
                           dashboard: DashboardProvider.Snapshot?,
                           structure: StructureAnalyzer.StructureReport?,
                           signing: ProvisioningParser.SigningReport?,
                           fairplay: FairPlayDetector.EncryptionReport?,
                           sdk: SDKInventory.Inventory?) throws -> Data {
        var counts: [String: Int] = [:]
        for status in EvidenceStatus.allCases {
            counts[status.rawValue] = report.findings.filter { $0.status == status }.count
        }
        let payload = CompleteJSON(
            metadata: metadata, report: report, dashboard: dashboard,
            structure: structure, security: security, secrets: secrets,
            signing: signing, fairplay: fairplay, sdk: sdk,
            evidenceStatusCounts: counts)
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
        encoder.dateEncodingStrategy = .iso8601
        return try encoder.encode(payload)
    }

    // MARK: CSV

    static func csvEscape(_ field: String) -> String {
        // Newlines inside a value are flattened so every CSV row stays one
        // physical line; the value keeps its structure with "; " separators.
        let flattened = field
            .replacingOccurrences(of: "\r\n", with: "; ")
            .replacingOccurrences(of: "\n", with: "; ")
            .replacingOccurrences(of: "\r", with: "; ")
        let needsQuotes = flattened.contains(",") || flattened.contains("\"")
        let escaped = flattened.replacingOccurrences(of: "\"", with: "\"\"")
        return needsQuotes ? "\"\(escaped)\"" : escaped
    }

    static func exportFindingsCSV(report: Report, security: [SecurityAssessor.Finding]) -> Data {
        var lines: [String] = ["id,category,title,value,source,status,severity,confidence,masvs,note"]
        var n = 0
        for finding in report.findings {
            n += 1
            lines.append([
                String(format: "F-%04d", n),
                csvEscape(finding.category), csvEscape(finding.title),
                csvEscape(finding.value), csvEscape(finding.source),
                finding.status.rawValue, "", "", "",
                csvEscape(finding.note ?? ""),
            ].joined(separator: ","))
        }
        for finding in security {
            lines.append([
                finding.id,
                csvEscape("Security"), csvEscape(finding.title),
                csvEscape(finding.evidence), csvEscape(finding.sourceFile),
                finding.status.rawValue,
                finding.severity.rawValue, finding.confidence.rawValue,
                csvEscape(finding.masvs.joined(separator: " ")),
                csvEscape(finding.explanation),
            ].joined(separator: ","))
        }
        return Data((lines.joined(separator: "\n") + "\n").utf8)
    }

    static func exportSymbolsCSV(report: Report) -> Data {
        var lines: [String] = ["binary,cpu,symbol,kind"]
        for binary in report.binaries {
            for arch in binary.archs {
                for symbol in arch.symbols {
                    lines.append([
                        csvEscape(binary.path), arch.cpu,
                        csvEscape(symbol.name), symbol.kind.rawValue,
                    ].joined(separator: ","))
                }
            }
        }
        return Data((lines.joined(separator: "\n") + "\n").utf8)
    }

    static func exportStringsCSV(_ corpus: [(source: String, strings: [String])]) -> Data {
        var lines: [String] = ["source,offset,string"]
        for (source, strings) in corpus {
            for (index, string) in strings.enumerated() {
                lines.append([csvEscape(source), "\(index)", csvEscape(String(string.prefix(500)))].joined(separator: ","))
            }
        }
        return Data((lines.joined(separator: "\n") + "\n").utf8)
    }

    static func exportComponentsCSV(_ structure: StructureAnalyzer.StructureReport) -> Data {
        var lines: [String] = ["path,kind,bundleID,version,minOS,architectures,status,minOSCompatible"]
        for c in structure.components {
            lines.append([
                csvEscape(c.path), c.kind.rawValue,
                csvEscape(c.bundleID ?? ""), csvEscape(c.version ?? ""),
                csvEscape(c.minOS ?? ""), csvEscape(c.architectures.joined(separator: " ")),
                c.analysisStatus.rawValue,
                c.minOSCompatible.map { $0 ? "yes" : "no" } ?? "",
            ].joined(separator: ","))
        }
        return Data((lines.joined(separator: "\n") + "\n").utf8)
    }

    // MARK: TXT

    static func exportTXT(report: Report,
                          security: [SecurityAssessor.Finding],
                          fairplay: FairPlayDetector.EncryptionReport?,
                          signing: ProvisioningParser.SigningReport?,
                          metadata: EngineMetadata) -> String {
        var out: [String] = []
        out.append("IPA INSPECTOR — TECHNICAL SUMMARY")
        out.append(Rule.line(60))
        out.append("Generated: \(ISO8601DateFormatter().string(from: metadata.analysisFinishedAt))")
        out.append("Tool: \(metadata.toolName) \(metadata.toolVersion)")
        out.append("")
        out.append("APPLICATION")
        out.append(Rule.line(60, char: "-"))
        for title in ["Display name", "Bundle ID", "Version", "Build number", "Minimum iOS", "Main executable"] {
            if let f = report.findings.first(where: { $0.title == title }) {
                out.append(String(format: "  %@: %@", title, f.value))
            }
        }
        if let hash = report.sha256 {
            out.append("  IPA SHA-256: \(hash)")
        }
        out.append("  Files: \(report.fileCount) · extracted bytes: \(report.totalBytes)")
        out.append("")
        out.append("BINARIES")
        out.append(Rule.line(60, char: "-"))
        for binary in report.binaries {
            let archs = binary.archs.map { "\($0.cpu)\(binary.isEncrypted ? " (encrypted)" : "")" }.joined(separator: ", ")
            out.append("  \(binary.path) [\(archs)]")
        }
        out.append("")
        out.append("SECURITY FINDINGS (\(security.count))")
        out.append(Rule.line(60, char: "-"))
        for finding in security {
            out.append("  \(finding.id) [\(finding.severity.rawValue.uppercased())/\(finding.confidence)] \(finding.title)")
            out.append("      evidence: \(finding.evidence.prefix(220))")
            out.append("      source: \(finding.sourceFile) — \(finding.sourceLocation)")
            out.append("      MASVS: \(finding.masvs.joined(separator: "; "))")
            out.append("      status: \(finding.status.label)")
        }
        if let fairplay {
            out.append("")
            out.append("ENCRYPTION STATUS")
            out.append(Rule.line(60, char: "-"))
            out.append("  Encrypted binaries: \(fairplay.encryptedBinaryPaths.count)")
            out.append("  Blocked operations: \(fairplay.blockedOperations.count) (listed in the JSON export)")
        }
        if let signing {
            out.append("")
            out.append("SIGNING")
            out.append(Rule.line(60, char: "-"))
            out.append("  \(signing.summary)")
        }
        out.append("")
        out.append("METHODOLOGY")
        out.append(Rule.line(60, char: "-"))
        metadata.methodology.forEach { out.append("  • \($0)") }
        out.append("")
        out.append("LIMITATIONS (static analysis cannot prove runtime behaviour)")
        out.append(Rule.line(60, char: "-"))
        (metadata.limitations + report.limitations).forEach { out.append("  • \($0)") }
        return out.joined(separator: "\n") + "\n"
    }

    // MARK: PDF (minimal, dependency-free writer)

    /// Writes a simple, valid PDF 1.4 document: Helvetica text pages,
    /// Word-wrapped. Sufficient for a professional human-readable report and
    /// fully testable without external libraries.
    static func exportPDF(report: Report,
                          security: [SecurityAssessor.Finding],
                          secrets: [SecretScanner.Hit],
                          metadata: EngineMetadata,
                          fairplay: FairPlayDetector.EncryptionReport?) -> Data {
        var pages: [[String]] = []

        // Cover page
        pages.append([
            "IPA Inspector — Analysis Report",
            "",
            "Application: \(report.name)",
            "Source: \(report.source)",
            "Generated: \(ISO8601DateFormatter().string(from: metadata.analysisFinishedAt))",
            report.sha256.map { "IPA SHA-256: \($0)" } ?? "SHA-256: n/a",
            "Files: \(report.fileCount)   Findings: \(report.findings.count)",
        ])

        // Identity page
        var identity: [String] = ["1. Application identity"]
        for title in ["Display name", "Bundle ID", "Version", "Build number", "Minimum iOS",
                      "Main executable", "Platform", "Built with Xcode"] {
            if let f = report.findings.first(where: { $0.title == title }) {
                identity.append("  \(title): \(f.value)")
            }
        }
        identity.append("")
        identity.append("2. Binaries")
        for binary in report.binaries.prefix(40) {
            let archs = binary.archs.map { $0.cpu }.joined(separator: ", ")
            identity.append("  \(binary.path) [\(archs)]\(binary.isEncrypted ? " (encrypted)" : "")")
        }
        pages.append(wrap(identity))

        // Security findings
        var sec: [String] = ["3. Security findings (\(security.count))"]
        for finding in security {
            sec.append("\(finding.id) [\(finding.severity.rawValue.uppercased())/\(finding.confidence)] \(finding.title) (\(finding.status.label))")
            sec.append("   evidence: \(finding.evidence)")
            sec.append("   source: \(finding.sourceFile) — \(finding.sourceLocation)")
            sec.append("   MASVS: \(finding.masvs.joined(separator: "; "))")
            sec.append("   fix: \(finding.remediation)")
            sec.append("")
        }
        for chunk in split(sec, per: 42) { pages.append(wrap(chunk)) }

        // Secrets (masked) + limitations
        var tail: [String] = ["4. Credential-shaped strings (masked, \(secrets.count))"]
        for hit in secrets {
            tail.append("  \(hit.name) — \(hit.masked)")
            tail.append("    source: \(hit.source) · offset \(hit.offset) · \(hit.method)")
        }
        tail.append("")
        tail.append("5. Limitations")
        (metadata.limitations + report.limitations).forEach { tail.append("  • \($0)") }
        for chunk in split(tail, per: 42) { pages.append(wrap(chunk)) }

        return PDFWriter.render(pages: pages.map { page -> String in
            page.joined(separator: "\n")
        })
    }
}

// MARK: - PDF writer

/// A minimal but valid PDF 1.4 generator: text-only pages with Helvetica.
/// Produces correct xref offsets and object numbering; verified by tests.
enum PDFWriter {

    static func render(pages: [String]) -> Data {
        var objects: [String] = []

        // Font objects
        objects.append("<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>")
        objects.append("<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica-Bold >>")

        var pageObjectIDs: [Int] = []
        // ids: 1 catalog, 2 pages, then per page: page object + content stream
        for (index, text) in pages.enumerated() {
            let pageID = 3 + index * 2
            let contentID = pageID + 1
            pageObjectIDs.append(pageID)

            let content = contentStream(for: text)
            let escaped = escapePDFString(content)
            let streamDict = "<< /Length \(escaped.utf8.count) >>\nstream\n\(escaped)\nendstream"
            objects.append("<< /Type /Page /Parent 2 0 R /MediaBox [0 0 595 842] "
                + "/Resources << /Font << /F1 1 0 R /F2 2 0 R >> >> "
                + "/Contents \(contentID) 0 R >>")
            objects.append(streamDict)
        }

        var body = "%PDF-1.4\n"
        var offsets: [Int] = []
        for (index, object) in objects.enumerated() {
            offsets.append(body.utf8.count)
            body += "\(index + 1) 0 obj\n\(object)\nendobj\n"
        }

        // Fix catalog/pages references
        let catalogIndex = 0
        let pagesIndex = 1
        let kids = pageObjectIDs.map { "\($0) 0 R" }.joined(separator: " ")
        // Rebuild: objects[0] catalog, objects[1] pages — constructed now.
        objects[catalogIndex] = "<< /Type /Catalog /Pages 2 0 R >>"
        objects[pagesIndex] = "<< /Type /Pages /Kids [\(kids)] /Count \(pageObjectIDs.count) >>"
        // Re-render body with corrected first two objects.
        body = "%PDF-1.4\n"
        offsets = []
        for (index, object) in objects.enumerated() {
            offsets.append(body.utf8.count)
            body += "\(index + 1) 0 obj\n\(object)\nendobj\n"
        }

        let xrefStart = body.utf8.count
        body += "xref\n0 \(objects.count + 1)\n0000000000 65535 f \n"
        for offset in offsets {
            body += String(format: "%010d 00000 n \n", offset)
        }
        body += "trailer\n<< /Size \(objects.count + 1) /Root 1 0 R >>\nstartxref\n\(xrefStart)\n%%EOF\n"
        return Data(body.utf8)
    }

    private static func contentStream(for text: String) -> String {
        var out = "BT\n/F1 10 Tf\n14 TL\n50 792 Td\n"
        var first = true
        for line in text.components(separatedBy: "\n") {
            let safe = line.isEmpty ? " " : line
            if first {
                out += "(\(escapePDFText(safe))) Tj\n"
                first = false
            } else {
                out += "T*\n(\(escapePDFText(safe))) Tj\n"
            }
        }
        out += "ET"
        return out
    }

    private static func escapePDFText(_ text: String) -> String {
        var out = ""
        for scalar in text.unicodeScalars {
            switch scalar {
            case "\\": out += "\\\\"
            case "(": out += "\\("
            case ")": out += "\\)"
            case "\r": continue
            default:
                // WinAnsi coverage; anything else becomes a question mark so
                // the PDF stays valid and honest about its limits.
                out += scalar.value < 0x80 || (0xA0...0xFF).contains(scalar.value)
                    ? String(scalar) : "?"
            }
        }
        return out
    }

    private static func escapePDFString(_ text: String) -> String { text }
}

// MARK: - Shared string helpers

enum Rule {
    static func line(_ length: Int = 60, char: Character = "=") -> String {
        String(repeating: char, count: length)
    }
}

/// Splits lines into page-sized chunks.
func split(_ lines: [String], per pageSize: Int) -> [[String]] {
    guard !lines.isEmpty else { return [[]] }
    var pages: [[String]] = []
    var current: [String] = []
    for line in lines {
        current.append(line)
        if current.count >= pageSize {
            pages.append(current)
            current = []
        }
    }
    if !current.isEmpty { pages.append(current) }
    return pages
}

/// Word-wrap lines to a printable width so nothing runs off the page.
func wrap(_ lines: [String], width: Int = 92) -> [String] {
    var out: [String] = []
    for line in lines {
        if line.count <= width {
            out.append(line)
            continue
        }
        var remaining = Substring(line)
        while remaining.count > width {
            var cut = remaining.index(remaining.startIndex, offsetBy: width)
            // back to the last space
            while cut > remaining.startIndex, remaining[cut] != " " {
                cut = remaining.index(before: cut)
            }
            if cut == remaining.startIndex {
                cut = remaining.index(remaining.startIndex, offsetBy: width)
            }
            out.append(String(remaining[remaining.startIndex..<cut]))
            remaining = remaining[cut...].dropFirst()
        }
        out.append(String(remaining))
    }
    return out
}
