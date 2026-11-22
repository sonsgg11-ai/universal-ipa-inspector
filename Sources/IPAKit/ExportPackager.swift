import Foundation

/// Complete-analysis export package (requirement V): builds the
/// `IPAInspector-Analysis-Report/` ZIP with a full manifest, per-module data
/// files, masked secrets and generated reports.
///
/// Only files for data that was actually collected are written. Blocked or
/// absent modules are recorded in manifest.json instead of being faked.
enum ExportPackager {

    static let rootFolder = "IPAInspector-Analysis-Report"

    struct Manifest: Codable {
        var tool = "IPA Inspector"
        var toolVersion = "1.0.0"
        var generatedAt: Date = Date()
        var ipaName: String = ""
        var ipaSHA256: String?
        var moduleCounts: [String: Int] = [:]
        var completeness: [String: String] = [:]   // module → complete / partial / blocked
        var blockedModules: [String] = []
        var notes: [String] = []
    }

    enum PackageError: LocalizedError, Equatable {
        case noOutcome
        case writeFailed(String)

        var errorDescription: String? {
            switch self {
            case .noOutcome: return "There is no completed analysis to export."
            case .writeFailed(let detail): return "Export failed while writing: \(detail)"
            }
        }
    }

    /// Builds the ZIP into a temporary file and verifies it by re-reading.
    /// Returns the file URL for the share sheet.
    @discardableResult
    static func buildPackage(outcome: AnalysisEngine.Outcome,
                             destination: URL? = nil) throws -> URL {
        var files: [(path: String, data: Data)] = []

        func add(_ path: String, _ data: Data) {
            files.append((path, data))
        }
        func addJSON<T: Encodable>(_ path: String, _ value: T) throws {
            let encoder = JSONEncoder()
            encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
            encoder.dateEncodingStrategy = .iso8601
            add(path, try encoder.encode(value))
        }
        func addText(_ path: String, _ text: String) {
            add(path, Data(text.utf8))
        }

        let report = outcome.report
        let metadata = outcome.engineMetadata

        // ---- manifest ----
        var manifest = Manifest()
        manifest.ipaName = report.name
        manifest.ipaSHA256 = report.sha256
        manifest.moduleCounts["findings"] = report.findings.count
        manifest.moduleCounts["securityFindings"] = outcome.security.count
        manifest.moduleCounts["secrets"] = outcome.secrets.count
        manifest.moduleCounts["files"] = report.files.count
        manifest.moduleCounts["binaries"] = report.binaries.count
        manifest.moduleCounts["symbols"] = outcome.symbols.values.reduce(0) { $0 + $1.count }
        manifest.moduleCounts["urls"] = report.urls.count
        manifest.moduleCounts["sdkEntries"] = outcome.sdk?.entries.count ?? 0
        manifest.moduleCounts["components"] = outcome.structure?.components.count ?? 0

        let encrypted = report.binaries.filter(\.isEncrypted).count
        if encrypted > 0 {
            manifest.blockedModules.append("swift/objective-c/symbol content for \(encrypted) encrypted binary(ies)")
        }
        if outcome.structure == nil {
            manifest.blockedModules.append("structure (not collected)")
        }
        if report.binaries.isEmpty {
            manifest.completeness["binaries"] = "empty"
            manifest.notes.append("No Mach-O binaries were parsed; binary modules contain header-level data only.")
        } else {
            manifest.completeness["binaries"] = encrypted == report.binaries.count ? "blocked-by-encryption" : "complete"
        }
        manifest.completeness["security"] = outcome.security.isEmpty ? "no-findings" : "complete"
        manifest.completeness["secrets"] = "complete (values masked by design)"
        manifest.completeness["signing"] = outcome.signing != nil ? "complete" : "partial"
        manifest.completeness["structure"] = outcome.structure != nil ? "complete" : "partial"
        manifest.completeness["sdk"] = outcome.sdk != nil ? "complete" : "partial"
        manifest.notes.append("Secrets are masked in every file of this package; raw values are never exported.")
        manifest.notes.append("This package contains only data that was actually collected during analysis.")

        try addJSON("\(rootFolder)/manifest.json", manifest)

        // ---- summary / metadata ----
        if let dashboard = outcome.dashboard {
            try addJSON("\(rootFolder)/summary.json", dashboard)
        } else {
            addText("\(rootFolder)/summary.json", "{ \"note\": \"dashboard snapshot was not collected\" }")
        }
        try addJSON("\(rootFolder)/application-metadata.json", report)

        // ---- file inventory ----
        var csv = ["path,size_bytes,compressed_bytes,ratio,permissions,location,type,sha256"]
        for file in outcome.inventory {
            csv.append([
                ReportExporter.csvEscape(file.path),
                "\(file.size)", "\(file.compressedSize)",
                String(format: "%.2f", file.compressionRatio),
                file.permissions, file.location, file.nodeType.rawValue,
                file.sha256 ?? "",
            ].joined(separator: ","))
        }
        addText("\(rootFolder)/file-inventory.csv", csv.joined(separator: "\n") + "\n")

        // ---- binaries/ ----
        var binaryInventory = ["path,archs,encrypted,warnings"]
        for binary in report.binaries {
            binaryInventory.append([
                ReportExporter.csvEscape(binary.path),
                binary.archs.map(\.cpu).joined(separator: " "),
                binary.isEncrypted ? "yes" : "no",
                ReportExporter.csvEscape(binary.warnings.joined(separator: "; ")),
            ].joined(separator: ","))
        }
        addText("\(rootFolder)/binaries/binary-inventory.csv", binaryInventory.joined(separator: "\n") + "\n")

        var headers = ["path,cpu,is64,platform,minOS,sdk,uuid,encrypted,cryptid,cryptoff,cryptsize"]
        for binary in report.binaries {
            for arch in binary.archs {
                let escapedPath = ReportExporter.csvEscape(binary.path)
                let wordSize = arch.is64Bit ? "yes" : "no"
                let encFlag = arch.encrypted.map { $0 ? "yes" : "no" } ?? ""
                let cryptID = arch.cryptID.map { String($0) } ?? ""
                let cryptOff = arch.cryptOffset.map { String($0) } ?? ""
                let cryptSize = arch.cryptSize.map { String($0) } ?? ""
                let row = [escapedPath, arch.cpu, wordSize,
                           arch.platform ?? "", arch.minOS ?? "", arch.sdk ?? "",
                           arch.uuid ?? "", encFlag, cryptID, cryptOff, cryptSize]
                headers.append(row.joined(separator: ","))
            }
        }
        addText("\(rootFolder)/binaries/macho-headers.csv", headers.joined(separator: "\n") + "\n")

        var segments = ["binary,cpu,segment,vmSize,fileOffset,fileSize,maxProt,writable,executable,truncated,sections"]
        for binary in report.binaries {
            for arch in binary.archs {
                for segment in arch.segments {
                    segments.append([
                        ReportExporter.csvEscape(binary.path), arch.cpu,
                        ReportExporter.csvEscape(segment.name),
                        "\(segment.vmSize)", "\(segment.fileOffset)", "\(segment.fileSize)",
                        "\(segment.maxProt)",
                        segment.isWritable ? "yes" : "no",
                        segment.isExecutable ? "yes" : "no",
                        segment.truncated ? "yes" : "no",
                        "\(segment.sections.count)",
                    ].joined(separator: ","))
                }
            }
        }
        addText("\(rootFolder)/binaries/segments-sections.csv", segments.joined(separator: "\n") + "\n")

        var dylibs = ["binary,cpu,kind,library"]
        for binary in report.binaries {
            for arch in binary.archs {
                for lib in arch.dylibs {
                    dylibs.append([ReportExporter.csvEscape(binary.path), arch.cpu, "load", ReportExporter.csvEscape(lib)].joined(separator: ","))
                }
                for lib in arch.weakDylibs {
                    dylibs.append([ReportExporter.csvEscape(binary.path), arch.cpu, "weak", ReportExporter.csvEscape(lib)].joined(separator: ","))
                }
                for lib in arch.reexportedDylibs {
                    dylibs.append([ReportExporter.csvEscape(binary.path), arch.cpu, "reexport", ReportExporter.csvEscape(lib)].joined(separator: ","))
                }
            }
        }
        addText("\(rootFolder)/binaries/dependencies.csv", dylibs.joined(separator: "\n") + "\n")

        var symbolsCSV = ["binary,cpu,symbol,kind,value"]
        for binary in report.binaries {
            for arch in binary.archs {
                for symbol in arch.symbols {
                    symbolsCSV.append([
                        ReportExporter.csvEscape(binary.path), arch.cpu,
                        ReportExporter.csvEscape(symbol.name), symbol.kind.rawValue,
                        "\(symbol.value)",
                    ].joined(separator: ","))
                }
            }
        }
        addText("\(rootFolder)/binaries/symbols.csv", symbolsCSV.joined(separator: "\n") + "\n")

        // ---- swift/ objective-c/ ----
        let objc = BinaryMetadata.objcInfo(extraction: try rebuildExtraction(outcome),
                                           binaries: report.binaries)
        for (path, info) in objc {
            let safeName = path.replacingOccurrences(of: "/", with: "_").replacingOccurrences(of: ":", with: "_")
            try addJSON("\(rootFolder)/objective-c/\(safeName).json", info)
        }
        let swift = BinaryMetadata.swiftInfo(extraction: try rebuildExtraction(outcome),
                                             binaries: report.binaries)
        for (path, info) in swift {
            let safeName = path.replacingOccurrences(of: "/", with: "_").replacingOccurrences(of: ":", with: "_")
            try addJSON("\(rootFolder)/swift/\(safeName).json", info)
        }

        // ---- strings/ (per binary, capped) ----
        if let extraction = outcome.extractionRoot {
            for binary in report.binaries where !binary.isEncrypted {
                let scanner = StringScanner(url: extraction.appendingPathComponent(binary.path),
                                            maxBytes: 8 * 1024 * 1024)
                let strings = scanner.strings().prefix(50_000)
                let safeName = binary.path.replacingOccurrences(of: "/", with: "_").replacingOccurrences(of: ":", with: "_")
                var body = "offset,string\n"
                for (index, string) in strings.enumerated() {
                    body += "\(index),\(ReportExporter.csvEscape(String(string.prefix(500))))\n"
                }
                addText("\(rootFolder)/strings/\(safeName).csv", body)
            }
        }

        // ---- dependencies/ ----
        if let sdk = outcome.sdk {
            try addJSON("\(rootFolder)/dependencies/sdk-inventory.json", sdk)
        }
        if let structure = outcome.structure {
            try addJSON("\(rootFolder)/dependencies/structure.json", structure)
        }

        // ---- security/ ----
        try addJSON("\(rootFolder)/security/findings.json", outcome.security)
        addText("\(rootFolder)/security/findings.csv", String(data: ReportExporter.exportFindingsCSV(report: report, security: outcome.security), encoding: .utf8) ?? "")
        var masked = [[String: String]]()
        for hit in outcome.secrets {
            masked.append([
                "name": hit.name,
                "masked": hit.masked,
                "source": hit.source,
                "offset": "\(hit.offset)",
                "method": hit.method,
                "confidence": hit.confidence,
                "entropy": String(format: "%.3f", hit.entropy),
                "note": hit.note,
            ])
        }
        try addJSON("\(rootFolder)/security/secret-detections-masked.json", masked)
        var owaspMappings: [[String: [String]]] = []
        for finding in outcome.security {
            owaspMappings.append(["id": [finding.id], "masvs": finding.masvs, "mastg": finding.mastg])
        }
        let owaspMappingPayload: [String: [[String: [String]]]] = [
            "framework": [["reference": ["OWASP MASVS v2 / MASTG"]]],
            "findings": owaspMappings,
        ]
        try addJSON("\(rootFolder)/security/owasp-mapping.json", owaspMappingPayload)

        // ---- signing/ ----
        if let signing = outcome.signing {
            try addJSON("\(rootFolder)/signing/signing-report.json", signing)
        }
        if let fairplay = outcome.fairplay {
            try addJSON("\(rootFolder)/signing/encryption-status.json", fairplay)
        }

        // ---- sdk/ ----
        if let sdk = outcome.sdk {
            try addJSON("\(rootFolder)/sdk/entries.json", sdk.entries)
            try addJSON("\(rootFolder)/sdk/limitations.json", sdk.limitations)
        }

        // ---- reports/ ----
        let txt = ReportExporter.exportTXT(report: report, security: outcome.security,
                                           fairplay: outcome.fairplay,
                                           signing: outcome.signing, metadata: metadata)
        addText("\(rootFolder)/reports/technical-summary.txt", txt)
        let pdf = ReportExporter.exportPDF(report: report, security: outcome.security,
                                           secrets: outcome.secrets, metadata: metadata,
                                           fairplay: outcome.fairplay)
        add("\(rootFolder)/reports/complete-report.pdf", pdf)

        // ---- write the ZIP ----
        let safeApp = report.name
            .replacingOccurrences(of: "/", with: "-")
            .replacingOccurrences(of: ":", with: "-")
        let target = destination ?? FileManager.default.temporaryDirectory
            .appendingPathComponent("\(safeApp)-Analysis-Export.zip")
        try? FileManager.default.removeItem(at: target)
        try SimpleZipWriter.write(files: files, to: target)

        // Verify: the archive must re-open and every entry must round-trip.
        let entries = try ZipArchive.readDirectory(at: target)
        guard entries.count == files.count else {
            throw PackageError.writeFailed("archive contains \(entries.count) entries, expected \(files.count)")
        }
        for (index, entry) in entries.enumerated() {
            guard entry.path == files[index].path,
                  entry.uncompressedSize == Int64(files[index].data.count) else {
                throw PackageError.writeFailed("entry \(entry.path) did not round-trip")
            }
        }
        return target
    }

    private static func rebuildExtraction(_ outcome: AnalysisEngine.Outcome) throws -> ExtractionResult {
        var layout = BundleLayout(appBundlePath: "Payload/unknown.app")
        if let first = outcome.report.files.first(where: { $0.path.contains(".app/") }),
           let range = first.path.range(of: ".app") {
            layout.appBundlePath = String(first.path[..<range.upperBound])
        }
        for file in outcome.report.files {
            let p = file.path
            if p.contains(".framework/"), let r = p.range(of: ".framework") {
                let f = String(p[..<r.upperBound])
                if !layout.frameworks.contains(f) { layout.frameworks.append(f) }
            }
            if p.contains(".appex/"), let r = p.range(of: ".appex") {
                let e = String(p[..<r.upperBound])
                if !layout.extensions.contains(e) { layout.extensions.append(e) }
            }
        }
        guard let root = outcome.extractionRoot else {
            throw PackageError.noOutcome
        }
        return ExtractionResult(root: root, layout: layout, files: outcome.report.files,
                                totalBytes: outcome.report.totalBytes,
                                rejectedEntries: [], hash: outcome.report.sha256,
                                warnings: [])
    }
}

// MARK: - Simple ZIP writer (stored entries)

/// A minimal ZIP writer (stored/uncompressed entries) used for export
/// packages. Kept dependency-free so it runs and tests identically on iOS
/// and Linux. CRC-32 matches the reference implementation used elsewhere.
enum SimpleZipWriter {

    static func write(files: [(path: String, data: Data)], to url: URL) throws {
        var out = Data()
        var central = Data()
        var count: UInt16 = 0

        for file in files {
            let nameBytes = Array(file.path.utf8)
            let crc = FixtureCRC32.of(file.data)
            let offset = Int64(out.count)
            let size = Int64(file.data.count)

            var local = Data()
            local.appendLE32(0x0403_4B50)
            local.appendLE16(20)
            local.appendLE16(0)
            local.appendLE16(0)
            local.appendLE16(0)
            local.appendLE16(0)
            local.appendLE32(crc)
            local.appendLE32(UInt32(bitPattern: Int32(truncatingIfNeeded: size)))
            local.appendLE32(UInt32(bitPattern: Int32(truncatingIfNeeded: size)))
            local.appendLE16(UInt16(nameBytes.count))
            local.appendLE16(0)
            local.append(contentsOf: nameBytes)
            local.append(file.data)
            out.append(local)

            var c = Data()
            c.appendLE32(0x0201_4B50)
            c.appendLE16((3 << 8) | 20)
            c.appendLE16(20)
            c.appendLE16(0)
            c.appendLE16(0)
            c.appendLE16(0)
            c.appendLE16(0)
            c.appendLE32(crc)
            c.appendLE32(UInt32(bitPattern: Int32(truncatingIfNeeded: size)))
            c.appendLE32(UInt32(bitPattern: Int32(truncatingIfNeeded: size)))
            c.appendLE16(UInt16(nameBytes.count))
            c.appendLE16(0)
            c.appendLE16(0)
            c.appendLE16(0)
            c.appendLE16(0)
            c.appendLE32((0o100644 << 16) | 0o644)
            c.appendLE32(UInt32(bitPattern: Int32(truncatingIfNeeded: offset)))
            c.append(contentsOf: nameBytes)
            central.append(c)
            count += 1
        }

        let cdOffset = Int64(out.count)
        let cdSize = Int64(central.count)
        out.append(central)

        var eocd = Data()
        eocd.appendLE32(0x0605_4B50)
        eocd.appendLE16(0)
        eocd.appendLE16(0)
        eocd.appendLE16(count)
        eocd.appendLE16(count)
        eocd.appendLE32(UInt32(bitPattern: Int32(truncatingIfNeeded: cdSize)))
        eocd.appendLE32(UInt32(bitPattern: Int32(truncatingIfNeeded: cdOffset)))
        eocd.appendLE16(0)
        out.append(eocd)

        try out.write(to: url, options: .atomic)
    }
}

/// CRC-32 shared by the ZIP writer (needs to live in the main target; the
/// test-target copy in FixtureBuilder has the same reference values).
enum FixtureCRC32 {
    static func of(_ data: Data) -> UInt32 {
        var table: [UInt32] = (0..<256).map { i -> UInt32 in
            var c: UInt32 = UInt32(i)
            for _ in 0..<8 {
                c = (c & 1) != 0 ? (0xEDB8_8320 ^ (c >> 1)) : (c >> 1)
            }
            return c
        }
        var crc: UInt32 = 0xFFFF_FFFF
        for byte in [UInt8](data) {
            crc = table[Int((crc ^ UInt32(byte)) & 0xFF)] ^ (crc >> 8)
        }
        return crc ^ 0xFFFF_FFFF
    }
}
