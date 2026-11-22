import SwiftUI
import UniformTypeIdentifiers

@main
struct IPAInspectorApp: App {
    var body: some Scene {
        WindowGroup {
            RootView()
        }
    }
}

// MARK: - Root

struct RootView: View {
    @StateObject private var session = AnalysisSession()

    var body: some View {
        NavigationStack {
            InputView()
        }
        .environmentObject(session)
        .tint(.accentColor)
    }
}

// MARK: - Input screen

struct InputView: View {
    @EnvironmentObject private var session: AnalysisSession
    @State private var link = ""
    @State private var importing = false
    @State private var importError: String?

    var body: some View {
        List {
            Section {
                TextField("https://apps.apple.com/us/app/id1234567890", text: $link)
                    .textInputAutocapitalization(.never)
                    .autocorrectionDisabled()
                    .keyboardType(.URL)
                    .submitLabel(.go)
                    .onSubmit(lookup)
                    .disabled(session.isRunning)
                Picker("Storefront", selection: $session.storefront) {
                    ForEach(AppStoreClient.knownStorefronts.sorted(), id: \.self) { code in
                        Text(code.uppercased()).tag(code)
                    }
                }
                .disabled(session.isRunning)
                Button(action: lookup) {
                    Label("Look up listing", systemImage: "magnifyingglass")
                }
                .disabled(session.isRunning || link.trimmingCharacters(in: .whitespaces).isEmpty)
            } header: {
                Text("App Store link")
            } footer: {
                Text("Returns public listing data only. A store link never provides the app binary.")
            }

            Section {
                Button {
                    importing = true
                } label: {
                    Label("Import IPA…", systemImage: "square.and.arrow.down")
                }
                .disabled(session.isRunning)

                if session.isRunning {
                    ProgressView(value: session.progressFraction) {
                        Text(progressLabel)
                            .font(.footnote)
                    }
                    Button(role: .destructive, action: session.cancel) {
                        Label("Cancel", systemImage: "xmark.circle")
                    }
                }
            } header: {
                Text("IPA file")
            } footer: {
                Text("Analysis runs on this device. Nothing is uploaded anywhere.")
            }

            if case .failed(let message) = session.phase {
                Section("Error") {
                    Text(message).foregroundStyle(.red).font(.callout)
                }
            }
            if case .cancelled = session.phase {
                Section { Text("Cancelled.").foregroundStyle(.secondary) }
            }
            if let importError {
                Section("Import") { Text(importError).foregroundStyle(.red).font(.callout) }
            }

            if let report = session.report {
                Section("Results") {
                    NavigationLink {
                        ReportSummaryView(report: report)
                    } label: {
                        VStack(alignment: .leading, spacing: 4) {
                            Text(report.name).font(.headline)
                            Text("\(report.findings.count) findings · \(report.fileCount) files")
                                .font(.caption).foregroundStyle(.secondary)
                        }
                    }
                    NavigationLink("Findings browser") { FindingsBrowserView(report: report) }
                    NavigationLink("Evidence log") { LogView() }
                }
            } else {
                Section("How it works") {
                    Text("Static analysis only. Encrypted (FairPlay) executables are reported as blocked rather than guessed at, and nothing here decrypts them.")
                        .font(.footnote)
                        .foregroundStyle(.secondary)
                }
            }
        }
        .navigationTitle("IPA Inspector")
        .fileImporter(
            isPresented: $importing,
            allowedContentTypes: [.item, .data, .archive],
            allowsMultipleSelection: false
        ) { result in
            importError = nil
            switch result {
            case .success(let urls):
                guard let url = urls.first else { return }
                guard url.pathExtension.lowercased() == "ipa" || url.pathExtension.lowercased() == "zip" else {
                    importError = "Choose an .ipa (or .zip) file. Selected: \(url.lastPathComponent)"
                    return
                }
                session.analyse(ipaURL: url)
            case .failure(let error):
                importError = error.localizedDescription
            }
        }
    }

    private var progressLabel: String {
        if case .running(let message) = session.phase { return message }
        return "Working…"
    }

    private func lookup() {
        let trimmed = link.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty else { return }
        session.lookup(trimmed)
    }
}

// MARK: - Summary

struct ReportSummaryView: View {
    let report: Report
    @State private var exportState: ExportState = .idle

    enum ExportState: Equatable {
        case idle, working
        case ready(URL)
        case failed(String)
    }

    private var counts: [(EvidenceStatus, Int)] {
        EvidenceStatus.allCases.map { status in
            (status, report.findings.filter { $0.status == status }.count)
        }
    }

    var body: some View {
        List {
            Section("Report") {
                LabeledContent("Source", value: report.source)
                LabeledContent("Name", value: report.name)
                LabeledContent("Files", value: "\(report.fileCount)")
                LabeledContent("Total size", value: ByteCountFormatter.string(fromByteCount: report.totalBytes, countStyle: .file))
                LabeledContent("Findings", value: "\(report.findings.count)")
                if let hash = report.sha256 {
                    VStack(alignment: .leading, spacing: 2) {
                        Text("SHA-256").font(.caption).foregroundStyle(.secondary)
                        Text(hash).font(.caption2.monospaced()).textSelection(.enabled)
                    }
                }
            }

            Section("Evidence quality") {
                ForEach(counts, id: \.0) { status, count in
                    LabeledContent(status.label.capitalized, value: "\(count)")
                }
            }

            if !report.limitations.isEmpty {
                Section("Limitations of this report") {
                    ForEach(report.limitations, id: \.self) { limitation in
                        Text(limitation).font(.footnote).foregroundStyle(.secondary)
                    }
                }
            }

            Section("Export") {
                switch exportState {
                case .idle:
                    Button {
                        export()
                    } label: {
                        Label("Export report as JSON", systemImage: "square.and.arrow.up")
                    }
                case .working:
                    HStack { ProgressView(); Text("Writing JSON…") }
                case .ready(let url):
                    ShareLink(item: url) { Label("Share report JSON", systemImage: "square.and.arrow.up") }
                    Text(url.lastPathComponent).font(.caption2.monospaced()).foregroundStyle(.secondary)
                case .failed(let message):
                    Text("Export failed: \(message)").foregroundStyle(.red).font(.footnote)
                    Button("Try again") { export() }
                }
            }

            Section {
                NavigationLink("Findings browser") { FindingsBrowserView(report: report) }
                NavigationLink("Mach-O binaries (\(report.binaries.count))") { BinaryListView(report: report) }
                NavigationLink("Files (\(report.fileCount))") { FileInventoryView(report: report) }
                NavigationLink("URLs (\(report.urls.count))") { URLListView(report: report) }
                NavigationLink("Hosts (\(report.domains.count))") { HostListView(report: report) }
                NavigationLink("Evidence log") { LogView() }
            }
        }
        .navigationTitle("Summary")
    }

    private func export() {
        exportState = .working
        do {
            let encoder = JSONEncoder()
            encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
            encoder.dateEncodingStrategy = .iso8601
            let data = try encoder.encode(report)
            guard !data.isEmpty else { throw ExportError.empty }
            let safeName = report.name
                .replacingOccurrences(of: "/", with: "-")
                .replacingOccurrences(of: ":", with: "-")
            let url = FileManager.default.temporaryDirectory
                .appendingPathComponent("\(safeName)-report.json")
            try data.write(to: url, options: .atomic)
            // Read it back so a silent write failure cannot masquerade as success.
            let check = try Data(contentsOf: url)
            guard check.count == data.count else { throw ExportError.truncated }
            exportState = .ready(url)
        } catch {
            exportState = .failed(error.localizedDescription)
        }
    }

    enum ExportError: LocalizedError {
        case empty, truncated
        var errorDescription: String? {
            switch self {
            case .empty: return "the encoder produced no data"
            case .truncated: return "the written file did not match what was encoded"
            }
        }
    }
}

// MARK: - Findings browser

struct FindingsBrowserView: View {
    let report: Report
    @State private var query = ""
    @State private var selectedStatus: EvidenceStatus?
    @State private var selectedCategory: String?

    private var filtered: [Finding] {
        report.findings.filter { finding in
            if let selectedStatus, finding.status != selectedStatus { return false }
            if let selectedCategory, finding.category != selectedCategory { return false }
            guard !query.isEmpty else { return true }
            let haystack = [finding.title, finding.value, finding.source,
                            finding.category, finding.note ?? ""].joined(separator: " ")
            return haystack.localizedCaseInsensitiveContains(query)
        }
    }

    private var grouped: [(String, [Finding])] {
        Dictionary(grouping: filtered, by: \.category)
            .map { ($0.key, $0.value) }
            .sorted { $0.0 < $1.0 }
    }

    var body: some View {
        List {
            Section {
                Picker("Status", selection: $selectedStatus) {
                    Text("Any").tag(EvidenceStatus?.none)
                    ForEach(EvidenceStatus.allCases, id: \.self) { status in
                        Text(status.label.capitalized).tag(EvidenceStatus?.some(status))
                    }
                }
                Picker("Category", selection: $selectedCategory) {
                    Text("All").tag(String?.none)
                    ForEach(report.categories, id: \.self) { category in
                        Text(category).tag(String?.some(category))
                    }
                }
            }

            ForEach(grouped, id: \.0) { category, findings in
                Section(category) {
                    ForEach(findings) { finding in
                        NavigationLink {
                            FindingDetailView(finding: finding, report: report)
                        } label: {
                            FindingRow(finding: finding)
                        }
                    }
                }
            }

            if filtered.isEmpty {
                Section {
                    ContentUnavailableView("No matching findings",
                                           systemImage: "magnifyingglass",
                                           description: Text("Adjust the search text or filters."))
                }
            }
        }
        .searchable(text: $query, prompt: "Search titles, values and paths")
        .navigationTitle("Findings")
    }
}

struct FindingRow: View {
    let finding: Finding

    var body: some View {
        VStack(alignment: .leading, spacing: 4) {
            HStack(alignment: .firstTextBaseline) {
                Text(finding.title).font(.subheadline.weight(.semibold))
                Spacer(minLength: 8)
                StatusBadge(status: finding.status)
            }
            Text(finding.value)
                .font(.footnote)
                .lineLimit(3)
                .foregroundStyle(.secondary)
        }
        .padding(.vertical, 2)
    }
}

struct StatusBadge: View {
    let status: EvidenceStatus

    var body: some View {
        Text(status.label)
            .font(.caption2.weight(.medium))
            .padding(.horizontal, 6)
            .padding(.vertical, 2)
            .background(colour.opacity(0.18), in: Capsule())
            .foregroundStyle(colour)
            .accessibilityLabel("Evidence status: \(status.label)")
    }

    private var colour: Color {
        switch status {
        case .verified: return .green
        case .detected: return .blue
        case .estimated: return .orange
        case .blocked: return .red
        case .notFound: return .gray
        }
    }
}

struct FindingDetailView: View {
    let finding: Finding
    let report: Report

    var body: some View {
        List {
            Section("Finding") {
                LabeledContent("Title", value: finding.title)
                LabeledContent("Category", value: finding.category)
                HStack {
                    Text("Status")
                    Spacer()
                    StatusBadge(status: finding.status)
                }
            }
            Section("Value") {
                Text(finding.value)
                    .font(.callout)
                    .textSelection(.enabled)
            }
            Section("Source") {
                Text(finding.source)
                    .font(.footnote.monospaced())
                    .textSelection(.enabled)
            }
            if let note = finding.note {
                Section("What this does and does not prove") {
                    Text(note).font(.footnote)
                }
            }
        }
        .navigationTitle(finding.title)
    }
}

// MARK: - Binaries

struct BinaryListView: View {
    let report: Report

    private var growth: [BinaryInfo] {
        report.binaries
            .map { ($0, $0.archs.reduce(0) { $0 + $1.segments.reduce(0) { $0 + $1.fileSize } }) }
            .sorted { $0.1 > $1.1 }
            .map(\.0)
    }

    var body: some View {
        List {
            ForEach(growth) { binary in
                NavigationLink {
                    BinaryDetailView(binary: binary)
                } label: {
                    VStack(alignment: .leading, spacing: 3) {
                        Text((binary.path as NSString).lastPathComponent)
                            .font(.subheadline.weight(.semibold))
                        Text(binary.path).font(.caption2.monospaced()).foregroundStyle(.secondary)
                        HStack(spacing: 6) {
                            ForEach(binary.archs, id: \.self) { arch in
                                Text(arch.cpu).font(.caption2)
                                    .padding(.horizontal, 5).padding(.vertical, 1)
                                    .background(Color.secondary.opacity(0.15), in: Capsule())
                            }
                            if binary.isEncrypted {
                                Text("encrypted").font(.caption2).foregroundStyle(.red)
                            }
                        }
                    }
                }
            }
            if report.binaries.isEmpty {
                ContentUnavailableView("No Mach-O files parsed",
                                       systemImage: "doc.questionmark",
                                       description: Text("The bundle may contain only resources, or the binaries could not be read."))
            }
        }
        .navigationTitle("Binaries")
    }
}

struct BinaryDetailView: View {
    let binary: BinaryInfo

    var body: some View {
        List {
            Section("Path") {
                Text(binary.path).font(.caption.monospaced()).textSelection(.enabled)
            }
            ForEach(Array(binary.archs.enumerated()), id: \.offset) { index, arch in
                Section(binary.archs.count > 1 ? "Slice \(index + 1): \(arch.cpu)" : "Architecture") {
                    LabeledContent("CPU", value: arch.cpu)
                    LabeledContent("Word size", value: arch.is64Bit ? "64-bit" : "32-bit")
                    if let platform = arch.platform { LabeledContent("Platform", value: platform) }
                    if let minOS = arch.minOS { LabeledContent("Minimum OS", value: minOS) }
                    if let sdk = arch.sdk { LabeledContent("SDK", value: sdk) }
                    if let uuid = arch.uuid { Text(uuid).font(.caption.monospaced()).textSelection(.enabled) }
                    LabeledContent("Encryption", value: encryptionLabel(arch))
                    if !arch.segments.isEmpty {
                        DisclosureGroup("Segments (\(arch.segments.count))") {
                            ForEach(arch.segments, id: \.name) { segment in
                                VStack(alignment: .leading, spacing: 3) {
                                    HStack {
                                        Text(segment.name).font(.footnote.weight(.semibold))
                                        Spacer()
                                        Text(ByteCountFormatter.string(fromByteCount: Int64(segment.fileSize), countStyle: .file))
                                            .font(.caption2)
                                    }
                                    Text("prot \(protLabel(segment)) · \(segment.sections.count) sections"
                                         + (segment.truncated ? " · TRUNCATED" : ""))
                                        .font(.caption2)
                                        .foregroundStyle(segment.truncated ? .red : .secondary)
                                }
                            }
                        }
                    }
                    if !arch.dylibs.isEmpty {
                        DisclosureGroup("Linked libraries (\(arch.dylibs.count))") {
                            ForEach(arch.dylibs, id: \.self) { lib in
                                VStack(alignment: .leading) {
                                    Text((lib as NSString).lastPathComponent).font(.footnote)
                                    Text(lib).font(.caption2.monospaced()).foregroundStyle(.secondary)
                                }
                            }
                        }
                    }
                    if !arch.rpaths.isEmpty {
                        DisclosureGroup("Runtime search paths") {
                            ForEach(arch.rpaths, id: \.self) { Text($0).font(.caption.monospaced()) }
                        }
                    }
                    if let entitlements = arch.entitlementsXML {
                        DisclosureGroup("Entitlements") {
                            Text(entitlements).font(.caption2.monospaced()).textSelection(.enabled)
                        }
                    }
                    if !arch.warnings.isEmpty {
                        ForEach(arch.warnings, id: \.self) { warning in
                            Text(warning).font(.caption).foregroundStyle(.orange)
                        }
                    }
                }
            }
        }
        .navigationTitle((binary.path as NSString).lastPathComponent)
    }

    private func encryptionLabel(_ arch: ArchInfo) -> String {
        switch arch.encrypted {
        case .some(true): return "FairPlay encrypted (cryptid \(arch.cryptID ?? 0))"
        case .some(false): return "not encrypted"
        case .none: return "no encryption load command"
        }
    }

    private func protLabel(_ segment: SegmentInfo) -> String {
        var parts: [String] = []
        if segment.maxProt & 0x1 != 0 { parts.append("r") }
        if segment.maxProt & 0x2 != 0 { parts.append("w") }
        if segment.maxProt & 0x4 != 0 { parts.append("x") }
        return parts.isEmpty ? "-" : parts.joined()
    }
}

// MARK: - Files

struct FileInventoryView: View {
    let report: Report
    @State private var query = ""

    private var filtered: [FileEntry] {
        guard !query.isEmpty else { return report.files }
        return report.files.filter { $0.path.localizedCaseInsensitiveContains(query) }
    }

    var body: some View {
        List {
            Section {
                Text("\(report.files.count) files, \(ByteCountFormatter.string(fromByteCount: report.totalBytes, countStyle: .file)) total")
                    .font(.footnote)
                    .foregroundStyle(.secondary)
            }
            ForEach(filtered, id: \.path) { file in
                HStack(alignment: .firstTextBaseline) {
                    VStack(alignment: .leading, spacing: 2) {
                        Text((file.path as NSString).lastPathComponent).font(.footnote)
                        Text(file.path).font(.caption2.monospaced()).foregroundStyle(.secondary).lineLimit(2)
                    }
                    Spacer(minLength: 8)
                    Text(ByteCountFormatter.string(fromByteCount: file.size, countStyle: .file))
                        .font(.caption2).foregroundStyle(.secondary)
                }
            }
        }
        .searchable(text: $query, prompt: "Filter by path")
        .navigationTitle("Files")
    }
}

// MARK: - URLs and hosts

struct URLListView: View {
    let report: Report
    @State private var query = ""

    private var filtered: [String] {
        guard !query.isEmpty else { return report.urls }
        return report.urls.filter { $0.localizedCaseInsensitiveContains(query) }
    }

    var body: some View {
        List {
            if report.urls.isEmpty {
                Section {
                    Text("No URL literals were found. This is expected for an encrypted binary: its strings are not readable on disk.")
                        .font(.footnote).foregroundStyle(.secondary)
                }
            }
            ForEach(filtered, id: \.self) { url in
                Text(url).font(.caption.monospaced()).textSelection(.enabled)
            }
        }
        .searchable(text: $query, prompt: "Filter URLs")
        .navigationTitle("URLs")
    }
}

struct HostListView: View {
    let report: Report

    var body: some View {
        List {
            ForEach(report.domains, id: \.self) { host in
                HStack {
                    Text(host).font(.callout.monospaced())
                    Spacer()
                    Text("\(report.urls.filter { URL(string: $0)?.host?.lowercased() == host }.count)")
                        .font(.caption2).foregroundStyle(.secondary)
                }
            }
            if report.domains.isEmpty {
                ContentUnavailableView("No hosts found", systemImage: "network.slash",
                                       description: Text("URL literals are only readable in unencrypted binaries and text resources."))
            }
        }
        .navigationTitle("Hosts")
    }
}

// MARK: - Log

struct LogView: View {
    @EnvironmentObject private var session: AnalysisSession

    var body: some View {
        List {
            ForEach(Array(session.log.enumerated()), id: \.offset) { _, line in
                Text(line).font(.caption.monospaced())
            }
            if session.log.isEmpty {
                Text("Nothing yet.").foregroundStyle(.secondary)
            }
        }
        .navigationTitle("Evidence log")
    }
}
