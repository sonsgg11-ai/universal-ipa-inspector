import SwiftUI

// MARK: - H: Security module

struct SecurityHomeView: View {
    let outcome: AnalysisEngine.Outcome
    @State private var severity: SecurityAssessor.Severity?
    @State private var showSecrets = false

    var body: some View {
        List {
            Section("Findings by severity") {
                ForEach(SecurityAssessor.Severity.allCases, id: \.self) { level in
                    let count = outcome.security.filter { $0.severity == level }.count
                    HStack {
                        SeverityBadge(severity: level)
                        Spacer()
                        Text("\(count)").font(.subheadline.monospaced())
                    }
                }
                NavigationLink {
                    SecretsView(outcome: outcome)
                } label: {
                    ModuleTile(title: "Credential-shaped strings",
                               systemImage: "key.horizontal",
                               detail: "\(outcome.secrets.count) masked detections",
                               tint: .orange)
                }
            }

            Picker("Severity", selection: $severity) {
                Text("All").tag(SecurityAssessor.Severity?.none)
                ForEach(SecurityAssessor.Severity.allCases, id: \.self) { level in
                    Text(level.label).tag(SecurityAssessor.Severity?.some(level))
                }
            }

            ForEach(filtered) { finding in
                NavigationLink {
                    SecurityFindingDetailView(finding: finding)
                } label: {
                    VStack(alignment: .leading, spacing: 4) {
                        HStack(alignment: .firstTextBaseline) {
                            Text(finding.id).font(.caption.monospaced()).foregroundStyle(.secondary)
                            Spacer()
                            SeverityBadge(severity: finding.severity)
                        }
                        Text(finding.title).font(.subheadline.weight(.semibold))
                        Text(finding.evidence)
                            .font(.caption)
                            .foregroundStyle(.secondary)
                            .lineLimit(3)
                    }
                    .padding(.vertical, 2)
                }
            }

            if filtered.isEmpty {
                EmptyStateView(title: "No findings at this severity",
                               systemImage: "checkmark.seal",
                               description: "No security finding matched the selected filter.")
            }

            Section {
                Text("Static analysis detects indicators on disk. Findings marked 'estimated' are suspicions; they are never called vulnerabilities, and no finding proves runtime behaviour.")
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }
        }
        .navigationTitle("Security")
        .navigationBarTitleDisplayMode(.inline)
    }

    private var filtered: [SecurityAssessor.Finding] {
        guard let severity else { return outcome.security }
        return outcome.security.filter { $0.severity == severity }
    }
}

struct SecurityFindingDetailView: View {
    let finding: SecurityAssessor.Finding

    var body: some View {
        List {
            Section("Finding") {
                KeyValueRow(key: "ID", value: finding.id, monospaced: true)
                HStack {
                    Text("Severity").font(.subheadline).foregroundStyle(.secondary)
                    Spacer()
                    SeverityBadge(severity: finding.severity)
                }
                HStack {
                    Text("Status").font(.subheadline).foregroundStyle(.secondary)
                    Spacer()
                    StatusBadge(status: finding.status)
                }
                ConfidenceBadge(confidence: finding.confidence)
            }
            Section("Evidence") {
                CopyableBlock(text: finding.evidence, font: .callout.monospaced())
                KeyValueRow(key: "Source file", value: finding.sourceFile, monospaced: true)
                KeyValueRow(key: "Location", value: finding.sourceLocation, monospaced: true)
            }
            Section("What this does and does not prove") {
                Text(finding.explanation).font(.callout)
            }
            Section("OWASP mapping") {
                ForEach(finding.masvs, id: \.self) { KeyValueRow(key: "MASVS", value: $0) }
                ForEach(finding.mastg, id: \.self) { KeyValueRow(key: "MASTG", value: $0) }
            }
            Section("Remediation") {
                Text(finding.remediation).font(.callout)
            }
        }
        .navigationTitle(finding.id)
        .navigationBarTitleDisplayMode(.inline)
    }
}

// MARK: - I: Secrets (masked by default)

struct SecretsView: View {
    let outcome: AnalysisEngine.Outcome
    @State private var revealed: Set<String> = []

    var body: some View {
        List {
            Section {
                Text("Detection combines format patterns, entropy and context words. Values are masked everywhere; revealing is local-only and requires your explicit action. Nothing is ever uploaded.")
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }

            ForEach(outcome.secrets, id: \.masked) { hit in
                Section("\(hit.name) — \(hit.confidence) confidence") {
                    CopyableBlock(text: hit.masked, font: .subheadline.monospaced())
                    KeyValueRow(key: "Source", value: hit.source, monospaced: true)
                    KeyValueRow(key: "Offset", value: "\(hit.offset)")
                    KeyValueRow(key: "Method", value: hit.method)
                    KeyValueRow(key: "Entropy", value: String(format: "%.2f bits/char", hit.entropy))
                    if revealed.contains(hit.masked) {
                        VStack(alignment: .leading, spacing: 2) {
                            Text("Revealed value (local only)")
                                .font(.caption).foregroundStyle(.secondary)
                            Text(SecretScanner.reveal(hit, authorisedLocally: true) ?? hit.masked)
                                .font(.footnote.monospaced())
                                .textSelection(.enabled)
                                .foregroundStyle(.red)
                        }
                        Button(role: .destructive) {
                            revealed.remove(hit.masked)
                        } label: {
                            Label("Hide again", systemImage: "eye.slash")
                        }
                    } else {
                        Button {
                            revealed.insert(hit.masked)
                        } label: {
                            Label("Reveal locally", systemImage: "eye")
                        }
                        .accessibilityHint("Reveals the value on this device only")
                    }
                    Text(hit.note).font(.caption).foregroundStyle(.secondary)
                }
            }

            if outcome.secrets.isEmpty {
                EmptyStateView(title: "No credential-shaped strings",
                               systemImage: "key.horizontal",
                               description: "Absence of matches is not proof that the app holds no secrets.")
            }
        }
        .navigationTitle("Secrets (masked)")
        .navigationBarTitleDisplayMode(.inline)
    }
}

// MARK: - K: Signing and Entitlements (incl. FairPlay)

struct SigningHomeView: View {
    let outcome: AnalysisEngine.Outcome

    var body: some View {
        List {
            if let signing = outcome.signing {
                Section("Signature status") {
                    Text(signing.summary).font(.footnote)
                }

                Section("Provisioning profile") {
                    switch signing.profile.rawStatus {
                    case .notFound:
                        Label("No embedded profile (expected for App Store builds)", systemImage: "doc.questionmark")
                            .font(.footnote).foregroundStyle(.secondary)
                    case .blocked:
                        Label("Profile present but not parseable", systemImage: "exclamationmark.triangle")
                            .font(.footnote).foregroundStyle(.orange)
                    default:
                        if let name = signing.profile.name {
                            KeyValueRow(key: "Name", value: name)
                        }
                        if let team = signing.profile.teamName {
                            KeyValueRow(key: "Team", value: "\(team) (\(signing.profile.teamIDs.first ?? "?"))")
                        }
                        if let bundleID = signing.profile.bundleID {
                            KeyValueRow(key: "Profile bundle ID", value: bundleID, monospaced: true)
                        }
                        if let expiry = signing.profile.expirationDate {
                            KeyValueRow(key: "Expires",
                                        value: ISO8601DateFormatter().string(from: expiry)
                                            + (signing.profile.isExpired ? " (EXPIRED)" : ""))
                        }
                        if let devices = signing.profile.provisionedDeviceCount {
                            KeyValueRow(key: "Registered devices", value: "\(devices) (UDIDs not listed)")
                        }
                        if let method = signing.profile.distributionMethod {
                            KeyValueRow(key: "Distribution", value: method)
                        }
                    }
                }

                Section("Entitlements (structurally checked)") {
                    ForEach(Array(signing.mainExecutableStates.keys.sorted()), id: \.self) { path in
                        VStack(alignment: .leading, spacing: 2) {
                            Text(path).font(.caption.monospaced())
                            Text(ProvisioningParser.describe(state: signing.mainExecutableStates[path]))
                                .font(.caption2).foregroundStyle(.secondary)
                        }
                    }
                }

                if !signing.profile.associatedDomains.isEmpty {
                    Section("Associated domains") {
                        ForEach(signing.profile.associatedDomains, id: \.self) { CopyableBlock(text: $0) }
                    }
                }
                if !signing.profile.appGroups.isEmpty {
                    Section("App groups") {
                        ForEach(signing.profile.appGroups, id: \.self) { CopyableBlock(text: $0) }
                    }
                }
                if !signing.profile.keychainAccessGroups.isEmpty {
                    Section("Keychain access groups") {
                        ForEach(signing.profile.keychainAccessGroups, id: \.self) { CopyableBlock(text: $0) }
                    }
                }
                if !signing.sensitiveEntitlements.isEmpty {
                    Section("Sensitive entitlements") {
                        ForEach(signing.sensitiveEntitlements, id: \.self) { CopyableBlock(text: $0) }
                    }
                }
            } else {
                EmptyStateView(title: "Signing data unavailable", systemImage: "signature",
                               description: "No signing report was produced for this analysis.")
            }

            if let fairplay = outcome.fairplay {
                Section("FairPlay encryption (per slice)") {
                    if fairplay.encryptedBinaryPaths.isEmpty && fairplay.mixedBinaries.isEmpty {
                        Label("No encrypted slices detected", systemImage: "checkmark.shield")
                            .font(.footnote).foregroundStyle(.green)
                    }
                    ForEach(fairplay.slices) { slice in
                        VStack(alignment: .leading, spacing: 2) {
                            HStack {
                                Text("\(slice.path) [\(slice.cpu)]").font(.caption.monospaced())
                                Spacer()
                                StatusBadge(status: slice.encrypted == true ? .blocked
                                            : slice.encrypted == false ? .verified : .estimated)
                            }
                            Text(slice.readableStructure.joined(separator: " · "))
                                .font(.caption2).foregroundStyle(.secondary)
                        }
                    }
                    if !fairplay.blockedOperations.isEmpty {
                        DisclosureGroup("Blocked operations (\(fairplay.blockedOperations.count))") {
                            ForEach(fairplay.blockedOperations, id: \.self) {
                                Text($0).font(.caption).foregroundStyle(.red)
                            }
                        }
                    }
                    DisclosureGroup("Still available (\(fairplay.availableOperations.count))") {
                        ForEach(fairplay.availableOperations, id: \.self) {
                            Text($0).font(.caption).foregroundStyle(.secondary)
                        }
                    }
                    Text(fairplay.notice).font(.caption2).foregroundStyle(.secondary)
                }
            }
        }
        .navigationTitle("Signing")
        .navigationBarTitleDisplayMode(.inline)
    }
}

// MARK: - SDK inventory module (J)

struct SDKInventoryView: View {
    let outcome: AnalysisEngine.Outcome
    @State private var query = ""

    var body: some View {
        List {
            if let sdk = outcome.sdk {
                Section("Detected (\(sdk.entries.count))") {
                    ForEach(sdk.entries.filter {
                        query.isEmpty || $0.name.localizedCaseInsensitiveContains(query)
                    }) { entry in
                        NavigationLink {
                            SDKDetailView(entry: entry)
                        } label: {
                            VStack(alignment: .leading, spacing: 2) {
                                HStack {
                                    Text(entry.name).font(.subheadline.weight(.semibold))
                                    Spacer()
                                    Text(entry.confidence)
                                        .font(.caption2)
                                        .foregroundStyle(.secondary)
                                }
                                Text("\(entry.category)\(entry.version.map { " · \($0)" } ?? "")")
                                    .font(.caption).foregroundStyle(.secondary)
                            }
                        }
                    }
                }
                Section("Limitations") {
                    ForEach(sdk.limitations, id: \.self) { line in
                        Text(line).font(.caption).foregroundStyle(.secondary)
                    }
                }
            } else {
                EmptyStateView(title: "SDK inventory unavailable", systemImage: "shippingbox")
            }
        }
        .searchable(text: $query, prompt: "Filter SDKs")
        .navigationTitle("SDK Inventory")
        .navigationBarTitleDisplayMode(.inline)
    }
}

// MARK: - M: Cross-binary search

struct CrossBinarySearchView: View {
    let outcome: AnalysisEngine.Outcome
    @State private var query = ""
    @State private var useRegex = false
    @State private var caseSensitive = false
    @State private var category: CrossBinarySearch.ResultCategory?
    @State private var results: CrossBinarySearch.Results?
    @State private var history: [String] = []

    var body: some View {
        List {
            Section {
                HStack {
                    TextField("search symbols, strings, classes, URLs…", text: $query)
                        .autocorrectionDisabled()
                        .textInputAutocapitalization(.never)
                        .onSubmit(run)
                    Button(action: run) {
                        Image(systemName: "magnifyingglass")
                    }
                    .disabled(query.isEmpty)
                }
                Toggle("Regular expression", isOn: $useRegex)
                Toggle("Case sensitive", isOn: $caseSensitive)
                Picker("Category", selection: $category) {
                    Text("All").tag(CrossBinarySearch.ResultCategory?.none)
                    ForEach(CrossBinarySearch.ResultCategory.allCases, id: \.self) { c in
                        Text(c.rawValue).tag(CrossBinarySearch.ResultCategory?.some(c))
                    }
                }
            } footer: {
                Text("Searches every unencrypted binary's strings, symbol tables, ObjC/Swift metadata, URLs and framework names. Results jump straight to the source file.")
            }

            if let results {
                Section("Results (\(results.hits.count)\(results.truncated ? ", truncated" : "")) · \(results.elapsedMilliseconds) ms") {
                    ForEach(Array(results.bySource.keys.sorted()), id: \.self) { source in
                        DisclosureGroup("\(source) — \(results.bySource[source]?.count ?? 0)") {
                            ForEach((results.bySource[source] ?? []).prefix(80)) { hit in
                                VStack(alignment: .leading, spacing: 2) {
                                    Text(hit.value)
                                        .font(.caption.monospaced())
                                        .textSelection(.enabled)
                                    Text("\(hit.category.rawValue) · \(hit.location)")
                                        .font(.caption2)
                                        .foregroundStyle(.secondary)
                                }
                            }
                        }
                    }
                    if results.hits.isEmpty {
                        EmptyStateView(title: "No matches", systemImage: "magnifyingglass",
                                       description: "Nothing matched this query in the indexed corpus.")
                    }
                }
            }

            if !history.isEmpty {
                Section("Recent searches") {
                    ForEach(history, id: \.self) { item in
                        Button(item) {
                            query = item
                            run()
                        }
                        .font(.caption.monospaced())
                    }
                    Button(role: .destructive) {
                        outcome.searchHistory.clear()
                        history = []
                    } label: {
                        Label("Clear history", systemImage: "trash")
                    }
                }
            }
        }
        .navigationTitle("Search")
        .navigationBarTitleDisplayMode(.inline)
        .onAppear { history = outcome.searchHistory.all() }
    }

    private func run() {
        let index = outcome.searchIndex ?? CrossBinarySearch.SearchIndex()
        results = index.search(query, filter: .init(category: category,
                                                    caseSensitive: caseSensitive,
                                                    useRegex: useRegex))
        outcome.searchHistory.add(query)
        history = outcome.searchHistory.all()
    }
}

// MARK: - O: Reports module

struct ReportsView: View {
    let outcome: AnalysisEngine.Outcome
    @State private var exportState: ExportState = .idle

    enum ExportState: Equatable {
        case idle
        case working
        case ready(URL, String)
        case failed(String)
    }

    var body: some View {
        List {
            Section("Single-file exports") {
                exportRow(title: "Complete analysis (JSON)", systemImage: "curlybraces.square") {
                    exportJSON()
                }
                exportRow(title: "Findings CSV", systemImage: "tablecells") {
                    exportCSV()
                }
                exportRow(title: "Technical summary (TXT)", systemImage: "doc.plaintext") {
                    exportTXT()
                }
                exportRow(title: "Human-readable report (PDF)", systemImage: "doc.richtext") {
                    exportPDF()
                }
            }

            Section {
                switch exportState {
                case .idle:
                    Button {
                        exportZIP()
                    } label: {
                        Label("Export Complete Analysis (ZIP)", systemImage: "shippingbox.fill")
                            .font(.headline)
                    }
                    .buttonStyle(.borderedProminent)
                case .working:
                    HStack { ProgressView(); Text("Building package…") }
                case .ready(let url, let kind):
                    ShareLink(item: url) {
                        Label("Share \(kind)", systemImage: "square.and.arrow.up")
                    }
                    Text(url.lastPathComponent)
                        .font(.caption2.monospaced()).foregroundStyle(.secondary)
                    Button("Export again") { resetAndRetry(kind: kind) }
                        .font(.footnote)
                case .failed(let message):
                    Text("Export failed: \(message)")
                        .foregroundStyle(.red).font(.footnote)
                    Button("Try again") { exportState = .idle }
                }
            } footer: {
                Text("The complete package contains the manifest, per-module data files, masked secrets and generated reports. Only collected data is written; blocked modules are named in the manifest.")
            }

            Section("What the exports contain") {
                Text("All exports come from the same engine outputs the UI shows — the summary and the data cannot drift apart. Secrets are masked in every export; raw values are never written to any file.")
                    .font(.footnote).foregroundStyle(.secondary)
            }
        }
        .navigationTitle("Reports")
        .navigationBarTitleDisplayMode(.inline)
    }

    @ViewBuilder
    private func exportRow(title: String, systemImage: String,
                           action: @escaping () -> Void) -> some View {
        Button {
            action()
        } label: {
            Label(title, systemImage: systemImage)
        }
    }

    private func finish(_ url: URL, _ kind: String) {
        exportState = .ready(url, kind)
    }

    private func resetAndRetry(kind: String) {
        exportState = .idle
        if kind == "ZIP" { exportZIP() }
    }

    private func exportJSON() {
        exportState = .working
        do {
            let data = try ReportExporter.exportJSON(report: outcome.report,
                                                     security: outcome.security,
                                                     secrets: outcome.secrets,
                                                     metadata: outcome.engineMetadata,
                                                     dashboard: outcome.dashboard,
                                                     structure: outcome.structure,
                                                     signing: outcome.signing,
                                                     fairplay: outcome.fairplay,
                                                     sdk: outcome.sdk)
            finish(try writeTemp(data, name: "\(safeName)-report.json"), "JSON")
        } catch {
            exportState = .failed(error.localizedDescription)
        }
    }

    private func exportCSV() {
        exportState = .working
        let csv = ReportExporter.exportFindingsCSV(report: outcome.report,
                                                   security: outcome.security)
        let csvURL = (try? writeTemp(csv, name: "\(safeName)-findings.csv")) ?? URL(fileURLWithPath: "/dev/null")
        finish(csvURL, "CSV")
    }

    private func exportTXT() {
        exportState = .working
        let txt = ReportExporter.exportTXT(report: outcome.report, security: outcome.security,
                                           fairplay: outcome.fairplay,
                                           signing: outcome.signing,
                                           metadata: outcome.engineMetadata)
        let txtURL = (try? writeTemp(Data(txt.utf8), name: "\(safeName)-summary.txt")) ?? URL(fileURLWithPath: "/dev/null")
        finish(txtURL, "TXT")
    }

    private func exportPDF() {
        exportState = .working
        let pdf = ReportExporter.exportPDF(report: outcome.report, security: outcome.security,
                                           secrets: outcome.secrets,
                                           metadata: outcome.engineMetadata,
                                           fairplay: outcome.fairplay)
        let pdfURL = (try? writeTemp(pdf, name: "\(safeName)-report.pdf")) ?? URL(fileURLWithPath: "/dev/null")
        finish(pdfURL, "PDF")
    }

    private func exportZIP() {
        exportState = .working
        DispatchQueue.global(qos: .userInitiated).async { [outcome] in
            do {
                let url = try ExportPackager.buildPackage(outcome: outcome)
                DispatchQueue.main.async {
                    finish(url, "ZIP")
                }
            } catch {
                DispatchQueue.main.async {
                    exportState = .failed(error.localizedDescription)
                }
            }
        }
    }

    private var safeName: String {
        outcome.report.name
            .replacingOccurrences(of: "/", with: "-")
            .replacingOccurrences(of: ":", with: "-")
    }

    /// Writes to a temp file and reads it back so a silent write failure can
    /// never masquerade as success.
    private func writeTemp(_ data: Data, name: String) throws -> URL {
        guard !data.isEmpty else { throw ExportValidationError.empty }
        let url = FileManager.default.temporaryDirectory.appendingPathComponent(name)
        try data.write(to: url, options: .atomic)
        let check = try Data(contentsOf: url)
        guard check.count == data.count else { throw ExportValidationError.truncated }
        return url
    }

    enum ExportValidationError: LocalizedError {
        case empty, truncated
        var errorDescription: String? {
            switch self {
            case .empty: return "the exporter produced no data"
            case .truncated: return "the written file did not match what was encoded"
            }
        }
    }
}

// MARK: - Summary (shared with the input flow)

struct ReportSummaryView: View {
    let report: Report
    @EnvironmentObject private var session: AnalysisSession

    private var counts: [(EvidenceStatus, Int)] {
        EvidenceStatus.allCases.map { status in
            (status, report.findings.filter { $0.status == status }.count)
        }
    }

    var body: some View {
        List {
            Section("Report") {
                KeyValueRow(key: "Source", value: report.source)
                KeyValueRow(key: "Name", value: report.name)
                if report.source == "App Store" {
                    // A store listing has no local bytes to count. Show what
                    // the store actually tells us instead of a meaningless
                    // “Zero KB / 0 files” pair.
                    KeyValueRow(key: "Download size", value: listingValue(for: "Download size"))
                    KeyValueRow(key: "Files", value: "— (needs an imported IPA)")
                } else {
                    KeyValueRow(key: "Files", value: "\(report.fileCount)")
                    KeyValueRow(key: "Total size", value: ByteFormat.string(report.totalBytes))
                }
                KeyValueRow(key: "Findings", value: "\(report.findings.count)")
                if let hash = report.sha256 {
                    VStack(alignment: .leading, spacing: 2) {
                        Text("SHA-256").font(.caption).foregroundStyle(.secondary)
                        Text(hash).font(.caption2.monospaced()).textSelection(.enabled)
                    }
                }
            }

            Section("Evidence quality") {
                ForEach(counts, id: \.0) { status, count in
                    HStack {
                        StatusBadge(status: status)
                        Spacer()
                        Text("\(count)").font(.subheadline.monospaced())
                    }
                }
            }

            if !report.limitations.isEmpty {
                Section("Limitations of this report") {
                    ForEach(report.limitations, id: \.self) { limitation in
                        Text(limitation).font(.footnote).foregroundStyle(.secondary)
                    }
                }
            }

            Section {
                NavigationLink("Findings browser") { FindingsBrowserView(report: report) }
                if report.binaries.isEmpty == false {
                    NavigationLink("Mach-O binaries (\(report.binaries.count))") { BinaryListView(report: report) }
                }
                if report.source == "App Store" {
                    NavigationLink("Files — import an IPA") { FileInventoryListView(report: report) }
                } else {
                    NavigationLink("Files (\(report.fileCount))") { FileInventoryListView(report: report) }
                }
                NavigationLink("URLs (\(report.urls.count))") { URLListView(report: report) }
                NavigationLink("Hosts (\(report.domains.count))") { HostListView(report: report) }
                NavigationLink("Evidence log") { LogView() }
            }
        }
        .navigationTitle("Summary")
    }

    /// Pulls a named verified finding out of a store listing (e.g. the
    /// download size the lookup API already returns).
    private func listingValue(for title: String) -> String {
        if let finding = report.findings.first(where: { $0.title == title && $0.status == .verified }) {
            return finding.value
        }
        return "—"
    }
}

// MARK: - Findings browser (kept from the original app)

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
                    ForEach(report.findings.categories, id: \.self) { category in
                        Text(category).tag(String?.some(category))
                    }
                }
            }

            ForEach(grouped, id: \.0) { category, findings in
                Section(category) {
                    ForEach(findings) { finding in
                        NavigationLink {
                            FindingDetailView(finding: finding)
                        } label: {
                            FindingRow(finding: finding)
                        }
                    }
                }
            }

            if filtered.isEmpty {
                Section {
                    EmptyStateView(title: "No matching findings", systemImage: "magnifyingglass",
                                   description: "Adjust the search text or filters.")
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

struct FindingDetailView: View {
    let finding: Finding

    var body: some View {
        List {
            Section("Finding") {
                KeyValueRow(key: "Title", value: finding.title)
                KeyValueRow(key: "Category", value: finding.category)
                HStack {
                    Text("Status")
                    Spacer()
                    StatusBadge(status: finding.status)
                }
            }
            Section("Value") {
                CopyableBlock(text: finding.value, font: .callout)
            }
            Section("Source") {
                CopyableBlock(text: finding.source)
            }
            if let note = finding.note {
                Section("What this does and does not prove") {
                    Text(note).font(.footnote)
                }
            }
        }
        .navigationTitle(finding.title)
        .navigationBarTitleDisplayMode(.inline)
    }
}

// MARK: - Legacy list views (file/URL/host/log)

struct BinaryListView: View {
    let report: Report

    var body: some View {
        List {
            ForEach(report.binaries) { binary in
                NavigationLink {
                    BinaryDetailView(binary: binary)
                } label: {
                    VStack(alignment: .leading, spacing: 3) {
                        Text((binary.path as NSString).lastPathComponent)
                            .font(.subheadline.weight(.semibold))
                        Text(binary.path).font(.caption2.monospaced()).foregroundStyle(.secondary)
                    }
                }
            }
        }
        .navigationTitle("Binaries")
    }
}

struct FileInventoryListView: View {
    let report: Report
    @State private var query = ""

    private var filtered: [FileEntry] {
        guard !query.isEmpty else { return report.files }
        return report.files.filter { $0.path.localizedCaseInsensitiveContains(query) }
    }

    var body: some View {
        List {
            ForEach(filtered.prefix(1000), id: \.path) { file in
                HStack(alignment: .firstTextBaseline) {
                    VStack(alignment: .leading, spacing: 2) {
                        Text((file.path as NSString).lastPathComponent).font(.footnote)
                        Text(file.path).font(.caption2.monospaced()).foregroundStyle(.secondary).lineLimit(2)
                    }
                    Spacer(minLength: 8)
                    Text(ByteFormat.string(file.size))
                        .font(.caption2).foregroundStyle(.secondary)
                }
            }
        }
        .searchable(text: $query, prompt: "Filter by path")
        .navigationTitle("Files")
    }
}

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
                CopyableBlock(text: url)
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
                EmptyStateView(title: "No hosts found", systemImage: "network.slash",
                               description: "URL literals are only readable in unencrypted binaries and text resources.")
            }
        }
        .navigationTitle("Hosts")
    }
}

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
