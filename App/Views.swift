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
    @State private var openError: String?

    var body: some View {
        NavigationStack {
            if session.outcome != nil {
                ModuleHomeView()
            } else {
                InputView(externalError: openError)
            }
        }
        // Files → Share → “IPA Inspector”, “Open in IPA Inspector”, and
        // AirDrop all arrive here. Without this handler the share sheet may
        // list the app but handing a file over did nothing — which is exactly
        // how a 230 MB IPA “never loads into the app”.
        .onOpenURL { url in
            openError = nil
            switch InputValidator.validate(url: url) {
            case .accepted(let name):
                session.analyse(ipaURL: url, displayName: name)
            case .rejected(let message):
                openError = message
            }
        }
        .environmentObject(session)
        .tint(DesignSystem.accent)
    }
}

// MARK: - Input screen (App Store lookup + IPA import)

struct InputView: View {
    var externalError: String? = nil
    @EnvironmentObject private var session: AnalysisSession
    @State private var link = ""
    @State private var importing = false
    @State private var importError: String?
    /// Declared in project.yml as UTExportedTypeDeclarations; resolving it by
    /// identifier keeps the picker and the document types in sync.
    private let ipaType = UTType("com.yourname.ipainspector.ipa")
    /// The widest possible net: our declared IPA type, the system ZIP types,
    /// and finally .item so nothing in the picker is ever greyed out.
    private var importTypes: [UTType] {
        var types: [UTType] = []
        if let ipaType { types.append(ipaType) }
        types.append(contentsOf: [.zip, .data, .archive, .item])
        return types
    }

    var body: some View {
        ScrollView {
            VStack(spacing: DesignSystem.Spacing.m) {
                hero

                ModuleCard(title: "App Store link", systemImage: "magnifyingglass",
                           subtitle: "Returns public listing data only. A store link never provides the app binary.") {
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
                    .pickerStyle(.menu)
                    .disabled(session.isRunning)
                    Button(action: lookup) {
                        Label("Look up listing", systemImage: "magnifyingglass")
                    }
                    .buttonStyle(.borderedProminent)
                    .disabled(session.isRunning || link.trimmingCharacters(in: .whitespaces).isEmpty)
                }

                ModuleCard(title: "IPA file", systemImage: "square.and.arrow.down",
                           subtitle: "Analysis runs on this device. Nothing is uploaded anywhere.") {
                    Button {
                        importing = true
                    } label: {
                        Label("Import IPA…", systemImage: "doc.badge.plus")
                    }
                    .buttonStyle(.borderedProminent)

                    if session.isRunning {
                        VStack(alignment: .leading, spacing: DesignSystem.Spacing.xs) {
                            ProgressView(value: session.progressFraction)
                            Text(progressLabel)
                                .font(.footnote)
                                .foregroundStyle(.secondary)
                            Button(role: .destructive, action: session.cancel) {
                                Label("Cancel", systemImage: "xmark.circle")
                            }
                            .font(.footnote)
                        }
                    } else {
                        Text("Supports packages of 1 GB and more. Copying and analysis run in the background with live progress — the file is never loaded into memory in one piece.")
                            .font(.footnote)
                            .foregroundStyle(.secondary)
                    }

                    if !session.log.isEmpty {
                        VStack(alignment: .leading, spacing: 2) {
                            Text("Activity")
                                .font(.caption.weight(.semibold))
                                .foregroundStyle(.secondary)
                            ForEach(session.log.suffix(4), id: \.self) { line in
                                Text(line)
                                    .font(.caption2.monospaced())
                                    .foregroundStyle(.secondary)
                                    .lineLimit(2)
                            }
                        }
                        .frame(maxWidth: .infinity, alignment: .leading)
                        .accessibilityElement(children: .combine)
                    }
                }

                if case .failed(let message) = session.phase {
                    errorCard("Error", message)
                }
                if case .cancelled = session.phase {
                    errorCard("Cancelled", "The run was stopped and temporary files were removed.")
                }
                if let importError {
                    errorCard("Import", importError)
                }
                if let externalError {
                    errorCard("Import", externalError)
                }

                if let report = session.activeReport {
                    ModuleCard(title: "Results", systemImage: "list.bullet.clipboard") {
                        NavigationLink {
                            ReportSummaryView(report: report)
                        } label: {
                            VStack(alignment: .leading, spacing: 4) {
                                Text(report.name).font(.headline)
                                Text(resultSubtitle(report))
                                    .font(.caption).foregroundStyle(.secondary)
                            }
                        }
                    }
                } else if !session.isRunning {
                    ModuleCard(title: "How it works", systemImage: "info.circle") {
                        Text("Static analysis only. Encrypted (FairPlay) executables are reported as blocked rather than guessed at, and nothing here decrypts them. Import an IPA you are authorised to analyse.")
                            .font(.footnote)
                            .foregroundStyle(.secondary)
                    }
                }
            }
            .padding(DesignSystem.Spacing.m)
        }
        .background(Color(.systemGroupedBackground))
        .navigationTitle("IPA Inspector")
        .fileImporter(
            isPresented: $importing,
            allowedContentTypes: importTypes,
            allowsMultipleSelection: false
        ) { result in
            importError = nil
            switch result {
            case .success(let urls):
                guard let url = urls.first else { return }
                // Content-based validation: a real ZIP container is accepted
                // whatever its name, so nothing importable is refused here.
                switch InputValidator.validate(url: url) {
                case .accepted(let name):
                    session.analyse(ipaURL: url, displayName: name)
                case .rejected(let message):
                    importError = message
                }
            case .failure(let error):
                importError = error.localizedDescription
            }
        }
    }

    private func resultSubtitle(_ report: Report) -> String {
        if report.source == "App Store" {
            return "\(report.findings.count) listing details · import an IPA for binary analysis"
        }
        return "\(report.findings.count) findings · \(report.fileCount) files"
    }

    private var hero: some View {
        VStack(spacing: DesignSystem.Spacing.s) {
            Image(systemName: "cpu")
                .font(.system(size: 44, weight: .medium))
                .foregroundStyle(DesignSystem.accent)
            Text("IPA Inspector")
                .font(.title2.weight(.semibold))
            Text("Static security analysis for iOS apps: Mach-O, SDKs, signing, secrets, MASVS checks — all on device.")
                .font(.footnote)
                .foregroundStyle(.secondary)
                .multilineTextAlignment(.center)
        }
        .padding(.top, DesignSystem.Spacing.l)
        .accessibilityElement(children: .combine)
    }

    private var progressLabel: String {
        if case .running(let message) = session.phase { return message }
        return session.progressStage.isEmpty ? "Working…" : session.progressStage
    }

    private func errorCard(_ title: String, _ message: String) -> some View {
        ModuleCard(title: title, systemImage: "exclamationmark.triangle") {
            Text(message)
                .font(.callout)
                .foregroundStyle(.red)
        }
    }

    private func lookup() {
        let trimmed = link.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty else { return }
        session.lookup(trimmed)
    }
}

// MARK: - Module home (12-module navigation, requirement R)

struct ModuleHomeView: View {
    @EnvironmentObject private var session: AnalysisSession

    var body: some View {
        Group {
            if let outcome = session.outcome {
                ModuleList(outcome: outcome)
            } else {
                EmptyStateView(title: "No analysis yet",
                               systemImage: "doc.questionmark",
                               description: "Import an IPA to begin.")
            }
        }
        .navigationTitle(session.outcome?.report.name ?? "Overview")
        .navigationBarTitleDisplayMode(.inline)
        .toolbar {
            ToolbarItem(placement: .topBarLeading) {
                Button {
                    session.reset()
                } label: {
                    Label("New analysis", systemImage: "arrow.counterclockwise")
                }
            }
        }
    }
}

private struct ModuleList: View {
    let outcome: AnalysisEngine.Outcome
    @EnvironmentObject private var session: AnalysisSession
    @State private var showSearch = false

    var body: some View {
        List {
            Section {
                NavigationLink { DashboardView(outcome: outcome) } label: {
                    ModuleTile(title: "Overview",
                               systemImage: "gauge.with.dots.needle.bottom.50percent",
                               detail: dashboardDetail,
                               tint: DesignSystem.accent)
                }
            }

            Section("Analysis") {
                NavigationLink { FileExplorerView(outcome: outcome) } label: {
                    ModuleTile(title: "File Explorer", systemImage: "folder",
                               detail: "\(outcome.report.fileCount) files")
                }
                NavigationLink { MachOHomeView(outcome: outcome) } label: {
                    ModuleTile(title: "Mach-O", systemImage: "wrench.and.screwdriver",
                               detail: "\(outcome.report.binaries.count) binaries",
                               tint: .purple)
                }
                NavigationLink { SwiftMetadataHomeView(outcome: outcome) } label: {
                    ModuleTile(title: "Swift Metadata", systemImage: "swift",
                               detail: swiftDetail, tint: .orange)
                }
                NavigationLink { ObjCMetadataHomeView(outcome: outcome) } label: {
                    ModuleTile(title: "Objective-C", systemImage: "c.circle",
                               detail: objcDetail, tint: .mint)
                }
                NavigationLink { SymbolsHomeView(outcome: outcome) } label: {
                    ModuleTile(title: "Symbols", systemImage: "textformat.123",
                               detail: symbolDetail, tint: .indigo)
                }
                NavigationLink { StringsHomeView(outcome: outcome) } label: {
                    ModuleTile(title: "Strings", systemImage: "text.quote",
                               detail: "strings corpus", tint: .brown)
                }
                NavigationLink { DependenciesView(outcome: outcome) } label: {
                    ModuleTile(title: "Dependencies", systemImage: "link",
                               detail: dependencyDetail, tint: .cyan)
                }
            }

            Section("Security") {
                NavigationLink { SecurityHomeView(outcome: outcome) } label: {
                    ModuleTile(title: "Security", systemImage: "shield.lefthalf.filled",
                               detail: securityDetail, tint: .red)
                }
                NavigationLink { SDKInventoryView(outcome: outcome) } label: {
                    ModuleTile(title: "SDK Inventory", systemImage: "shippingbox",
                               detail: sdkDetail, tint: .teal)
                }
                NavigationLink { SigningHomeView(outcome: outcome) } label: {
                    ModuleTile(title: "Signing and Entitlements", systemImage: "signature",
                               detail: signingDetail, tint: .green)
                }
            }

            Section("Output") {
                NavigationLink { ReportsView(outcome: outcome) } label: {
                    ModuleTile(title: "Reports", systemImage: "doc.richtext",
                               detail: "JSON · PDF · CSV · TXT · ZIP", tint: .gray)
                }
            }
        }
        .toolbar {
            ToolbarItem(placement: .topBarTrailing) {
                NavigationLink { CrossBinarySearchView(outcome: outcome) } label: {
                    Label("Search", systemImage: "magnifyingglass")
                }
                .accessibilityLabel("Cross-binary search")
            }
        }
    }

    private var dashboardDetail: String {
        let d = outcome.dashboard
        return "\(outcome.report.fileCount) files · \(d?.securityFindingCount ?? 0) security findings"
    }
    private var swiftDetail: String {
        "mangled types & metadata sections"
    }
    private var objcDetail: String {
        "classes, methods, categories"
    }
    private var symbolDetail: String {
        "\(outcome.symbols.values.reduce(0) { $0 + $1.count }) symbols"
    }
    private var dependencyDetail: String {
        "\(outcome.sdk?.totalDetected ?? 0) SDKs · \(outcome.report.domains.count) hosts"
    }
    private var securityDetail: String {
        let critical = outcome.security.filter { $0.severity == .critical }.count
        let high = outcome.security.filter { $0.severity == .high }.count
        return "\(outcome.security.count) findings · \(critical) critical · \(high) high"
    }
    private var sdkDetail: String {
        "\(outcome.sdk?.totalDetected ?? 0) detected SDKs"
    }
    private var signingDetail: String {
        outcome.signing?.profile.present == true ? "profile present" : "no embedded profile"
    }
}
