import SwiftUI

// MARK: - Mach-O module

struct MachOHomeView: View {
    let outcome: AnalysisEngine.Outcome

    var body: some View {
        List {
            ForEach(outcome.report.binaries) { binary in
                NavigationLink {
                    BinaryDetailView(binary: binary)
                } label: {
                    VStack(alignment: .leading, spacing: 3) {
                        Text((binary.path as NSString).lastPathComponent)
                            .font(.subheadline.weight(.semibold))
                        Text(binary.path)
                            .font(.caption2.monospaced())
                            .foregroundStyle(.secondary)
                            .lineLimit(2)
                        HStack(spacing: 6) {
                            ForEach(binary.archs, id: \.cpu) { arch in
                                Text(arch.cpu)
                                    .font(.caption2)
                                    .padding(.horizontal, 5).padding(.vertical, 1)
                                    .background(Color.secondary.opacity(0.15), in: Capsule())
                            }
                            if binary.isEncrypted {
                                Text("encrypted")
                                    .font(.caption2.weight(.semibold))
                                    .foregroundStyle(.red)
                            }
                        }
                    }
                }
            }
            if outcome.report.binaries.isEmpty {
                EmptyStateView(title: "No Mach-O files parsed",
                               systemImage: "wrench.and.screwdriver",
                               description: "The bundle may contain only resources, or the binaries could not be read.")
            }
        }
        .navigationTitle("Mach-O")
        .navigationBarTitleDisplayMode(.inline)
    }
}

struct BinaryDetailView: View {
    let binary: BinaryInfo

    var body: some View {
        List {
            Section("Path") {
                CopyableBlock(text: binary.path)
            }
            ForEach(Array(binary.archs.enumerated()), id: \.offset) { index, arch in
                Section(binary.archs.count > 1 ? "Slice \(index + 1): \(arch.cpu)" : "Architecture") {
                    KeyValueRow(key: "CPU", value: arch.cpu)
                    KeyValueRow(key: "Word size", value: arch.is64Bit ? "64-bit" : "32-bit")
                    if let platform = arch.platform { KeyValueRow(key: "Platform", value: platform) }
                    if let minOS = arch.minOS { KeyValueRow(key: "Minimum OS", value: minOS) }
                    if let sdk = arch.sdk { KeyValueRow(key: "SDK", value: sdk) }
                    if let uuid = arch.uuid { CopyableBlock(text: uuid) }
                    KeyValueRow(key: "Encryption", value: encryptionLabel(arch))
                    if let size = arch.cryptSize, size > 0 {
                        KeyValueRow(key: "Encrypted range",
                                    value: "\(ByteFormat.string(Int64(size))) at offset \(arch.cryptOffset ?? 0)")
                    }
                    KeyValueRow(key: "Symbols", value: "\(arch.symbols.count)")

                    if !arch.segments.isEmpty {
                        DisclosureGroup("Segments (\(arch.segments.count))") {
                            ForEach(arch.segments, id: \.name) { segment in
                                VStack(alignment: .leading, spacing: 3) {
                                    HStack {
                                        Text(segment.name).font(.footnote.weight(.semibold))
                                        Spacer()
                                        Text(ByteFormat.string(Int64(segment.fileSize)))
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
                    if !arch.weakDylibs.isEmpty {
                        DisclosureGroup("Weak-linked (\(arch.weakDylibs.count))") {
                            ForEach(arch.weakDylibs, id: \.self) { Text($0).font(.caption.monospaced()) }
                        }
                    }
                    if !arch.rpaths.isEmpty {
                        DisclosureGroup("Runtime search paths") {
                            ForEach(arch.rpaths, id: \.self) { Text($0).font(.caption.monospaced()) }
                        }
                    }
                    if let entitlements = arch.entitlementsXML {
                        DisclosureGroup("Entitlements") {
                            CopyableBlock(text: entitlements)
                        }
                    }
                    if !arch.warnings.isEmpty {
                        ForEach(arch.warnings, id: \.self) { warning in
                            Label(warning, systemImage: "exclamationmark.triangle")
                                .font(.caption).foregroundStyle(.orange)
                        }
                    }
                }
            }
        }
        .navigationTitle((binary.path as NSString).lastPathComponent)
        .navigationBarTitleDisplayMode(.inline)
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

// MARK: - Symbols module

struct SymbolsHomeView: View {
    let outcome: AnalysisEngine.Outcome
    @State private var query = ""

    private var filtered: [(String, [SymbolEntry])] {
        outcome.symbols
            .map { (path, symbols) -> (String, [SymbolEntry]) in
                let list = query.isEmpty
                    ? symbols
                    : symbols.filter { $0.name.localizedCaseInsensitiveContains(query) }
                return (path, list)
            }
            .filter { !$0.1.isEmpty }
            .sorted { $0.0 < $1.0 }
    }

    var body: some View {
        List {
            ForEach(filtered, id: \.0) { path, symbols in
                Section("\(path) — \(symbols.count)") {
                    let imported = symbols.filter { $0.kind == .imported }
                    let exported = symbols.filter { $0.kind == .exported }
                    let local = symbols.filter { $0.kind == .local }
                    if !imported.isEmpty {
                        DisclosureGroup("Imported (\(imported.count))") {
                            ForEach(imported.prefix(300), id: \.self) { symbol in
                                CopyableBlock(text: symbol.name)
                            }
                        }
                    }
                    if !exported.isEmpty {
                        DisclosureGroup("Exported (\(exported.count))") {
                            ForEach(exported.prefix(300), id: \.self) { symbol in
                                CopyableBlock(text: symbol.name)
                            }
                        }
                    }
                    if !local.isEmpty {
                        DisclosureGroup("Local (\(local.count))") {
                            ForEach(local.prefix(200), id: \.self) { symbol in
                                CopyableBlock(text: symbol.name)
                            }
                        }
                    }
                }
            }
            if filtered.isEmpty {
                EmptyStateView(title: "No symbols", systemImage: "textformat.123",
                               description: "No symbol table was readable for this filter.")
            }
        }
        .searchable(text: $query, prompt: "Filter symbols")
        .navigationTitle("Symbols")
        .navigationBarTitleDisplayMode(.inline)
    }
}

// MARK: - Strings module

struct StringsHomeView: View {
    let outcome: AnalysisEngine.Outcome
    @State private var query = ""
    @State private var strings: [String: [String]] = [:]
    @State private var loading = false

    var body: some View {
        List {
            ForEach(Array(strings.keys.sorted()), id: \.self) { path in
                Section("\(path) — \(strings[path]?.count ?? 0)") {
                    let list = (strings[path] ?? []).filter {
                        query.isEmpty || $0.localizedCaseInsensitiveContains(query)
                    }
                    ForEach(list.prefix(400), id: \.self) { string in
                        CopyableBlock(text: string)
                    }
                    if list.count > 400 {
                        Text("… \(list.count - 400) more (showing first 400)")
                            .font(.caption2).foregroundStyle(.secondary)
                    }
                }
            }
            if strings.isEmpty && !loading {
                EmptyStateView(title: "No strings extracted", systemImage: "text.quote",
                               description: "Encrypted binaries have no readable strings on disk.")
            }
            if loading {
                LoadingCard(message: "Extracting strings…")
            }
        }
        .searchable(text: $query, prompt: "Filter strings")
        .navigationTitle("Strings")
        .navigationBarTitleDisplayMode(.inline)
        .onAppear {
            guard strings.isEmpty, let root = outcome.extractionRoot else { return }
            loading = true
            let binaries = outcome.report.binaries.filter { !$0.isEncrypted }
            Task.detached(priority: .userInitiated) {
                var result: [String: [String]] = [:]
                for binary in binaries {
                    let scanner = StringScanner(url: root.appendingPathComponent(binary.path),
                                                maxBytes: 8 * 1024 * 1024)
                    result[binary.path] = Array(scanner.strings().prefix(5000))
                }
                await MainActor.run {
                    strings = result
                    loading = false
                }
            }
        }
    }
}

// MARK: - Swift metadata module

struct SwiftMetadataHomeView: View {
    let outcome: AnalysisEngine.Outcome
    @State private var infos: [String: BinaryMetadata.SwiftInfo] = [:]
    @State private var loading = true

    var body: some View {
        List {
            ForEach(infos.sorted(by: { $0.key < $1.key }), id: \.key) { pair in
                let info = pair.value
                Section(pair.key) {
                    switch info.status {
                    case .blocked:
                        Label("Blocked by FairPlay encryption", systemImage: "lock.fill")
                            .foregroundStyle(.red).font(.footnote)
                    case .notFound:
                        Text("No Swift metadata found (an Objective-C-only binary contains no Swift sections).")
                            .font(.footnote).foregroundStyle(.secondary)
                    default:
                        if !info.metadataSections.isEmpty {
                            DisclosureGroup("Metadata sections (\(info.metadataSections.count))") {
                                ForEach(info.metadataSections.sorted(by: { $0.key < $1.key }), id: \.key) { name, size in
                                    KeyValueRow(key: name, value: ByteFormat.string(Int64(size)))
                                }
                            }
                        }
                        if !info.mangledTypeNames.isEmpty {
                            DisclosureGroup("Mangled types (\(info.mangledTypeNames.count))") {
                                ForEach(info.mangledTypeNames.prefix(200), id: \.self) { name in
                                    CopyableBlock(text: name)
                                }
                            }
                        }
                        if !info.demangledNames.isEmpty {
                            DisclosureGroup("Reflection strings (\(info.demangledNames.count))") {
                                ForEach(info.demangledNames.prefix(200), id: \.self) { name in
                                    CopyableBlock(text: name)
                                }
                            }
                        }
                        if !info.swiftVersionStrings.isEmpty {
                            KeyValueRow(key: "Runtime strings", value: info.swiftVersionStrings.joined(separator: ", "))
                        }
                        if info.mangledTypeNames.isEmpty && info.metadataSections.isEmpty {
                            Text("No Swift type information was found in this binary.")
                                .font(.footnote).foregroundStyle(.secondary)
                        }
                    }
                }
            }
            if loading {
                LoadingCard(message: "Scanning Swift metadata…")
            }
        }
        .navigationTitle("Swift Metadata")
        .navigationBarTitleDisplayMode(.inline)
        .onAppear {
            guard infos.isEmpty, let root = outcome.extractionRoot else { loading = false; return }
            let extraction = ExtractionResult(root: root, layout: BundleLayout(appBundlePath: "Payload/"),
                                              files: outcome.report.files, totalBytes: 0,
                                              rejectedEntries: [], hash: nil, warnings: [])
            Task.detached(priority: .userInitiated) {
                let result = BinaryMetadata.swiftInfo(extraction: extraction,
                                                      binaries: outcome.report.binaries)
                await MainActor.run {
                    infos = result
                    loading = false
                }
            }
        }
    }
}

// MARK: - Objective-C module

struct ObjCMetadataHomeView: View {
    let outcome: AnalysisEngine.Outcome
    @State private var infos: [String: BinaryMetadata.ObjCInfo] = [:]
    @State private var loading = true
    @State private var query = ""

    var body: some View {
        List {
            ForEach(infos.sorted(by: { $0.key < $1.key }), id: \.key) { pair in
                let info = pair.value
                Section(pair.key) {
                    switch info.status {
                    case .blocked:
                        Label("Blocked by FairPlay encryption", systemImage: "lock.fill")
                            .foregroundStyle(.red).font(.footnote)
                    case .notFound:
                        Text("No Objective-C metadata sections found.")
                            .font(.footnote).foregroundStyle(.secondary)
                    default:
                        if !info.classNames.isEmpty {
                            DisclosureGroup("Class names (\(info.classNames.count))") {
                                ForEach(info.classNames.filter { query.isEmpty || $0.localizedCaseInsensitiveContains(query) }.prefix(200), id: \.self) {
                                    CopyableBlock(text: $0)
                                }
                            }
                        }
                        if !info.methodNames.isEmpty {
                            DisclosureGroup("Method names (\(info.methodNames.count))") {
                                ForEach(info.methodNames.filter { query.isEmpty || $0.localizedCaseInsensitiveContains(query) }.prefix(200), id: \.self) {
                                    CopyableBlock(text: $0)
                                }
                            }
                        }
                        if !info.categories.isEmpty {
                            DisclosureGroup("Categories (\(info.categories.count))") {
                                ForEach(info.categories.prefix(100), id: \.self) {
                                    CopyableBlock(text: $0)
                                }
                            }
                        }
                        if !info.sectionBytes.isEmpty {
                            ForEach(info.sectionBytes.sorted(by: { $0.key < $1.key }), id: \.key) { name, size in
                                KeyValueRow(key: name, value: ByteFormat.string(Int64(size)))
                            }
                        }
                    }
                }
            }
            if loading {
                LoadingCard(message: "Scanning Objective-C metadata…")
            }
        }
        .searchable(text: $query, prompt: "Filter classes and methods")
        .navigationTitle("Objective-C")
        .navigationBarTitleDisplayMode(.inline)
        .onAppear {
            guard infos.isEmpty, let root = outcome.extractionRoot else { loading = false; return }
            let extraction = ExtractionResult(root: root, layout: BundleLayout(appBundlePath: "Payload/"),
                                              files: outcome.report.files, totalBytes: 0,
                                              rejectedEntries: [], hash: nil, warnings: [])
            Task.detached(priority: .userInitiated) {
                let result = BinaryMetadata.objcInfo(extraction: extraction,
                                                     binaries: outcome.report.binaries)
                await MainActor.run {
                    infos = result
                    loading = false
                }
            }
        }
    }
}

// MARK: - Dependencies module

struct DependenciesView: View {
    let outcome: AnalysisEngine.Outcome

    var body: some View {
        List {
            if let sdk = outcome.sdk {
                Section("Third-party SDKs (\(sdk.entries.count))") {
                    ForEach(sdk.entries) { entry in
                        NavigationLink {
                            SDKDetailView(entry: entry)
                        } label: {
                            VStack(alignment: .leading, spacing: 2) {
                                HStack {
                                    Text(entry.name).font(.subheadline.weight(.semibold))
                                    if entry.tracksUsers {
                                        Label("tracks", systemImage: "chart.bar.fill")
                                            .font(.caption2).foregroundStyle(.orange)
                                    }
                                }
                                Text(entry.category).font(.caption).foregroundStyle(.secondary)
                            }
                        }
                    }
                    if sdk.entries.isEmpty {
                        EmptyStateView(title: "No known SDKs matched", systemImage: "shippingbox",
                                       description: "No fingerprint from the local database matched this bundle.")
                    }
                }
                if !sdk.duplicates.isEmpty {
                    Section("Duplicate frameworks") {
                        ForEach(sdk.duplicates, id: \.self) { CopyableBlock(text: $0) }
                    }
                }
                if !sdk.renames.isEmpty {
                    Section("Suspicious names") {
                        ForEach(sdk.renames, id: \.self) { CopyableBlock(text: $0) }
                    }
                }
                Section("Apple frameworks linked") {
                    let apple = appleFrameworks
                    if apple.isEmpty {
                        Text("none").font(.footnote).foregroundStyle(.secondary)
                    } else {
                        ForEach(apple, id: \.self) { framework in
                            VStack(alignment: .leading, spacing: 1) {
                                Text(framework).font(.footnote)
                                let hints = AppleFrameworks.capability(forFrameworkName: framework)
                                if !hints.isEmpty {
                                    Text("implies: \(hints.joined(separator: ", "))")
                                        .font(.caption2).foregroundStyle(.secondary)
                                }
                            }
                        }
                    }
                }
                Section("Limitations") {
                    ForEach(sdk.limitations, id: \.self) { line in
                        Text(line).font(.caption).foregroundStyle(.secondary)
                    }
                }
            }

            if let structure = outcome.structure {
                Section("Embedded components") {
                    ForEach(structure.components) { component in
                        HStack {
                            VStack(alignment: .leading, spacing: 1) {
                                Text(component.name).font(.footnote.weight(.semibold))
                                Text(component.kind.rawValue).font(.caption2).foregroundStyle(.secondary)
                            }
                            Spacer()
                            StatusBadge(status: component.analysisStatus)
                        }
                    }
                }
            }

            if !outcome.report.domains.isEmpty {
                Section("Hosts referenced (\(outcome.report.domains.count))") {
                    ForEach(outcome.report.domains.prefix(80), id: \.self) { host in
                        KeyValueRow(key: host, value: "\(outcome.urlsByHost(host)) URLs")
                    }
                }
            }
        }
        .navigationTitle("Dependencies")
        .navigationBarTitleDisplayMode(.inline)
    }

    private var appleFrameworks: [String] {
        var set = Set<String>()
        for binary in outcome.report.binaries {
            for arch in binary.archs {
                for lib in arch.dylibs {
                    let base = (lib as NSString).lastPathComponent
                    if base.hasSuffix(".framework") {
                        set.insert(String(base.dropLast(".framework".count)))
                    }
                }
            }
        }
        return set.sorted()
    }
}

struct SDKDetailView: View {
    let entry: SDKInventory.SDKEntry

    var body: some View {
        List {
            Section("Identity") {
                KeyValueRow(key: "Name", value: entry.name)
                KeyValueRow(key: "Category", value: entry.category)
                KeyValueRow(key: "Version", value: entry.version ?? "not stated by the bundle")
                if let source = entry.versionSource {
                    KeyValueRow(key: "Version source", value: source, monospaced: true)
                }
                KeyValueRow(key: "Tracks users", value: entry.tracksUsers ? "flagged by the local database" : "no tracking flag")
                KeyValueRow(key: "Confidence", value: entry.confidence)
            }
            Section("Evidence") {
                ForEach(entry.evidence, id: \.self) { CopyableBlock(text: $0) }
            }
            if !entry.frameworkPaths.isEmpty {
                Section("Framework bundles") {
                    ForEach(entry.frameworkPaths, id: \.self) { CopyableBlock(text: $0) }
                }
            }
            Section("Compatibility") {
                if let minOS = entry.minOS {
                    KeyValueRow(key: "Minimum OS", value: minOS)
                }
                if let compatible = entry.compatible {
                    KeyValueRow(key: "Compatible with the app",
                                value: compatible ? "yes" : "no — newer minimum OS")
                }
                if !entry.architectures.isEmpty {
                    KeyValueRow(key: "Architectures", value: entry.architectures.joined(separator: ", "))
                }
            }
            Section("Notes") {
                Text(entry.notes).font(.footnote)
            }
        }
        .navigationTitle(entry.name)
        .navigationBarTitleDisplayMode(.inline)
    }
}

extension AnalysisEngine.Outcome {
    func urlsByHost(_ host: String) -> Int {
        report.urls.filter { URL(string: $0)?.host?.lowercased() == host }.count
    }
}
