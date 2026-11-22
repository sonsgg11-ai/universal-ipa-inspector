import SwiftUI

// MARK: - N: Dashboard (Overview)

struct DashboardView: View {
    let outcome: AnalysisEngine.Outcome

    var body: some View {
        List {
            if let d = outcome.dashboard {
                Section("Application") {
                    KeyValueRow(key: "Name", value: d.appName)
                    KeyValueRow(key: "Bundle ID", value: d.bundleID)
                    KeyValueRow(key: "Version", value: "\(d.version) (\(d.buildNumber))")
                    KeyValueRow(key: "Minimum iOS", value: d.minOS)
                    if !d.ipaSHA256.isEmpty {
                        VStack(alignment: .leading, spacing: 2) {
                            Text("IPA SHA-256").font(.caption).foregroundStyle(.secondary)
                            Text(d.ipaSHA256)
                                .font(.caption2.monospaced())
                                .textSelection(.enabled)
                        }
                    }
                }

                Section("Bundle") {
                    KeyValueRow(key: "IPA size (extracted bytes)", value: ByteFormat.string(d.ipaSizeBytes))
                    KeyValueRow(key: "Files", value: "\(d.fileCount)")
                    KeyValueRow(key: "Directories", value: "\(d.directoryCount)")
                    KeyValueRow(key: "Executables parsed", value: "\(d.executableCount)")
                    KeyValueRow(key: "Architectures", value: d.architectures.joined(separator: ", "))
                    KeyValueRow(key: "Frameworks", value: "\(d.frameworkCount)")
                    KeyValueRow(key: "Extensions", value: "\(d.extensionCount)")
                    KeyValueRow(key: "Encrypted binaries", value: "\(d.encryptedBinaryCount)")
                    KeyValueRow(key: "Unencrypted binaries", value: "\(d.unencryptedBinaryCount)")
                    KeyValueRow(key: "Imported symbols", value: "\(d.importedSymbolCount)")
                    KeyValueRow(key: "Exported symbols", value: "\(d.exportedSymbolCount)")
                    KeyValueRow(key: "URLs / hosts", value: "\(d.urlCount) / \(d.domainCount)")
                    KeyValueRow(key: "SDKs detected", value: "\(d.sdkCount)")
                }

                Section("Security") {
                    ForEach(SecurityAssessor.Severity.allCases, id: \.self) { severity in
                        HStack {
                            SeverityBadge(severity: severity)
                            Spacer()
                            Text("\(d.findingsBySeverity[severity.rawValue] ?? 0)")
                                .font(.subheadline.monospaced())
                        }
                    }
                    KeyValueRow(key: "Credential-shaped strings (masked)", value: "\(d.secretCount)")
                    KeyValueRow(key: "Completed checks", value: "\(d.completedChecks)")
                    KeyValueRow(key: "Blocked checks", value: "\(d.blockedChecks)")
                }

                if !outcome.report.limitations.isEmpty {
                    Section("Limitations") {
                        ForEach(outcome.report.limitations, id: \.self) { line in
                            Text(line).font(.caption).foregroundStyle(.secondary)
                        }
                    }
                }
            } else {
                EmptyStateView(title: "Dashboard unavailable", systemImage: "gauge",
                               description: "The engine produced no dashboard snapshot.")
            }
        }
        .navigationTitle("Overview")
        .navigationBarTitleDisplayMode(.inline)
    }
}

// MARK: - F: File Explorer

struct FileExplorerView: View {
    let outcome: AnalysisEngine.Outcome
    @State private var query = ""

    /// Directory tree built from the flat inventory.
    private struct Node: Identifiable {
        let id: String
        let name: String
        let path: String
        var children: [Node]
        var file: FileExplorer.FileMetadata?
    }

    private var root: Node {
        buildTree(query: query)
    }

    var body: some View {
        Group {
            if outcome.inventory.isEmpty {
                EmptyStateView(title: "No files inventoried", systemImage: "folder",
                               description: "The archive contained no extractable files.")
            } else {
                List {
                    TreeNodeView(node: root, outcome: outcome, depth: 0)
                }
            }
        }
        .searchable(text: $query, prompt: "Filter by path")
        .navigationTitle("File Explorer")
        .navigationBarTitleDisplayMode(.inline)
    }

    private func buildTree(query: String) -> Node {
        var directories: [String: [FileExplorer.FileMetadata]] = [:]
        for file in outcome.inventory {
            let matches = query.isEmpty || file.path.localizedCaseInsensitiveContains(query)
            guard matches else { continue }
            let dir = (file.path as NSString).deletingLastPathComponent
            directories[dir, default: []].append(file)
        }
        // Build nested structure for every directory prefix.
        var nodes: [String: Node] = [:]
        var allDirs = Set(directories.keys)
        // Include intermediate dirs
        for dir in directories.keys {
            var parts = dir.split(separator: "/").map(String.init)
            var prefix = ""
            for part in parts {
                prefix = prefix.isEmpty ? part : "\(prefix)/\(part)"
                allDirs.insert(prefix)
            }
        }
        for dir in allDirs.sorted(by: { $0.count > $1.count }) {
            let children = (directories[dir] ?? []).map { file in
                Node(id: file.path, name: (file.path as NSString).lastPathComponent,
                     path: file.path, children: [], file: file)
            }
            var subdirs: [Node] = []
            for candidate in allDirs where candidate.hasPrefix("\(dir)/") {
                let rest = String(candidate.dropFirst(dir.count + 1))
                if !rest.contains("/") {
                    if let child = nodes[candidate] { subdirs.append(child) }
                }
            }
            let node = Node(id: dir, name: (dir as NSString).lastPathComponent,
                            path: dir, children: subdirs + children, file: nil)
            nodes[dir] = node
        }
        let rootPath = outcome.inventory.map { ($0.path as NSString).deletingLastPathComponent }
            .min { $0.count < $1.count } ?? "Payload"
        return nodes[rootPath] ?? Node(id: "Payload", name: "Payload", path: "Payload",
                                       children: [], file: nil)
    }
}

private struct TreeNodeView: View {
    let node: FileExplorerView.Node
    let outcome: AnalysisEngine.Outcome
    let depth: Int
    @State private var expanded = depth < 1

    var body: some View {
        if let file = node.file {
            NavigationLink {
                FileDetailView(file: file, outcome: outcome)
            } label: {
                HStack(spacing: DesignSystem.Spacing.s) {
                    Image(systemName: icon(for: file.nodeType))
                        .foregroundStyle(DesignSystem.accent)
                        .frame(width: 20)
                    VStack(alignment: .leading, spacing: 1) {
                        Text(node.name).font(.footnote)
                        Text(ByteFormat.string(file.size))
                            .font(.caption2).foregroundStyle(.secondary)
                    }
                }
                .padding(.leading, CGFloat(depth) * 12)
            }
        } else {
            DisclosureGroup(isExpanded: $expanded) {
                ForEach(node.children) { child in
                    TreeNodeView(node: child, outcome: outcome, depth: depth + 1)
                }
            } label: {
                Label(node.name, systemImage: "folder")
                    .font(.footnote.weight(.medium))
                    .padding(.leading, CGFloat(depth) * 12)
            }
        }
    }

    private func icon(for type: FileExplorer.FileNodeType) -> String {
        switch type {
        case .executable: return "wrench.and.screwdriver"
        case .dynamicLibrary: return "shippingbox"
        case .plist, .xml: return "doc.plaintext"
        case .json: return "curlybraces"
        case .strings: return "text.quote"
        case .image: return "photo"
        case .database: return "cylinder"
        case .certificate: return "seal"
        case .provisioning: return "signature"
        case .archive: return "doc.zipper"
        case .font: return "textformat"
        case .audio: return "waveform"
        case .video: return "film"
        case .text: return "doc.text"
        case .script: return "terminal"
        case .binary: return "cpu"
        case .unknown: return "doc"
        case .framework: return "shippingbox"
        case .configuration: return "gearshape.2"
        }
    }
}

// MARK: - File detail (metadata + preview + hex entry)

struct FileDetailView: View {
    let file: FileExplorer.FileMetadata
    let outcome: AnalysisEngine.Outcome
    @State private var showHex = false

    var body: some View {
        List {
            Section("Metadata") {
                KeyValueRow(key: "Path", value: file.path, monospaced: true)
                KeyValueRow(key: "Size", value: ByteFormat.string(file.size))
                KeyValueRow(key: "Compressed size", value: ByteFormat.string(file.compressedSize))
                KeyValueRow(key: "Compression ratio", value: String(format: "%.2f:1", file.compressionRatio))
                KeyValueRow(key: "Permissions", value: file.permissions, monospaced: true)
                KeyValueRow(key: "Location", value: file.location)
                KeyValueRow(key: "Type", value: file.nodeType.rawValue)
                if let sha = file.sha256 {
                    VStack(alignment: .leading, spacing: 2) {
                        Text("SHA-256").font(.caption).foregroundStyle(.secondary)
                        Text(sha).font(.caption2.monospaced()).textSelection(.enabled)
                    }
                }
            }

            Section("Preview") {
                previewContent
            }

            Section {
                Button {
                    showHex = true
                } label: {
                    Label("Open hex viewer", systemImage: "square.grid.3x3.square")
                }
            } footer: {
                Text("The viewer streams the file in windows; large files never load fully into memory. The extracted bundle is read-only.")
            }
        }
        .navigationTitle((file.path as NSString).lastPathComponent)
        .navigationBarTitleDisplayMode(.inline)
        .navigationDestination(isPresented: $showHex) {
            HexViewerView(path: file.path, outcome: outcome)
        }
    }

    @ViewBuilder
    private var previewContent: some View {
        if let root = outcome.extractionRoot {
            switch FileExplorer.preview(path: file.path, extractionRoot: root) {
            case .text(let text, let truncated):
                CopyableBlock(text: text)
                if truncated {
                    Label("Preview truncated at the first 256 KB.", systemImage: "scissors")
                        .font(.caption2).foregroundStyle(.secondary)
                }
            case .image(let total):
                ImagePreview(path: file.path, root: root)
                Text("Image, \(ByteFormat.string(total)) — open the hex viewer for raw bytes.")
                    .font(.caption2).foregroundStyle(.secondary)
            case .binary(_, let reason):
                Text(reason).font(.footnote).foregroundStyle(.secondary)
            case .unavailable(let message):
                Text(message).font(.footnote).foregroundStyle(.secondary)
            }
        } else {
            Text("Extraction root unavailable.").font(.footnote).foregroundStyle(.secondary)
        }
    }
}

/// Renders an image from the extracted file (UIKit-backed).
struct ImagePreview: View {
    let path: String
    let root: URL
    @State private var image: UIImage?

    var body: some View {
        Group {
            if let image {
                Image(uiImage: image)
                    .resizable()
                    .scaledToFit()
                    .frame(maxHeight: 220)
                    .clipShape(RoundedRectangle(cornerRadius: DesignSystem.Radius.chip))
                    .accessibilityLabel("Image preview")
            } else {
                EmptyStateView(title: "No preview", systemImage: "photo",
                               description: "The image could not be decoded on this device.")
            }
        }
        .onAppear {
            let url = root.appendingPathComponent(path)
            if let data = try? Data(contentsOf: url) {
                image = UIImage(data: data)
            }
        }
    }
}

// MARK: - Hex workbench

struct HexViewerView: View {
    let path: String
    let outcome: AnalysisEngine.Outcome
    @State private var offset: Int64 = 0
    @State private var chunk: FileExplorer.HexChunk?
    @State private var fileSize: Int64 = 0
    @State private var searchQuery = ""
    @State private var searchResults: [Int64] = []
    @State private var searchError: String?
    @State private var isCaseSensitive = false
    @State private var useHexMode = false
    @State private var jumpText = ""

    private let windowSize = 512

    var body: some View {
        VStack(spacing: 0) {
            // Byte ruler
            HStack {
                Text("Offset \(offset) — \(min(offset + Int64(windowSize), fileSize)) of \(fileSize)")
                    .font(.caption.monospaced())
                    .foregroundStyle(.secondary)
                Spacer()
            }
            .padding(.horizontal, DesignSystem.Spacing.m)
            .padding(.vertical, DesignSystem.Spacing.s)

            ScrollView([.horizontal, .vertical]) {
                if let chunk {
                    VStack(alignment: .leading, spacing: 1) {
                        ForEach(chunk.lines) { line in
                            Text("\(String(format: "%08X", UInt64(line.offset)))  \(line.hex)  |\(line.ascii)|")
                                .font(.system(size: 11, design: .monospaced))
                                .textSelection(.enabled)
                        }
                    }
                    .padding(DesignSystem.Spacing.s)
                } else {
                    Text("No data at this offset.")
                        .font(.footnote).foregroundStyle(.secondary)
                        .padding(DesignSystem.Spacing.m)
                }
            }
            .background(Color(.secondarySystemGroupedBackground))

            controls
        }
        .navigationTitle("Hex viewer")
        .navigationBarTitleDisplayMode(.inline)
        .onAppear(perform: load)
    }

    private var controls: some View {
        VStack(spacing: DesignSystem.Spacing.s) {
            HStack(spacing: DesignSystem.Spacing.s) {
                Button {
                    seek(to: max(0, offset - Int64(windowSize)))
                } label: {
                    Image(systemName: "chevron.left")
                }
                .disabled(offset <= 0)

                Spacer()
                Text(jumpField)
                    .font(.caption.monospaced())
                    .foregroundStyle(.secondary)
                Spacer()

                Button {
                    seek(to: min(fileSize, offset + Int64(windowSize)))
                } label: {
                    Image(systemName: "chevron.right")
                }
                .disabled(offset + Int64(windowSize) >= fileSize)
            }

            HStack(spacing: DesignSystem.Spacing.s) {
                TextField(useHexMode ? "hex: cf fa ed fe" : "text to find", text: $searchQuery)
                    .textFieldStyle(.roundedBorder)
                    .font(.caption.monospaced())
                    .autocorrectionDisabled()
                    .textInputAutocapitalization(.never)
                Toggle("hex", isOn: $useHexMode)
                    .toggleStyle(.button)
                    .font(.caption)
                Toggle("Aa", isOn: Binding(
                    get: { !isCaseSensitive },
                    set: { isCaseSensitive = !$0 }))
                    .toggleStyle(.button)
                    .font(.caption)
                Button(action: runSearch) {
                    Image(systemName: "magnifyingglass")
                }
                .disabled(searchQuery.isEmpty)
            }

            if let searchError {
                Text(searchError)
                    .font(.caption2).foregroundStyle(.red)
            } else if !searchResults.isEmpty {
                ScrollView(.horizontal, showsIndicators: false) {
                    HStack {
                        ForEach(Array(searchResults.prefix(20).enumerated()), id: \.offset) { _, hit in
                            Button("0x\(String(UInt64(hit), radix: 16))") {
                                seek(to: hit)
                            }
                            .font(.caption2.monospaced())
                            .buttonStyle(.bordered)
                        }
                    }
                }
            }

            HStack {
                TextField("jump to offset", text: $jumpText)
                    .textFieldStyle(.roundedBorder)
                    .font(.caption.monospaced())
                    .keyboardType(.numbersAndPunctuation)
                    .autocorrectionDisabled()
                    .textInputAutocapitalization(.never)
                Button("Go") { jump() }
                    .font(.caption)
                    .disabled(jumpText.isEmpty)
            }
        }
        .padding(DesignSystem.Spacing.m)
        .background(Color(.systemGroupedBackground))
    }

    private var jumpField: String {
        "0x\(String(UInt64(max(0, offset)), radix: 16))"
    }

    private func load() {
        guard let root = outcome.extractionRoot else { return }
        let url = root.appendingPathComponent(path)
        fileSize = (try? FileManager.default.attributesOfItem(atPath: url.path)[.size] as? Int64) ?? 0
        loadChunk()
    }

    private func loadChunk() {
        guard let root = outcome.extractionRoot else { return }
        chunk = FileExplorer.hexChunk(path: path, extractionRoot: root,
                                      offset: offset, length: windowSize)
    }

    private func seek(to target: Int64) {
        offset = max(0, min(target, max(0, fileSize - Int64(windowSize))))
        loadChunk()
    }

    private func runSearch() {
        searchError = nil
        searchResults = []
        guard let root = outcome.extractionRoot else { return }
        do {
            if useHexMode {
                let pattern = try FileExplorer.parseHexPattern(searchQuery)
                searchResults = try FileExplorer.searchBytes(path: path, extractionRoot: root,
                                                             pattern: pattern)
            } else {
                searchResults = try FileExplorer.searchText(path: path, extractionRoot: root,
                                                            text: searchQuery,
                                                            caseSensitive: isCaseSensitive)
            }
            if searchResults.isEmpty {
                searchError = "No matches found (searched up to 64 MB)."
            }
        } catch {
            searchError = error.localizedDescription
        }
    }

    private func jump() {
        let text = jumpText.trimmingCharacters(in: .whitespaces)
        let value: Int64?
        if text.hasPrefix("0x") {
            value = UInt64(text.dropFirst(2), radix: 16).map { Int64(bitPattern: $0) }
        } else {
            value = Int64(text)
        }
        if let value {
            seek(to: value)
            jumpText = ""
        }
    }
}
