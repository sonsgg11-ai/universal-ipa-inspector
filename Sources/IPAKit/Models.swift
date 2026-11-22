import Foundation

// MARK: - Evidence status

/// How strong the evidence behind a finding is. Every finding carries one so a
/// reader can always tell a proven fact from an indication or a blocked check.
enum EvidenceStatus: String, Codable, CaseIterable, Equatable, Sendable {
    case verified      // proven by parsing: the value is on disk and was read
    case detected      // reliable indicator found in the artefact
    case estimated     // inferred; weaker evidence, clearly labelled
    case blocked       // the check cannot run (e.g. FairPlay encryption)
    case notFound      // the artefact was looked for and is genuinely absent

    var label: String {
        switch self {
        case .verified: return "verified"
        case .detected: return "detected"
        case .estimated: return "estimated"
        case .blocked: return "blocked"
        case .notFound: return "not found"
        }
    }
}

/// Back-compat alias used across the older code paths.
typealias Status = EvidenceStatus

// MARK: - Finding

struct Finding: Codable, Identifiable, Equatable, Sendable {
    var id = UUID()
    let category: String
    let title: String
    let value: String
    let source: String
    let status: EvidenceStatus
    var note: String? = nil

    init(id: UUID = UUID(),
         category: String,
         title: String,
         value: String,
         source: String,
         status: EvidenceStatus,
         note: String? = nil) {
        self.id = id
        self.category = category
        self.title = title
        self.value = value
        self.source = source
        self.status = status
        self.note = note
    }
}

extension Array where Element == Finding {
    var categories: [String] {
        var names = Set<String>()
        for finding in self { names.insert(finding.category) }
        return names.sorted()
    }
}

// MARK: - Mach-O model

struct SectionInfo: Codable, Equatable, Sendable {
    let segmentName: String
    let name: String
    let address: UInt64
    let size: UInt64
    let offset: UInt32
}

struct SegmentInfo: Codable, Equatable, Sendable {
    let name: String
    let vmSize: UInt64
    let fileOffset: UInt64
    let fileSize: UInt64
    let maxProt: UInt32
    var sections: [SectionInfo]
    var truncated: Bool

    var isWritable: Bool { maxProt & 0x2 != 0 }
    var isExecutable: Bool { maxProt & 0x4 != 0 }
}

struct ArchInfo: Codable, Sendable {
    var cpu: String = "unknown"
    var is64Bit: Bool = true
    var encrypted: Bool? = nil
    /// Byte offset and size of the encrypted range (LC_ENCRYPTION_INFO).
    var cryptID: UInt32? = nil
    var cryptOffset: UInt64? = nil
    var cryptSize: UInt64? = nil
    var minOS: String? = nil
    var sdk: String? = nil
    var platform: String? = nil
    var uuid: String? = nil
    var dylibs: [String] = []
    var weakDylibs: [String] = []
    var reexportedDylibs: [String] = []
    var rpaths: [String] = []
    var segments: [SegmentInfo] = []
    var entitlements: String? = nil
    /// Alias kept for the entitlements XML extracted from LC_CODE_SIGNATURE.
    var entitlementsXML: String? {
        get { entitlements }
        set { entitlements = newValue }
    }
    var warnings: [String] = []
    var cpuTypeRaw: UInt32 = 0
    var cpuSubtypeRaw: UInt32 = 0
    var linkedItOffset: UInt64 = 0

    /// Symbols parsed from LC_SYMTAB (filled by SymbolTableParser when asked).
    var symbols: [SymbolEntry] = []

    var isEncrypted: Bool { encrypted == true }
}

/// One symbol table entry (nlist record) from LC_SYMTAB.
struct SymbolEntry: Codable, Equatable, Sendable, Hashable {
    let name: String
    let isExternal: Bool
    let isUndefined: Bool   // imported: defined in another image
    let section: UInt8
    let value: UInt64

    var kind: SymbolKind {
        if isUndefined { return .imported }
        if isExternal { return .exported }
        return .local
    }
}

enum SymbolKind: String, Codable, CaseIterable, Sendable {
    case imported, exported, local
}

struct BinaryInfo: Codable, Identifiable, Sendable {
    var id: String { path }
    let path: String
    let archs: [ArchInfo]
    var warnings: [String] = []
    var componentKind: String = "binary"     // main app / framework / extension
    var parentBundle: String? = nil

    var isEncrypted: Bool {
        guard !archs.isEmpty else { return false }
        return archs.allSatisfy { $0.encrypted == true }
    }
    var hasMixedEncryption: Bool {
        let flags = archs.map { $0.encrypted == true }
        return flags.contains(true) && flags.contains(false)
    }
}

// MARK: - Files

struct FileEntry: Codable, Identifiable, Equatable, Sendable {
    var id: String { path }
    let path: String
    let size: Int64
    var kind: String = "resource"            // BundleRole raw value

    init(path: String, size: Int64, kind: String = "resource") {
        self.path = path
        self.size = size
        self.kind = kind
    }
}

// MARK: - Report

struct Report: Codable, Sendable {
    let source: String          // "IPA" or "App Store"
    var name: String
    var sha256: String? = nil
    var fileCount: Int = 0
    var totalBytes: Int64 = 0
    var directoryCount: Int = 0
    var findings: [Finding] = []
    var binaries: [BinaryInfo] = []
    var files: [FileEntry] = []
    var urls: [String] = []
    var domains: [String] = []
    var limitations: [String] = []
    var analysedAt: Date = Date()

    init(source: String, name: String) {
        self.source = source
        self.name = name
    }
}

// MARK: - Shared byte formatting used by both engine and UI

enum ByteFormat {
    static func string(_ bytes: Int64) -> String {
        ByteCountFormatter.string(fromByteCount: bytes, countStyle: .file)
    }
}

// MARK: - Little/big endian append helpers (shared by ZIP/fixture writers)

extension Data {
    mutating func appendLE16(_ v: UInt16) {
        append(UInt8(v & 0xFF)); append(UInt8(v >> 8))
    }
    mutating func appendLE32(_ v: UInt32) {
        append(UInt8(v & 0xFF)); append(UInt8((v >> 8) & 0xFF))
        append(UInt8((v >> 16) & 0xFF)); append(UInt8(v >> 24))
    }
    mutating func appendLE64(_ v: UInt64) {
        for i in 0..<8 { append(UInt8((v >> (i * 8)) & 0xFF)) }
    }
    mutating func appendBE16(_ v: UInt16) {
        append(UInt8(v >> 8)); append(UInt8(v & 0xFF))
    }
    mutating func appendBE32(_ v: UInt32) {
        append(UInt8(v >> 24)); append(UInt8((v >> 16) & 0xFF))
        append(UInt8((v >> 8) & 0xFF)); append(UInt8(v & 0xFF))
    }
    mutating func appendBE64(_ v: UInt64) {
        for i in 0..<8 { append(UInt8((v >> ((7 - i) * 8)) & 0xFF)) }
    }
}
