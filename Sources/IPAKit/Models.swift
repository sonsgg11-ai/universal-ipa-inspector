import Foundation

// MARK: - Evidence status

/// How strong the evidence behind a finding is. Every finding carries one so a
/// reader can tell "read it out of the file" from "pattern match, could be wrong"
/// from "cannot be checked at all".
enum EvidenceStatus: String, Codable, CaseIterable {
    /// Read directly from the artifact and re-derivable.
    case verified
    /// A pattern match or heuristic result.
    case detected
    /// A plausible inference; the fingerprint is weak or the value is inferred.
    case estimated
    /// The check cannot be performed (usually FairPlay encryption).
    case blocked
    /// Looked for it, not present.
    case notFound

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

// MARK: - Findings

/// One observation about the analyzed artifact.
struct Finding: Codable, Identifiable {
    /// Stable identity for SwiftUI lists; deliberately not part of the encoded
    /// report, which should describe the artifact, not this run.
    var id = UUID()
    let category: String
    let title: String
    let value: String
    let source: String
    let status: EvidenceStatus
    var note: String?

    init(category: String,
         title: String,
         value: String,
         source: String,
         status: EvidenceStatus,
         note: String? = nil) {
        self.id = UUID()
        self.category = category
        self.title = title
        self.value = value
        self.source = source
        self.status = status
        self.note = note
    }

    enum CodingKeys: String, CodingKey {
        case category, title, value, source, status, note
    }

    init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        id = UUID()
        category = try container.decode(String.self, forKey: .category)
        title = try container.decode(String.self, forKey: .title)
        value = try container.decode(String.self, forKey: .value)
        source = try container.decode(String.self, forKey: .source)
        status = try container.decode(EvidenceStatus.self, forKey: .status)
        note = try container.decodeIfPresent(String.self, forKey: .note)
    }
}

// MARK: - Mach-O model

/// One parsed architecture slice of a Mach-O file.
struct ArchInfo: Codable, Hashable {
    var cpu = "unknown"
    var cpuTypeRaw: UInt32?
    var cpuSubtypeRaw: UInt32?
    var is64Bit = true
    var platform: String?
    var minOS: String?
    var sdk: String?
    var uuid: String?
    /// nil when the file carries no encryption load command.
    var encrypted: Bool?
    var cryptID: UInt32?
    var dylibs: [String] = []
    var weakDylibs: [String] = []
    var reexportedDylibs: [String] = []
    var rpaths: [String] = []
    var segments: [SegmentInfo] = []
    /// XML entitlements plist extracted from the code-signature SuperBlob.
    var entitlementsXML: String?
    var warnings: [String] = []
    /// Offset of the linked code-signature blob, when present.
    var linkedItOffset: UInt64?

    init() {}
}

/// One segment of a Mach-O slice.
struct SegmentInfo: Codable, Hashable {
    var name = ""
    var vmSize: UInt64 = 0
    var fileOffset: UInt64 = 0
    var fileSize: UInt64 = 0
    var maxProt: UInt32 = 0
    var sections: [SectionInfo] = []
    var truncated = false

    var isWritable: Bool { maxProt & 0x2 != 0 }
    var isExecutable: Bool { maxProt & 0x4 != 0 }

    init(name: String,
         vmSize: UInt64,
         fileOffset: UInt64,
         fileSize: UInt64,
         maxProt: UInt32,
         sections: [SectionInfo],
         truncated: Bool) {
        self.name = name
        self.vmSize = vmSize
        self.fileOffset = fileOffset
        self.fileSize = fileSize
        self.maxProt = maxProt
        self.sections = sections
        self.truncated = truncated
    }
}

/// One section of a Mach-O segment.
struct SectionInfo: Codable, Hashable {
    var segmentName = ""
    var name = ""
    var address: UInt64 = 0
    var size: UInt64 = 0
    var offset: UInt32 = 0

    init(segmentName: String, name: String, address: UInt64, size: UInt64, offset: UInt32) {
        self.segmentName = segmentName
        self.name = name
        self.address = address
        self.size = size
        self.offset = offset
    }
}

/// A Mach-O file (all slices) found inside the bundle.
struct BinaryInfo: Codable, Identifiable, Hashable {
    var path: String
    var archs: [ArchInfo]
    var warnings: [String] = []

    var id: String { path }
    var isEncrypted: Bool { archs.contains { $0.encrypted == true } }

    init(path: String, archs: [ArchInfo], warnings: [String] = []) {
        self.path = path
        self.archs = archs
        self.warnings = warnings
    }
}

// MARK: - Inventory

/// One extracted file and what role it plays in the bundle.
struct FileEntry: Codable, Hashable {
    let path: String
    let size: Int64
    var kind: String = "resource"
}

// MARK: - Report

/// The complete result of one analysis run.
struct Report: Codable {
    /// "IPA" or "App Store".
    let source: String
    var name: String
    var sha256: String?
    var fileCount = 0
    var totalBytes: Int64 = 0
    var findings: [Finding] = []
    var binaries: [BinaryInfo] = []
    var files: [FileEntry] = []
    var urls: [String] = []
    var domains: [String] = []
    /// What this report cannot tell you. Always populated for IPA analysis.
    var limitations: [String] = []

    init(source: String, name: String) {
        self.source = source
        self.name = name
    }

    var categories: [String] {
        Array(Set(findings.map(\.category))).sorted()
    }
}
