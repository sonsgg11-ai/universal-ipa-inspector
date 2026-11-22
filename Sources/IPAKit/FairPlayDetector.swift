import Foundation

/// FairPlay encryption detection (requirement L).
///
/// This module reports which slices of which binaries are encrypted, using
/// LC_ENCRYPTION_INFO (cryptid / cryptoff / cryptsize). It explains what
/// analysis remains possible and marks unavailable operations as blocked.
/// It never attempts to decrypt, bypass or otherwise defeat FairPlay.
enum FairPlayDetector {

    struct SliceStatus: Codable, Identifiable, Sendable {
        var id: String { "\(path)#\(cpu)" }
        let path: String
        let cpu: String
        let cryptID: UInt32?
        let cryptOffset: UInt64?
        let cryptSize: UInt64?
        let encrypted: Bool?
        /// Structured facts that survive encryption.
        let readableStructure: [String]
    }

    struct EncryptionReport: Codable, Sendable {
        var slices: [SliceStatus] = []
        var encryptedBinaryPaths: [String] = []
        var unencryptedBinaryPaths: [String] = []
        var mixedBinaries: [String] = []
        var blockedOperations: [String] = []
        var availableOperations: [String] = []
        var notice: String = ""
    }

    static func detect(report: Report) -> EncryptionReport {
        var out = EncryptionReport()

        for binary in report.binaries {
            for arch in binary.archs {
                out.slices.append(SliceStatus(
                    path: binary.path,
                    cpu: arch.cpu,
                    cryptID: arch.cryptID,
                    cryptOffset: arch.cryptOffset,
                    cryptSize: arch.cryptSize,
                    encrypted: arch.encrypted,
                    readableStructure: readableStructure(for: arch)))
            }
            let flags = binary.archs.map { $0.encrypted == true }
            if flags.allSatisfy({ $0 }) {
                out.encryptedBinaryPaths.append(binary.path)
            } else if flags.allSatisfy({ !$0 }) {
                out.unencryptedBinaryPaths.append(binary.path)
            } else {
                out.mixedBinaries.append(binary.path)
            }
        }

        if !out.encryptedBinaryPaths.isEmpty || !out.mixedBinaries.isEmpty {
            out.blockedOperations = [
                "Disassembly of the encrypted slices (__TEXT is scrambled on disk)",
                "String extraction from encrypted slices",
                "Objective-C class/method metadata extraction from encrypted slices",
                "Swift metadata extraction from encrypted slices",
                "Symbol table analysis of encrypted slices (the table itself is scrambled on disk for these images)",
            ]
            out.availableOperations = [
                "Info.plist, bundle structure, resources and asset inventory",
                "Mach-O header and load-command parsing (load commands are not encrypted)",
                "Linked-library lists, runtime paths and platform/SDK versions",
                "Code-signature blobs and entitlements of unencrypted slices",
                "Provisioning profile and entitlements from the profile",
                "Text resources, plists, JSON/XML configuration and their contents",
                "Architecture inventory, section/segment layout, UUIDs",
                "Entire FairPlay status reporting — including which slices are affected",
            ]
            out.notice = "Encrypted slices are reported as blocked, never skipped silently. No decryption or FairPlay bypass is attempted or provided by this tool."
        } else {
            out.availableOperations = [
                "All static analysis operations (no encrypted slices detected)",
            ]
            out.notice = "No FairPlay-encrypted slices were found. Note: an unsigned local build may lack LC_ENCRYPTION_INFO entirely, which is reported per slice."
        }
        return out
    }

    private static func readableStructure(for arch: ArchInfo) -> [String] {
        var items: [String] = []
        items.append("Mach-O header (\(arch.cpu), \(arch.is64Bit ? "64" : "32")-bit)")
        if let platform = arch.platform { items.append("platform: \(platform)") }
        if let minOS = arch.minOS { items.append("minimum OS: \(minOS)") }
        if let sdk = arch.sdk { items.append("SDK: \(sdk)") }
        if let uuid = arch.uuid { items.append("LC_UUID: \(uuid)") }
        if !arch.dylibs.isEmpty { items.append("\(arch.dylibs.count) linked libraries") }
        if !arch.rpaths.isEmpty { items.append("\(arch.rpaths.count) runtime paths") }
        if !arch.segments.isEmpty { items.append("\(arch.segments.count) segments") }
        if let cryptSize = arch.cryptSize, cryptSize > 0 {
            items.append("encrypted range: \(ByteFormat.string(Int64(cryptSize))) at offset \(arch.cryptOffset ?? 0)")
        }
        return items
    }
}
