import Foundation
@testable import IPAKit

/// Builds synthetic archives and binaries for the tests.
///
/// Everything is written from scratch so the tests depend on no external
/// fixture files: `zip` emits stored (uncompressed) ZIP entries with real CRCs,
/// `thinMachO`/`fat` emit byte-accurate Mach-O containers, and `sampleIPA`
/// assembles a complete synthetic app bundle that exercises the whole analyzer.
enum FixtureBuilder {

    // MARK: - ZIP specifications

    /// One entry to write into a synthetic archive.
    struct ZipSpec {
        var path: String
        var contents: Data
        var externalAttributes: UInt32? = nil
    }

    /// Unix mode bits (st_mode) for a regular file, in the high 16 bits of the
    /// ZIP external-attributes field.
    static func regularAttributes() -> UInt32 {
        UInt32(0o100644) << 16
    }

    /// Unix mode bits for a symbolic link.
    static func symlinkAttributes() -> UInt32 {
        UInt32(0o120777) << 16
    }

    // MARK: - ZIP writing (stored entries only)

    private static func le16(_ value: UInt16) -> Data {
        withUnsafeBytes(of: value.littleEndian) { Data($0) }
    }

    private static func le32(_ value: UInt32) -> Data {
        withUnsafeBytes(of: value.littleEndian) { Data($0) }
    }

    /// Builds a ZIP archive with every entry stored (method 0) and real CRCs.
    static func zip(_ specs: [ZipSpec]) -> Data {
        var out = Data()
        var records: [(spec: ZipSpec, offset: Int, crc: UInt32)] = []

        for spec in specs {
            let nameBytes = Data(spec.path.utf8)
            let crc = crc32(spec.contents)
            let offset = out.count

            out += le32(0x0403_4B50)                      // local file header
            out += le16(20)                               // version needed
            out += le16(0)                                // flags
            out += le16(0)                                // method: stored
            out += le16(0)                                // mod time
            out += le16(0x21)                             // mod date
            out += le32(crc)
            out += le32(UInt32(truncatingIfNeeded: spec.contents.count))
            out += le32(UInt32(truncatingIfNeeded: spec.contents.count))
            out += le16(UInt16(nameBytes.count))
            out += le16(0)                                // extra length
            out += nameBytes
            out += spec.contents

            records.append((spec, offset, crc))
        }

        let directoryStart = out.count
        for record in records {
            let nameBytes = Data(record.spec.path.utf8)
            out += le32(0x0201_4B50)                      // central directory header
            out += le16(0x031E)                           // version made by: Unix, 3.0
            out += le16(20)                               // version needed
            out += le16(0)                                // flags
            out += le16(0)                                // method
            out += le16(0)                                // mod time
            out += le16(0x21)                             // mod date
            out += le32(record.crc)
            out += le32(UInt32(truncatingIfNeeded: record.spec.contents.count))
            out += le32(UInt32(truncatingIfNeeded: record.spec.contents.count))
            out += le16(UInt16(nameBytes.count))
            out += le16(0)                                // extra length
            out += le16(0)                                // comment length
            out += le16(0)                                // disk number start
            out += le16(0)                                // internal attributes
            out += le32(record.spec.externalAttributes ?? 0)
            out += le32(UInt32(truncatingIfNeeded: record.offset))
            out += nameBytes
        }
        let directorySize = out.count - directoryStart

        out += le32(0x0605_4B50)                          // end of central directory
        out += le16(0)                                    // disk number
        out += le16(0)                                    // disk with directory
        out += le16(UInt16(records.count))
        out += le16(UInt16(records.count))
        out += le32(UInt32(directorySize))
        out += le32(UInt32(directoryStart))
        out += le16(0)                                    // comment length

        return out
    }

    /// Reference CRC-32 (polynomial 0xEDB88320, reflected).
    static func crc32(_ data: Data) -> UInt32 {
        var crc: UInt32 = 0xFFFF_FFFF
        for byte in data {
            crc ^= UInt32(byte)
            for _ in 0..<8 {
                if crc & 1 != 0 {
                    crc = (crc >> 1) ^ 0xEDB8_8320
                } else {
                    crc >>= 1
                }
            }
        }
        return crc ^ 0xFFFF_FFFF
    }

    // MARK: - Mach-O specifications

    /// A synthetic thin Mach-O. The default is an arm64 64-bit little-endian
    /// binary with no load commands.
    struct MachOSpec {
        var magic: UInt32 = 0xFEED_FACF
        var cpuType: UInt32 = 0x0100_000C
        var cpuSubtype: UInt32 = 0
        /// Write every header field (including the first word) big-endian.
        var bigEndian = false
        var minOS: UInt32?
        var sdk: UInt32?
        var cryptID: UInt32?
        var uuid: [UInt8]?
        var dylibs: [String] = []
        var rpaths: [String] = []
        var segmentName: String?
        var corruptCommandSize = false
        var entitlementsXML: String?

        init() {}
    }

    /// Builds a thin Mach-O with the requested load commands.
    static func thinMachO(_ spec: MachOSpec) -> Data {
        let is64 = spec.magic == 0xFEED_FACF || spec.magic == 0xCFFA_EDFE
        let big = spec.bigEndian

        func be(_ value: UInt32) -> Data { withUnsafeBytes(of: value.bigEndian) { Data($0) } }
        func le(_ value: UInt32) -> Data { withUnsafeBytes(of: value.littleEndian) { Data($0) } }
        func word(_ value: UInt32) -> Data { big ? be(value) : le(value) }
        func word64(_ value: UInt64) -> Data {
            let low = UInt32(truncatingIfNeeded: value >> 32)
            let high = UInt32(truncatingIfNeeded: value)
            return big ? be(low) + be(high) : le(high) + le(low)
        }
        func align8(_ n: Int) -> Int { (n + 7) & ~7 }
        func padded(_ string: String, to length: Int) -> Data {
            let bytes = Data(string.utf8).prefix(length)
            return bytes + Data(repeating: 0, count: length - bytes.count)
        }

        var commands: [Data] = []

        // LC_LOAD_DYLIB
        for name in spec.dylibs {
            let nameBytes = Data(name.utf8) + Data([0])
            let cmdSize = align8(24 + nameBytes.count)
            var c = word(0xC) + word(UInt32(cmdSize)) + word(24)
            c += word(1) + word(0) + word(0)              // timestamp, versions
            c += nameBytes
            while c.count < cmdSize { c.append(0) }
            commands.append(c)
        }

        // LC_RPATH
        for path in spec.rpaths {
            let pathBytes = Data(path.utf8) + Data([0])
            let cmdSize = align8(12 + pathBytes.count)
            var c = word(0x8000_001C) + word(UInt32(cmdSize)) + word(12)
            c += pathBytes
            while c.count < cmdSize { c.append(0) }
            commands.append(c)
        }

        // LC_BUILD_VERSION
        if let minOS = spec.minOS {
            var c = word(0x32) + word(24)
            c += word(2)                                   // platform: iOS
            c += word(minOS) + word(spec.sdk ?? 0)
            c += word(0)                                   // ntools
            commands.append(c)
        }

        // LC_UUID
        if let uuid = spec.uuid {
            var c = word(0x1B) + word(24)
            c += Data(uuid.prefix(16))
            while c.count < 24 { c.append(0) }
            commands.append(c)
        }

        // LC_SEGMENT_64 with two sections.
        if let segmentName = spec.segmentName, is64 {
            var c = word(0x19) + word(232)                 // 72 + 2 * 80
            c += padded(segmentName, to: 16)
            c += word64(0)                                 // vmaddr
            c += word64(0x1000)                            // vmsize
            c += word64(0)                                 // file offset
            c += word64(16)                                // file size
            c += word(5) + word(5)                         // maxprot, initprot: r-x
            c += word(2)                                   // nsects
            c += word(0)                                   // flags
            for (index, sectionName) in ["__text", "__objc_methname"].enumerated() {
                c += padded(sectionName, to: 16)
                c += padded(segmentName, to: 16)
                c += word64(UInt64(index) * 8)             // address
                c += word64(8)                             // size
                c += word(0)                               // offset
                c += word(0)                               // alignment
                c += word(0)                               // relocations
                c += word(0)                               // nrelocs
                c += word(0)                               // flags
                c += word(0)                               // reserved 1
                c += word(0)                               // reserved 2
                c += word(0)                               // reserved 3
            }
            commands.append(c)
        }

        // LC_ENCRYPTION_INFO(_64). The struct is 20 bytes, but every load
        // command must occupy a multiple of 8 bytes, so it is padded to 24 —
        // exactly what the toolchain emits for real binaries.
        if let cryptID = spec.cryptID {
            var c = word(is64 ? 0x2C : 0x21) + word(24)
            c += word(0) + word(16)                        // cryptoff, cryptsize
            c += word(cryptID)
            while c.count < 24 { c.append(0) }             // alignment padding
            commands.append(c)
        }

        // LC_CODE_SIGNATURE (offset and size patched once the blob size is known)
        var signatureCommand: Data?
        if spec.entitlementsXML != nil {
            signatureCommand = word(0x1D) + word(8) + word(0) + word(0)
        }

        if spec.corruptCommandSize {
            if commands.isEmpty {
                commands.append(word(0x2) + word(4))       // LC_SYMTAB, invalid size
            } else {
                var first = commands[0]
                first.replaceSubrange(4..<8, with: word(4))
                commands[0] = first
            }
        }

        var allCommands = commands
        if let signatureCommand { allCommands.append(signatureCommand) }
        let ncmds = allCommands.count
        let sizeofcmds = allCommands.reduce(0) { $0 + $1.count }

        var out = Data()
        out += word(spec.magic)
        out += word(spec.cpuType)
        out += word(spec.cpuSubtype)
        out += word(0)                                     // reserved
        out += word(UInt32(ncmds))
        out += word(UInt32(sizeofcmds))
        out += word(0)                                     // flags
        if is64 { out += word(0) }                         // reserved
        // Plain commands first; the code-signature command is written after
        // the loop with its data offset and size patched in, so it appears
        // exactly once.
        for command in commands { out += command }

        if let xml = spec.entitlementsXML, let signatureCommand {
            let blob = codeSignatureSuperBlob(entitlementsXML: xml)
            // The SuperBlob sits directly after the 8-byte LC_CODE_SIGNATURE.
            let dataOffset = out.count + 8
            var patched = signatureCommand
            patched.replaceSubrange(8..<12, with: big
                ? withUnsafeBytes(of: UInt32(dataOffset).bigEndian) { Data($0) }
                : withUnsafeBytes(of: UInt32(dataOffset).littleEndian) { Data($0) })
            patched.replaceSubrange(12..<16, with: big
                ? withUnsafeBytes(of: UInt32(blob.count).bigEndian) { Data($0) }
                : withUnsafeBytes(of: UInt32(blob.count).littleEndian) { Data($0) })
            out += patched
            out += blob
        }
        return out
    }

    /// A code-signature SuperBlob containing exactly one entitlements blob.
    private static func codeSignatureSuperBlob(entitlementsXML: String) -> Data {
        func be(_ value: UInt32) -> Data { withUnsafeBytes(of: value.bigEndian) { Data($0) } }

        let xml = Data(entitlementsXML.utf8)
        var blob = Data()
        blob += be(0xFADE_7171)                            // entitlements magic
        blob += be(UInt32(xml.count + 8))
        blob += xml

        var superblob = Data()
        superblob += be(0xFADE_0CC0)                       // SuperBlob magic
        superblob += be(UInt32(12 + 8 + blob.count))
        superblob += be(1)                                 // one index entry
        superblob += be(0xFADE_7171)                       // slot type
        superblob += be(28)                                // 12 + 2 * 8
        superblob += blob
        return superblob
    }

    /// Builds a FAT (multi-architecture) container from thin slices.
    static func fat(slices: [(cpuType: UInt32, cpuSubtype: UInt32, data: Data)],
                    is64: Bool = false) -> Data {
        func be(_ value: UInt32) -> Data { withUnsafeBytes(of: value.bigEndian) { Data($0) } }
        func be64(_ value: UInt64) -> Data { withUnsafeBytes(of: value.bigEndian) { Data($0) } }

        var out = Data()
        out += be(is64 ? 0xCAFEBABF : 0xCAFEBABE)
        out += be(UInt32(slices.count))

        let entrySize = is64 ? 32 : 20
        var offset = 8 + slices.count * entrySize
        for slice in slices {
            out += be(slice.cpuType)
            out += be(slice.cpuSubtype)
            if is64 {
                out += be64(UInt64(offset))
                out += be64(UInt64(slice.data.count))
                out += be64(12)                            // alignment
            } else {
                out += be(UInt32(offset))
                out += be(UInt32(slice.data.count))
                out += be(12)                              // alignment
            }
            offset += slice.data.count
        }
        for slice in slices { out += slice.data }
        return out
    }

    // MARK: - Synthetic IPA

    static let sampleEntitlementsXML = """
    <?xml version="1.0" encoding="UTF-8"?>
    <!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
    <plist version="1.0">
    <dict>
        <key>application-identifier</key>
        <string>ABCD1234EG.com.example.sample</string>
        <key>com.apple.developer.associated-domains</key>
        <array>
            <string>applinks:example.com</string>
        </array>
        <key>get-task-allow</key>
        <false/>
    </dict>
    </plist>
    """

    /// Assembles a complete synthetic IPA: Info.plist, a Mach-O main executable
    /// (optionally FairPlay-encrypted), a config file with a URL and a Google
    /// API key, a privacy manifest, Unity markers, plus any extra entries.
    static func sampleIPA(executableEncrypted: Bool = false,
                          extraEntries: [ZipSpec] = []) -> Data {
        var specs: [ZipSpec] = []

        let info: [String: Any] = [
            "CFBundleIdentifier": "com.example.sample",
            "CFBundleShortVersionString": "1.2.3",
            "CFBundleVersion": "42",
            "CFBundleExecutable": "Sample",
            "CFBundleDisplayName": "Sample",
            "CFBundleName": "Sample",
            "MinimumOSVersion": "17.0",
            "UIDeviceFamily": [1],
            "NSCameraUsageDescription": "To scan documents.",
            "CFBundleURLTypes": [
                ["CFBundleURLName": "com.example.sample",
                 "CFBundleURLSchemes": ["sampleapp"]]
            ],
            "NSAppTransportSecurity": ["NSAllowsArbitraryLoads": false],
        ]
        specs.append(ZipSpec(
            path: "Payload/Sample.app/Info.plist",
            contents: xmlPlist(info),
            externalAttributes: regularAttributes()))

        var executable = MachOSpec()
        executable.dylibs = [
            "@rpath/FirebaseCore.framework/FirebaseCore",
            "@rpath/UnityFramework.framework/UnityFramework",
            "/usr/lib/libobjc.A.dylib",
        ]
        executable.rpaths = ["@executable_path/Frameworks"]
        executable.cryptID = executableEncrypted ? 1 : 0
        executable.uuid = (0..<16).map { UInt8($0) }
        executable.minOS = 0x0011_0000                   // 17.0.0
        executable.sdk = 0x0012_0000                     // 18.0.0
        executable.segmentName = "__TEXT"
        executable.entitlementsXML = sampleEntitlementsXML
        specs.append(ZipSpec(
            path: "Payload/Sample.app/Sample",
            contents: thinMachO(executable),
            externalAttributes: regularAttributes()))

        let config = """
        {
          "api_endpoint": "https://api.example.com/v1/items",
          "telemetry": "https://telemetry.example.org/beacon",
          "google_api_key": "AIza1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8S"
        }
        """
        specs.append(ZipSpec(
            path: "Payload/Sample.app/config.json",
            contents: Data(config.utf8),
            externalAttributes: regularAttributes()))

        let privacy: [String: Any] = [
            "NSPrivacyTracking": true,
            "NSPrivacyTrackingDomains": ["tracker.example.net"],
            "NSPrivacyCollectedDataTypes": [["NSPrivacyCollectedDataType": "NSPrivacyCollectedDataTypeEmailAddress"]],
            "NSPrivacyAccessedAPITypes": [["NSPrivacyAccessedAPIType": "NSPrivacyAccessedAPICategoryUserDefaults"]],
        ]
        specs.append(ZipSpec(
            path: "Payload/Sample.app/PrivacyInfo.xcprivacy",
            contents: xmlPlist(privacy),
            externalAttributes: regularAttributes()))

        specs.append(ZipSpec(
            path: "Payload/Sample.app/Frameworks/UnityFramework.framework/UnityFramework",
            contents: Data("placeholder framework binary".utf8),
            externalAttributes: regularAttributes()))
        specs.append(ZipSpec(
            path: "Payload/Sample.app/Data/level0.assetbundle",
            contents: Data(repeating: 0x41, count: 256),
            externalAttributes: regularAttributes()))

        specs.append(contentsOf: extraEntries)
        return zip(specs)
    }

    /// Serializes a dictionary as an XML property list.
    private static func xmlPlist(_ value: Any) -> Data {
        (try? PropertyListSerialization.data(fromPropertyList: value, format: .xml, options: 0)) ?? Data()
    }
}

// MARK: - ZipArchive.Entry test constructors

extension ZipArchive.Entry {
    /// Full-fidelity test constructor: carries the payload that a fixture
    /// builder should write for a stored entry, plus explicit size fields.
    init(path: String,
         contents: Data,
         compressionMethod: UInt16 = 0,
         localHeaderOffset: Int64 = 0,
         isSymlink: Bool = false,
         isDirectory: Bool = false,
         compressedSize: Int64? = nil,
         uncompressedSize: Int64? = nil,
         unixMode: UInt16? = nil) {
        self.init(path: path,
                  compressedSize: compressedSize ?? Int64(contents.count),
                  uncompressedSize: uncompressedSize ?? Int64(contents.count),
                  compressionMethod: compressionMethod,
                  localHeaderOffset: localHeaderOffset,
                  isSymlink: isSymlink,
                  isDirectory: isDirectory,
                  unixMode: unixMode)
    }

    /// Constructor mirroring real archives: Unix mode taken from the external
    /// attributes' high 16 bits.
    init(path: String, contents: Data, externalAttributes: UInt32) {
        let mode = UInt16((externalAttributes >> 16) & 0xFFFF)
        self.init(path: path,
                  contents: contents,
                  isSymlink: (mode & 0xF000) == 0xA000,
                  isDirectory: path.hasSuffix("/"),
                  unixMode: mode == 0 ? nil : mode)
    }
}
