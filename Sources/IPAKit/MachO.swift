import Foundation

// MARK: - Constants

enum MachO {
    // Thin magics (little-endian read of the first word)
    static let magic32: UInt32        = 0xFEEDFACE
    static let magic64: UInt32        = 0xFEEDFACF
    static let magic32Swapped: UInt32 = 0xCEFAEDFE
    static let magic64Swapped: UInt32 = 0xCFFAEDFE
    // FAT magics (big-endian read of the first word)
    static let fatMagic: UInt32   = 0xCAFEBABE
    static let fat64Magic: UInt32 = 0xCAFEBABF

    // LC_REQ_DYLD flag
    static let reqDyld: UInt32 = 0x80000000

    enum LoadCommand: UInt32 {
        case segment32        = 0x1
        case symtab           = 0x2
        case uuid             = 0x1B
        case segment64        = 0x19
        case codeSignature    = 0x1D
        case versionMinIPhone = 0x25
        case versionMinMacOS  = 0x24
        case versionMinTVOS   = 0x2F
        case versionMinWatch  = 0x30
        case encryptionInfo   = 0x21
        case encryptionInfo64 = 0x2C
        case rpath            = 0x8000001C
        case buildVersion     = 0x32
        case loadDylib        = 0xC
        case idDylib          = 0xD
        case loadWeakDylib    = 0x80000018
        case reexportDylib    = 0x8000001F
        case lazyLoadDylib    = 0x20
        case dyldEnvironment  = 0x27
    }

    /// Those load commands that carry a `lc_str` offset at +8.
    static func isDylibCommand(_ cmd: UInt32) -> Bool {
        switch cmd {
        case LoadCommand.loadDylib.rawValue, LoadCommand.idDylib.rawValue,
             LoadCommand.loadWeakDylib.rawValue, LoadCommand.reexportDylib.rawValue,
             LoadCommand.lazyLoadDylib.rawValue:
            return true
        default:
            return false
        }
    }

    static func platformName(_ raw: UInt32) -> String {
        switch raw {
        case 1: return "macOS"
        case 2: return "iOS"
        case 3: return "tvOS"
        case 4: return "watchOS"
        case 5: return "bridgeOS"
        case 6: return "macCatalyst"
        case 7: return "iOSSimulator"
        case 8: return "tvOSSimulator"
        case 9: return "watchOSSimulator"
        case 10: return "driverKit"
        case 11: return "visionOS"
        case 12: return "visionOSSimulator"
        default: return "platform \(raw)"
        }
    }

    static func cpuName(type: UInt32, subtype: UInt32) -> String {
        // subtype's low byte is the "real" subtype; bit 0x80000000 marks 64-bit
        // variants on some architectures.
        let sub = subtype & 0x00FF_FFFF
        switch type {
        case 7:  return "x86"
        case 0x0100_0007: return "x86_64"
        case 12:
            switch sub {
            case 9: return "armv7"
            case 11: return "armv7s"
            case 12: return "armv7k"
            default: return "armv7+"
            }
        case 0x0100_000C:
            switch sub {
            case 0: return "arm64"
            case 1: return "arm64v8"
            case 2: return "arm64e"
            default: return "arm64+"
            }
        default:
            return String(format: "cpu type 0x%08X", type)
        }
    }
}

// MARK: - Compatibility errors

enum MachOError: LocalizedError, Equatable {
    case notMachO
    case truncated(String)
    case malformed(String)

    var errorDescription: String? {
        switch self {
        case .notMachO: return "Not a Mach-O file."
        case .truncated(let what): return "Truncated file: \(what)"
        case .malformed(let what): return "Malformed Mach-O: \(what)"
        }
    }
}

// MARK: - Parser

enum MachOParser {

    /// Cheap sniff of the first four bytes. Does not mean the file will parse.
    /// A Java `.class` file shares the FAT magic, so callers must still call
    /// `parse` and handle `.notMachO`.
    static func looksLikeMachO(_ head: Data) -> Bool {
        guard head.count >= 4 else { return false }
        let r = ByteReader(head, label: "head")
        let le = r.u32(0, bigEndian: false) ?? 0
        let be = r.u32(0, bigEndian: true) ?? 0
        return le == MachO.magic32 || le == MachO.magic64
            || le == MachO.magic32Swapped || le == MachO.magic64Swapped
            || be == MachO.fatMagic || be == MachO.fat64Magic
    }

    /// Parses a Mach-O file, returning one ArchInfo per architecture slice.
    /// A FAT container yields several; a thin file yields exactly one.
    static func parse(_ data: Data, label: String = "binary") throws -> [ArchInfo] {
        let r = ByteReader(data, label: label)
        guard let beMagic = r.u32(0, bigEndian: true) else {
            throw MachOError.truncated("file is shorter than 4 bytes")
        }
        if beMagic == MachO.fatMagic || beMagic == MachO.fat64Magic {
            return try parseFat(r, magic: beMagic)
        }
        return [try parseThin(r, offset: 0, size: data.count)]
    }

    // MARK: FAT

    private static func parseFat(_ r: ByteReader, magic: UInt32) throws -> [ArchInfo] {
        let is64 = magic == MachO.fat64Magic
        let entrySize = is64 ? 32 : 20
        guard let rawCount = r.u32(4, bigEndian: true) else {
            throw MachOError.truncated("FAT header has no architecture count")
        }
        let count = Int(rawCount)
        // Guard against the Java class-file false positive and hostile counts.
        guard count > 0, count <= 64 else {
            throw MachOError.malformed("FAT architecture count \(count) is implausible")
        }
        // A Java .class file shares the FAT magic and carries a version count
        // (52 for modern classes) with no slice table behind it. The table
        // must fit the file, so an implausible count is malformed, not merely
        // truncated.
        guard r.fits(8, count * entrySize) else {
            throw MachOError.malformed(
                "FAT header claims \(count) architectures (\(count * entrySize) bytes of entries) " +
                "but the file is only \(max(0, r.count - 8)) bytes past the header")
        }

        var archs: [ArchInfo] = []
        for i in 0..<count {
            let base = 8 + i * entrySize
            guard let cpuType = r.u32(base, bigEndian: true),
                  let cpuSubtype = r.u32(base + 4, bigEndian: true) else { continue }
            let offsetWidth = is64 ? 8 : 4
            guard let offsetRaw = r.uint(base + 8, size: offsetWidth, bigEndian: true),
                  let sizeRaw = r.uint(base + 8 + offsetWidth, size: offsetWidth, bigEndian: true) else { continue }

            let offset = Int(offsetRaw)
            let size = Int(sizeRaw)
            guard offset >= 0, size > 0, offset <= r.count, size <= r.count - offset else {
                // Record rather than throw: one bad slice shouldn't lose the rest.
                var broken = ArchInfo()
                broken.cpu = MachO.cpuName(type: cpuType, subtype: cpuSubtype)
                broken.cpuTypeRaw = cpuType
                broken.cpuSubtypeRaw = cpuSubtype
                broken.warnings.append("FAT slice \(i) points outside the file (offset \(offset), size \(size))")
                archs.append(broken)
                continue
            }
            var arch = try parseThin(r, offset: offset, size: size)
            arch.cpuTypeRaw = cpuType
            arch.cpuSubtypeRaw = cpuSubtype
            // The FAT entry is authoritative for the architecture name: it is
            // what Apple's tools record, and the slice header may disagree.
            arch.cpu = MachO.cpuName(type: cpuType, subtype: cpuSubtype)
            archs.append(arch)
        }
        return archs
    }

    // MARK: Thin

    private static func ver(_ v: UInt32) -> String {
        "\(v >> 16).\((v >> 8) & 0xFF).\(v & 0xFF)"
    }

    private static func parseThin(_ outer: ByteReader, offset: Int, size: Int) throws -> ArchInfo {
        guard let sliceData = outer.subdata(offset, size) else {
            throw MachOError.truncated("slice \(offset)+\(size) is outside the file")
        }
        let d = ByteReader(sliceData, label: outer.label)
        guard let raw = d.u32(0, bigEndian: false) else {
            throw MachOError.truncated("slice has no header")
        }

        let is64: Bool
        let swapped: Bool
        switch raw {
        case MachO.magic64:        is64 = true;  swapped = false
        case MachO.magic32:        is64 = false; swapped = false
        case MachO.magic64Swapped: is64 = true;  swapped = true
        case MachO.magic32Swapped: is64 = false; swapped = true
        default:
            throw MachOError.notMachO
        }
        // The header is read with `swapped`, but the first word must be read
        // little-endian to identify it, exactly as above.
        let big = swapped

        var arch = ArchInfo()
        arch.is64Bit = is64
        guard let cpuType = d.u32(4, bigEndian: big),
              let cpuSubtype = d.u32(8, bigEndian: big),
              let ncmds = d.u32(16, bigEndian: big),
              let sizeofcmds = d.u32(20, bigEndian: big) else {
            throw MachOError.truncated("header fields")
        }
        arch.cpuTypeRaw = cpuType
        arch.cpuSubtypeRaw = cpuSubtype
        arch.cpu = MachO.cpuName(type: cpuType, subtype: cpuSubtype)

        let headerSize = is64 ? 32 : 28
        let commandCount = Int(ncmds)
        guard commandCount <= 4096 else {
            throw MachOError.malformed("\(commandCount) load commands is implausible")
        }
        let commandsSize = Int(sizeofcmds)
        guard d.fits(headerSize, commandsSize) else {
            throw MachOError.truncated("load command table (\(commandsSize) bytes) exceeds the file")
        }

        var cursor = headerSize
        let commandLimit = headerSize + commandsSize

        for index in 0..<commandCount {
            guard cursor + 8 <= commandLimit else {
                arch.warnings.append("load command \(index) starts past the end of the command table")
                break
            }
            guard let rawCmd = d.u32(cursor, bigEndian: big),
                  let rawSize = d.u32(cursor + 4, bigEndian: big) else {
                arch.warnings.append("load command \(index) header is truncated")
                break
            }
            // size includes the 8-byte cmd/size header and must be 8-aligned.
            let cmdSize = Int(rawSize)
            guard cmdSize >= 8, (cmdSize % 8) == 0, cursor + cmdSize <= commandLimit else {
                arch.warnings.append("load command \(index) has an invalid size (\(cmdSize))")
                break
            }
            // The switch matches on the raw command value: the LC_REQ_DYLD bit
            // is part of the weak/re-export command identities.
            let body = cursor
            let cmd = rawCmd

            switch cmd {
            case MachO.LoadCommand.segment64.rawValue, MachO.LoadCommand.segment32.rawValue:
                if let seg = parseSegment(d, at: body, is64: is64 && cmd == MachO.LoadCommand.segment64.rawValue, big: big) {
                    arch.segments.append(seg)
                } else {
                    arch.warnings.append("segment \(index) could not be parsed")
                }

            case MachO.LoadCommand.uuid.rawValue:
                if let bytes = d.subdata(body + 8, 16) {
                    arch.uuid = formatUUID(bytes)
                }

            case MachO.LoadCommand.encryptionInfo.rawValue, MachO.LoadCommand.encryptionInfo64.rawValue:
                if let cryptID = d.u32(body + 16, bigEndian: big) {
                    arch.cryptID = cryptID
                    arch.encrypted = cryptID != 0
                }

            case MachO.LoadCommand.buildVersion.rawValue:
                // struct build_version_command { platform, minos, sdk, ntools }
                if let platform = d.u32(body + 8, bigEndian: big),
                   let minos = d.u32(body + 12, bigEndian: big),
                   let sdk = d.u32(body + 16, bigEndian: big) {
                    arch.platform = MachO.platformName(platform)
                    arch.minOS = ver(minos)
                    arch.sdk = ver(sdk)
                }

            case MachO.LoadCommand.versionMinIPhone.rawValue,
                 MachO.LoadCommand.versionMinMacOS.rawValue,
                 MachO.LoadCommand.versionMinTVOS.rawValue,
                 MachO.LoadCommand.versionMinWatch.rawValue:
                if let minos = d.u32(body + 8, bigEndian: big),
                   let sdk = d.u32(body + 12, bigEndian: big) {
                    arch.minOS = ver(minos)
                    arch.sdk = ver(sdk)
                    if arch.platform == nil {
                        switch cmd {
                        case MachO.LoadCommand.versionMinIPhone.rawValue: arch.platform = "iOS"
                        case MachO.LoadCommand.versionMinMacOS.rawValue:  arch.platform = "macOS"
                        case MachO.LoadCommand.versionMinTVOS.rawValue:   arch.platform = "tvOS"
                        default:                                          arch.platform = "watchOS"
                        }
                    }
                }

            case MachO.LoadCommand.rpath.rawValue:
                if let nameOffset = d.u32(body + 8, bigEndian: big),
                   let path = d.cString(body + Int(nameOffset)) {
                    arch.rpaths.append(path)
                }

            case MachO.LoadCommand.loadDylib.rawValue, MachO.LoadCommand.loadWeakDylib.rawValue,
                 MachO.LoadCommand.reexportDylib.rawValue, MachO.LoadCommand.lazyLoadDylib.rawValue,
                 MachO.LoadCommand.idDylib.rawValue:
                if let nameOffset = d.u32(body + 8, bigEndian: big),
                   let name = d.cString(body + Int(nameOffset)), !name.isEmpty {
                    switch cmd {
                    case MachO.LoadCommand.loadDylib.rawValue:      arch.dylibs.append(name)
                    case MachO.LoadCommand.loadWeakDylib.rawValue:  arch.weakDylibs.append(name)
                    case MachO.LoadCommand.reexportDylib.rawValue:  arch.reexportedDylibs.append(name)
                    case MachO.LoadCommand.idDylib.rawValue:        break // install name, not a dependency
                    default:                                        arch.dylibs.append(name)
                    }
                }

            case MachO.LoadCommand.codeSignature.rawValue:
                if let dataOffset = d.u32(body + 8, bigEndian: big),
                   let dataSize = d.u32(body + 12, bigEndian: big) {
                    arch.linkedItOffset = UInt64(dataOffset)
                    if let sig = d.subdata(Int(dataOffset), Int(dataSize)) {
                        arch.entitlementsXML = CodeSignature.entitlementsXML(signature: sig)
                    } else {
                        arch.warnings.append("LC_CODE_SIGNATURE points outside the file")
                    }
                }

            default:
                break
            }
            cursor += cmdSize
        }

        if arch.cryptID == nil {
            // No encryption load command. Not an error, but worth recording: an
            // App Store main executable always has one.
            arch.warnings.append("no LC_ENCRYPTION_INFO load command present")
        }
        return arch
    }

    private static func parseSegment(_ d: ByteReader, at body: Int, is64: Bool, big: Bool) -> SegmentInfo? {
        // struct segment_command(_64) {
        //   cmd, cmdsize, segname[16], vmaddr, vmsize, fileoff, filesize,
        //   maxprot, initprot, nsects, flags
        // }
        guard let vmSize = d.uint(body + 32, size: is64 ? 8 : 4, bigEndian: big),
              let fileOffset = d.uint(body + (is64 ? 40 : 36), size: is64 ? 8 : 4, bigEndian: big),
              let fileSize = d.uint(body + (is64 ? 48 : 40), size: is64 ? 8 : 4, bigEndian: big),
              let maxProt = d.u32(body + (is64 ? 56 : 44), bigEndian: big),
              let nsects = d.u32(body + (is64 ? 64 : 48), bigEndian: big),
              let name = d.cString(body + 8, limit: 16) else { return nil }

        let sectionOffset = body + (is64 ? 72 : 56)
        let sectionSize = is64 ? 80 : 68
        var sections: [SectionInfo] = []
        for s in 0..<Int(min(nsects, 4096)) {
            let base = sectionOffset + s * sectionSize
            guard let name = d.cString(base, limit: 16),
                  let segName = d.cString(base + 16, limit: 16),
                  let address = d.uint(base + 32, size: is64 ? 8 : 4, bigEndian: big),
                  let size = d.uint(base + (is64 ? 40 : 36), size: is64 ? 8 : 4, bigEndian: big),
                  let offset = d.u32(base + (is64 ? 48 : 40), bigEndian: big) else { break }
            sections.append(SectionInfo(segmentName: segName, name: name,
                                        address: address, size: size, offset: offset))
        }

        // A segment whose file range falls outside the file is a real defect in
        // the sample; flag it instead of quietly reporting bogus values.
        let truncated = fileOffset + fileSize > UInt64(d.count)
        return SegmentInfo(name: name, vmSize: vmSize, fileOffset: fileOffset,
                           fileSize: fileSize, maxProt: maxProt,
                           sections: sections, truncated: truncated)
    }

    static func formatUUID(_ bytes: Data) -> String {
        let hex = bytes.map { String(format: "%02X", $0) }.joined()
        guard hex.count == 32 else { return hex }
        func slice(_ a: Int, _ b: Int) -> Substring { hex[hex.index(hex.startIndex, offsetBy: a)..<hex.index(hex.startIndex, offsetBy: b)] }
        return "\(slice(0,8))-\(slice(8,12))-\(slice(12,16))-\(slice(16,20))-\(slice(20,32))"
    }
}

// MARK: - Code signature / entitlements

enum CodeSignature {
    /// SuperBlob magic values from Apple's `cs_blobs.h`.
    static let superBlob: UInt32     = 0xFADE0CC0
    static let blobWrapper: UInt32   = 0xFADE0B01   // CMS signature
    static let entitlements: UInt32  = 0xFADE7171
    static let entitlementsDER: UInt32 = 0xFADE7172

    /// Walks the SuperBlob index and returns the XML entitlements plist, if present.
    static func entitlementsXML(signature: Data) -> String? {
        let r = ByteReader(signature, label: "code signature")
        guard let magic = r.u32(0, bigEndian: true), magic == superBlob else { return nil }
        guard let countRaw = r.u32(8, bigEndian: true) else { return nil }
        let count = Int(min(countRaw, 256))
        // SuperBlob header is magic, length, count; then `count` index entries
        // of { type: UInt32, offset: UInt32 } — 8 bytes each, starting at 12.
        guard r.fits(12, count * 8) else { return nil }

        for i in 0..<count {
            let entry = 12 + i * 8
            guard let type = r.u32(entry, bigEndian: true),
                  let offset = r.u32(entry + 4, bigEndian: true) else { continue }
            guard type == entitlements || type == entitlementsDER else { continue }
            let blobOffset = Int(offset)
            guard let blobMagic = r.u32(blobOffset, bigEndian: true), blobMagic == type,
                  let blobLength = r.u32(blobOffset + 4, bigEndian: true) else { continue }
            let length = Int(blobLength)
            guard length > 8, r.fits(blobOffset, length),
                  let body = r.subdata(blobOffset + 8, length - 8) else { continue }
            if type == entitlements {
                return String(data: body, encoding: .utf8)
            }
            return "(entitlements present in DER form, \(body.count) bytes — not decoded)"
        }
        return nil
    }
}
