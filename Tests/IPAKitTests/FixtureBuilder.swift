import Foundation
@testable import IPAKit

/// Deterministic fixture construction for every test: ZIP archives, Mach-O
/// images (thin and FAT), and a complete synthetic IPA with frameworks,
/// extensions, plists, strings and secrets.
enum FixtureBuilder {

    // MARK: - ZIP

    struct ZipSpec {
        var path: String
        var contents: Data
        var externalAttributes: UInt32? = nil
        var method: UInt16 = 0            // 0 = stored

        init(path: String, contents: String, externalAttributes: UInt32? = nil) {
            self.path = path
            self.contents = Data(contents.utf8)
            self.externalAttributes = externalAttributes
        }

        init(path: String, contents: Data, externalAttributes: UInt32? = nil) {
            self.path = path
            self.contents = contents
            self.externalAttributes = externalAttributes
        }
    }

    static func regularAttributes() -> UInt32 { (0o100644 << 16) | 0o644 }
    static func symlinkAttributes() -> UInt32 { (0o120777 << 16) | 0o777 }
    static func executableAttributes() -> UInt32 { (0o100755 << 16) | 0o755 }

    /// CRC-32 (IEEE 802.3, reflected), reference implementation.
    static func crc32(_ data: Data) -> UInt32 {
        var table: [UInt32] = (0..<256).map { i -> UInt32 in
            var c: UInt32 = UInt32(i)
            for _ in 0..<8 {
                c = (c & 1) != 0 ? (0xEDB8_8320 ^ (c >> 1)) : (c >> 1)
            }
            return c
        }
        var crc: UInt32 = 0xFFFF_FFFF
        for byte in [UInt8](data) {
            crc = table[Int((crc ^ UInt32(byte)) & 0xFF)] ^ (crc >> 8)
        }
        return crc ^ 0xFFFF_FFFF
    }

    /// Builds a ZIP archive with stored (uncompressed) entries.
    static func zip(_ specs: [ZipSpec]) -> Data {
        var out = Data()
        var central = Data()
        var count: UInt16 = 0

        for spec in specs {
            let nameBytes = Array(spec.path.utf8)
            let crc = crc32(spec.contents)
            let offset = Int64(out.count)
            let size = Int64(spec.contents.count)

            var local = Data()
            local.appendLE32(0x0403_4B50)
            local.appendLE16(20)                      // version needed
            local.appendLE16(0)                       // flags
            local.appendLE16(spec.method)
            local.appendLE16(0)                       // mod time
            local.appendLE16(0)                       // mod date
            local.appendLE32(crc)
            local.appendLE32(UInt32(bitPattern: Int32(truncatingIfNeeded: size)))
            local.appendLE32(UInt32(bitPattern: Int32(truncatingIfNeeded: size)))
            local.appendLE16(UInt16(nameBytes.count))
            local.appendLE16(0)                       // extra len
            local.append(contentsOf: nameBytes)
            local.append(spec.contents)
            out.append(local)

            var c = Data()
            c.appendLE32(0x0201_4B50)
            c.appendLE16((3 << 8) | 20)               // made by: Unix, 2.0
            c.appendLE16(20)                          // version needed
            c.appendLE16(0)                           // flags
            c.appendLE16(spec.method)
            c.appendLE16(0)                           // time
            c.appendLE16(0)                           // date
            c.appendLE32(crc)
            c.appendLE32(UInt32(bitPattern: Int32(truncatingIfNeeded: size)))
            c.appendLE32(UInt32(bitPattern: Int32(truncatingIfNeeded: size)))
            c.appendLE16(UInt16(nameBytes.count))
            c.appendLE16(0)                           // extra
            c.appendLE16(0)                           // comment
            c.appendLE16(0)                           // disk start
            c.appendLE16(0)                           // internal attrs
            c.appendLE32(spec.externalAttributes ?? regularAttributes())
            c.appendLE32(UInt32(bitPattern: Int32(truncatingIfNeeded: offset)))
            c.append(contentsOf: nameBytes)
            central.append(c)

            count += 1
        }

        let cdOffset = Int64(out.count)
        let cdSize = Int64(central.count)
        out.append(central)

        var eocd = Data()
        eocd.appendLE32(0x0605_4B50)
        eocd.appendLE16(0)                            // disk
        eocd.appendLE16(0)                            // cd disk
        eocd.appendLE16(count)
        eocd.appendLE16(count)
        eocd.appendLE32(UInt32(bitPattern: Int32(truncatingIfNeeded: cdSize)))
        eocd.appendLE32(UInt32(bitPattern: Int32(truncatingIfNeeded: cdOffset)))
        eocd.appendLE16(0)                            // comment len
        out.append(eocd)
        return out
    }

    // MARK: - Mach-O

    struct MachOSpec {
        var magic: UInt32 = 0xFEED_FACF               // MH_MAGIC_64 little-endian
        var bigEndian: Bool = false
        var cpuType: UInt32 = 0x0100_000C             // arm64
        var cpuSubtype: UInt32 = 0
        var minOS: UInt32? = nil                      // encoded x.y.z
        var sdk: UInt32? = nil
        var platformRaw: UInt32 = 2                   // iOS
        var cryptID: UInt32? = nil                    // nil: no encryption command
        var dylibs: [String] = []
        var weakDylibs: [String] = []
        var rpaths: [String] = []
        var uuid: [UInt8]? = nil
        var segmentName: String = "__TEXT"
        var corruptCommandSize: Bool = false
        var entitlementsXML: String? = nil
        var symbols: [(name: String, external: Bool, undefined: Bool)] = []
        var cstrings: [String] = []
    }

    private static func pad(_ n: Int) -> Int { (n + 7) & ~7 }

    /// Builds a thin Mach-O image with the requested load commands.
    ///
    /// Section offsets are absolute within the slice, mirroring what real
    /// tools emit, so section-based scans work against these fixtures.
    static func thinMachO(_ spec: MachOSpec) -> Data {
        let is64 = spec.magic == 0xFEED_FACF || spec.magic == 0xCFFA_EDFE
        // Field endianness follows the file's byte order: a swapped magic
        // written as little-endian bytes means a big-endian file.
        let fieldsBig = spec.bigEndian
            || spec.magic == 0xCFFA_EDFE || spec.magic == 0xCEFA_EDFE
        // The magic's on-disk bytes must match the field byte order: a
        // big-endian file stores the natural magic big-endian, and a swapped
        // magic written little-endian reads back as the swapped constant.
        let naturalMagic: UInt32
        switch spec.magic {
        case 0xCFFA_EDFE: naturalMagic = 0xFEED_FACF
        case 0xCEFA_EDFE: naturalMagic = 0xFEED_FACE
        default: naturalMagic = spec.magic
        }

        func encode(_ value: UInt32) -> Data {
            var d = Data()
            if fieldsBig { d.appendBE32(value) } else { d.appendLE32(value) }
            return d
        }
        func encode64(_ value: UInt64) -> Data {
            var d = Data()
            if fieldsBig { d.appendBE64(value) } else { d.appendLE64(value) }
            return d
        }

        let sectionPayload = spec.cstrings.isEmpty
            ? Data(repeating: 0x90, count: 48)
            : Data((spec.cstrings.map { $0 + "\0" }.joined()).utf8)
        let payloadSize = max(sectionPayload.count, 48)

        // --- upfront layout so section offsets can be absolute ---
        let headerSize = is64 ? 32 : 28
        func dylibSize(_ name: String) -> Int { 24 + pad(Array(name.utf8).count + 1) }
        func rpathSize(_ name: String) -> Int { pad(12 + Array(name.utf8).count + 1) }
        let segBodySize = is64 ? 64 + 2 * 76 : 48 + 2 * 60
        var commandsSize = 8 + segBodySize
            + (spec.uuid != nil ? 24 : 0)
            + 24                                       // build version
            + spec.dylibs.reduce(0) { $0 + dylibSize($1) }
            + spec.weakDylibs.reduce(0) { $0 + dylibSize($1) }
            + spec.rpaths.reduce(0) { $0 + rpathSize($1) }
            + (spec.cryptID != nil ? 24 : 0)
            + (spec.corruptCommandSize ? 12 : 0)
            + (spec.symbols.isEmpty ? 0 : 24)          // LC_SYMTAB
            + (spec.entitlementsXML != nil ? 16 : 0)   // LC_CODE_SIGNATURE
        let payloadOffset = headerSize + commandsSize

        var commands = Data()
        var extraData = Data()

        // --- LC_SEGMENT(_64) with two sections (__text, __cstring) ---
        var segBody = Data()
        var segNameBytes = Array(spec.segmentName.utf8).prefix(16)
        while segNameBytes.count < 16 { segNameBytes.append(0) }
        segBody.append(contentsOf: segNameBytes)
        if is64 {
            segBody.append(encode64(0))                    // vmaddr
            segBody.append(encode64(UInt64(payloadSize)))  // vmsize
            segBody.append(encode64(UInt64(payloadOffset)))// fileoff (absolute)
            segBody.append(encode64(UInt64(payloadSize)))  // filesize
        } else {
            segBody.append(encode(UInt32(0)))
            segBody.append(encode(UInt32(payloadSize)))
            segBody.append(encode(UInt32(payloadOffset)))
            segBody.append(encode(UInt32(payloadSize)))
        }
        segBody.append(encode(0x05))                   // maxprot r-x
        segBody.append(encode(0x05))                   // initprot
        segBody.append(encode(2))                      // nsects
        segBody.append(encode(0))                      // flags
        let sections: [(seg: String, name: String, addr: UInt32, size: UInt32)] = [
            ("__TEXT", "__text", 0, 32),
            ("__TEXT", "__cstring", 32, UInt32(payloadSize - 32)),
        ]
        for section in sections {
            var cn = Array(section.name.utf8).prefix(16); while cn.count < 16 { cn.append(0) }
            var sn = Array(section.seg.utf8).prefix(16); while sn.count < 16 { sn.append(0) }
            segBody.append(contentsOf: cn)              // sectname comes first
            segBody.append(contentsOf: sn)              // then segname
            if is64 {
                segBody.append(encode64(UInt64(section.addr)))
                segBody.append(encode64(UInt64(section.size)))
            } else {
                segBody.append(encode(section.addr))
                segBody.append(encode(section.size))
            }
            segBody.append(encode(UInt32(payloadOffset) + section.addr))   // absolute offset
            if is64 {
                segBody.append(encode(0))              // align
                segBody.append(encode(0))              // reloff
                segBody.append(encode(0))              // nreloc
                segBody.append(encode(0))              // flags
                segBody.append(encode(0))              // reserved1
                segBody.append(encode(0))              // reserved2
            } else {
                segBody.append(encode(0)); segBody.append(encode(0))
                segBody.append(encode(0)); segBody.append(encode(0))
            }
        }
        var segCmd = Data()
        segCmd.append(encode(is64 ? 0x19 : 0x01))
        segCmd.append(encode(UInt32(8 + segBody.count)))
        segCmd.append(segBody)
        commands.append(segCmd)

        // --- LC_UUID ---
        if let uuid = spec.uuid {
            var u = Data()
            u.append(encode(0x1B)); u.append(encode(24))
            u.append(contentsOf: uuid.prefix(16))
            commands.append(u)
        }

        // --- LC_BUILD_VERSION ---
        var bv = Data()
        bv.append(encode(0x32)); bv.append(encode(24))
        bv.append(encode(spec.platformRaw))
        bv.append(encode(spec.minOS ?? 0x0011_0000))
        bv.append(encode(spec.sdk ?? 0x0012_0000))
        bv.append(encode(0))                       // ntools: 6 dwords = 24 bytes
        commands.append(bv)

        // --- LC_LOAD_DYLIB / LC_LOAD_WEAK_DYLIB ---
        func dylibCommand(_ name: String, weak: Bool) -> Data {
            let bytes = Array(name.utf8) + [0]
            let bodyLength = 24 + bytes.count
            let size = pad(bodyLength)
            var c = Data()
            c.append(encode(weak ? 0x8000_0018 : 0x0C))
            c.append(encode(UInt32(size)))
            c.append(encode(24))
            c.append(encode(1))
            c.append(encode(0))
            c.append(encode(0))
            c.append(contentsOf: bytes)
            if size > bodyLength { c.append(Data(repeating: 0, count: size - bodyLength)) }
            return c
        }
        for lib in spec.dylibs { commands.append(dylibCommand(lib, weak: false)) }
        for lib in spec.weakDylibs { commands.append(dylibCommand(lib, weak: true)) }

        // --- LC_RPATH ---
        for path in spec.rpaths {
            let bytes = Array(path.utf8) + [0]
            let bodyLength = 12 + bytes.count
            let size = pad(bodyLength)
            var c = Data()
            c.append(encode(0x8000_001C))
            c.append(encode(UInt32(size)))
            c.append(encode(12))
            c.append(contentsOf: bytes)
            if size > bodyLength { c.append(Data(repeating: 0, count: size - bodyLength)) }
            commands.append(c)
        }

        // --- LC_ENCRYPTION_INFO(_64) ---
        if let cryptID = spec.cryptID {
            var e = Data()
            e.append(encode(is64 ? 0x2C : 0x21))
            e.append(encode(24))
            e.append(encode(4096))                     // cryptoff
            e.append(encode(1024))                     // cryptsize
            e.append(encode(cryptID))
            e.append(Data(repeating: 0, count: 4))     // pad to the declared 24 bytes
            commands.append(e)
        }

        // --- corrupt dummy command (invalid size on purpose) ---
        if spec.corruptCommandSize {
            var c = Data()
            c.append(encode(0x27))
            c.append(encode(12))
            c.append(encode(0))
            c.append(encode(0))
            commands.append(c)
        }

        // --- LC_SYMTAB payload ---
        var symtabPlaceholder: Data?
        if !spec.symbols.isEmpty {
            var nlistData = Data()
            var strTable = Data([0x20])
            for sym in spec.symbols {
                let strx = UInt32(strTable.count)
                strTable.append(contentsOf: Array(sym.name.utf8))
                strTable.append(0)
                var nl = Data()
                nl.append(encode(strx))
                var ntype: UInt8 = 0x0E                // N_SECT
                if sym.external { ntype |= 0x01 }      // N_EXT
                if sym.undefined { ntype = 0x00 }      // N_UNDF
                nl.append(ntype)
                nl.append(1)
                nl.append(0); nl.append(0)             // n_desc: 2 bytes
                if fieldsBig { nl.appendBE64(0) } else { nl.appendLE64(0) }
                nlistData.append(nl)
            }
            symtabPlaceholder = nlistData
            extraData.append(nlistData)
            extraData.append(strTable)
        }

        // --- code signature blob ---
        var signatureBlob = Data()
        if let xml = spec.entitlementsXML {
            var blob = Data()
            blob.appendBE32(0xFADE_7171)
            blob.appendBE32(UInt32(8 + xml.utf8.count))
            blob.append(contentsOf: Array(xml.utf8))

            signatureBlob.appendBE32(0xFADE_0CC0)
            signatureBlob.appendBE32(UInt32(12 + 8 + blob.count))
            signatureBlob.appendBE32(1)
            signatureBlob.appendBE32(0xFADE_7171)
            signatureBlob.appendBE32(20)
            signatureBlob.append(blob)
        }

        // --- patch-free offsets now that every command exists ---
        let symtabOffset = payloadOffset + payloadSize
        let symtabSize = symtabPlaceholder?.count ?? 0
        let strTableOffset = symtabOffset + symtabSize
        let strTableSize = symtabPlaceholder != nil ? extraData.count - symtabSize : 0
        let signatureOffset = strTableOffset + strTableSize

        if symtabPlaceholder != nil {
            var st = Data()
            st.append(encode(0x02))
            st.append(encode(24))
            st.append(encode(UInt32(symtabOffset)))
            st.append(encode(UInt32(spec.symbols.count)))
            st.append(encode(UInt32(strTableOffset)))
            st.append(encode(UInt32(strTableSize)))
            commands.append(st)
        }

        if !signatureBlob.isEmpty {
            var cs = Data()
            cs.append(encode(0x1D))
            cs.append(encode(16))                  // linkedit_data_command: 16 bytes
            cs.append(encode(UInt32(signatureOffset)))
            cs.append(encode(UInt32(signatureBlob.count)))
            commands.append(cs)
        }

        // Count actual load commands by walking the assembled command bytes.
        var loadCommandCount = 0
        var walkCursor = 0
        let commandBytes = [UInt8](commands)
        while walkCursor + 8 <= commandBytes.count {
            loadCommandCount += 1
            let b0 = UInt32(commandBytes[walkCursor + 4])
            let b1 = UInt32(commandBytes[walkCursor + 5])
            let b2 = UInt32(commandBytes[walkCursor + 6])
            let b3 = UInt32(commandBytes[walkCursor + 7])
            let declared = fieldsBig
                ? (b0 << 24) | (b1 << 16) | (b2 << 8) | b3
                : b0 | (b1 << 8) | (b2 << 16) | (b3 << 24)
            if declared < 8 { break }
            walkCursor += Int(declared)
        }

        var out = Data()
        if fieldsBig {
            out.appendBE32(naturalMagic)
        } else {
            out.appendLE32(spec.magic)
        }
        out.append(encode(spec.cpuType))
        out.append(encode(spec.cpuSubtype))
        out.append(encode(2))                          // MH_EXECUTE
        out.append(encode(UInt32(loadCommandCount)))
        out.append(encode(UInt32(commandsSize)))
        out.append(encode(0))                          // flags
        if is64 { out.append(encode(0)) }              // reserved
        out.append(commands)
        out.append(sectionPayload)
        out.append(extraData)
        out.append(signatureBlob)
        return out
    }

    /// Builds a FAT container from slices.
    static func fat(slices: [(cpu: UInt32, sub: UInt32, data: Data)], is64: Bool = false) -> Data {
        var out = Data()
        out.appendBE32(is64 ? 0xCAFEBABF : 0xCAFEBABE)
        out.appendBE32(UInt32(slices.count))
        var dataBlob = Data()
        var entries: [(UInt32, UInt32, Int, Int)] = []

        var headerSize = 8 + slices.count * (is64 ? 32 : 20)
        headerSize = pad(headerSize)

        for slice in slices {
            let offset = headerSize + dataBlob.count
            // Align each slice to 16 bytes like the real tools do.
            let padding = (16 - (offset % 16)) % 16
            dataBlob.append(Data(repeating: 0, count: padding))
            let realOffset = headerSize + dataBlob.count
            dataBlob.append(slice.data)
            entries.append((slice.cpu, slice.sub, realOffset, slice.data.count))
        }

        for (cpu, sub, offset, size) in entries {
            out.appendBE32(cpu)
            out.appendBE32(sub)
            if is64 {
                out.appendBE64(UInt64(offset))
                out.appendBE64(UInt64(size))
                out.appendBE32(0)                     // align
                out.appendBE32(0)                     // reserved
            } else {
                out.appendBE32(UInt32(offset))
                out.appendBE32(UInt32(size))
                out.appendBE32(0)                     // align
            }
        }
        // Pad the header block to where the data actually starts.
        while out.count < headerSize { out.append(0) }
        out.append(dataBlob)
        return out
    }

    // MARK: - Plists

    /// Hand-built XML plist for the fixture (portable across platforms).
    static func xmlPlist(_ content: String) -> Data {
        Data("""
        <?xml version="1.0" encoding="UTF-8"?>
        <!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
        <plist version="1.0">
        \(content)
        </plist>
        """.utf8)
    }

    static func sampleInfoPlist() -> Data {
        xmlPlist("""
        <dict>
            <key>CFBundleDisplayName</key><string>Sample App</string>
            <key>CFBundleName</key><string>Sample</string>
            <key>CFBundleIdentifier</key><string>com.example.sample</string>
            <key>CFBundleShortVersionString</key><string>1.2.3</string>
            <key>CFBundleVersion</key><string>42</string>
            <key>CFBundleExecutable</key><string>Sample</string>
            <key>CFBundlePackageType</key><string>APPL</string>
            <key>MinimumOSVersion</key><string>13.0</string>
            <key>DTPlatformName</key><string>iphoneos</string>
            <key>UIDeviceFamily</key><array><integer>1</integer></array>
            <key>UIRequiredDeviceCapabilities</key><array><string>armv7</string></array>
            <key>NSCameraUsageDescription</key><string>To scan documents.</string>
            <key>NSLocationWhenInUseUsageDescription</key><string>To show nearby results.</string>
            <key>NSAppTransportSecurity</key>
            <dict>
                <key>NSAllowsArbitraryLoads</key><false/>
                <key>NSExceptionDomains</key>
                <dict>
                    <key>legacy.example.com</key>
                    <dict>
                        <key>NSExceptionAllowsInsecureHTTPLoads</key><true/>
                        <key>NSExceptionMinimumTLSVersion</key><string>TLSv1.0</string>
                    </dict>
                </dict>
            </dict>
            <key>CFBundleURLTypes</key>
            <array>
                <dict>
                    <key>CFBundleURLName</key><string>com.example.sample</string>
                    <key>CFBundleURLSchemes</key><array><string>sampleapp</string></array>
                </dict>
            </array>
            <key>LSApplicationQueriesSchemes</key><array><string>targetapp</string></array>
            <key>UIBackgroundModes</key><array><string>remote-notification</string></array>
            <key>UIFileSharingEnabled</key><true/>
            <key>CFBundleIcons</key>
            <dict>
                <key>CFBundlePrimaryIcon</key>
                <dict>
                    <key>CFBundleIconFiles</key><array><string>AppIcon60x60</string></array>
                </dict>
            </dict>
        </dict>
        """)
    }

    static func sampleEntitlementsXML() -> String {
        """
        <?xml version="1.0" encoding="UTF-8"?>
        <plist version="1.0">
        <dict>
            <key>application-identifier</key><string>TEAMID1234.com.example.sample</string>
            <key>keychain-access-groups</key>
            <array><string>TEAMID1234.*</string></array>
            <key>get-task-allow</key><false/>
            <key>aps-environment</key><string>development</string>
            <key>com.apple.developer.associated-domains</key>
            <array><string>applinks:example.com</string></array>
        </dict>
        </plist>
        """
    }

    static func sampleProfilePlist(expired: Bool = false) -> Data {
        let year = expired ? 2020 : 2030
        return xmlPlist("""
        <dict>
            <key>Name</key><string>Sample Profile</string>
            <key>TeamName</key><string>Example Ltd</string>
            <key>TeamIdentifier</key><array><string>TEAMID1234</string></array>
            <key>AppIDName</key><string>Sample App</string>
            <key>ApplicationIdentifierPrefix</key><array><string>TEAMID1234</string></array>
            <key>CreationDate</key><date>2024-01-01T00:00:00Z</date>
            <key>ExpirationDate</key><date>\(year)-01-01T00:00:00Z</date>
            <key>ProvisionedDevices</key><array><string>udid-redacted-1</string></array>
            <key>Entitlements</key>
            <dict>
                <key>application-identifier</key><string>TEAMID1234.com.example.sample</string>
                <key>get-task-allow</key><false/>
            </dict>
        </dict>
        """)
    }

    /// Wraps a plist in the CMS/DER framing a real .mobileprovision has.
    static func mobileprovision(plist: Data) -> Data {
        var blob = Data([0x30, 0x82])
        blob.appendLE16(UInt16(plist.count + 8))
        blob.append(contentsOf: [UInt8(0x30), UInt8(0x82)])
        blob.append(Data(repeating: 0x06, count: 8))   // mock CMS header
        blob.append(plist)
        return blob
    }

    // MARK: - The synthetic IPA

    /// A complete, realistic IPA: main app + framework + extension + privacy
    /// manifest + config with a key + Unity data + localization.
    static func sampleIPA(executableEncrypted: Bool = false,
                          extraEntries: [ZipSpec] = []) -> Data {
        let mainBinary = thinMachO(MachOSpec(
            cryptID: executableEncrypted ? 1 : nil,
            dylibs: [
                "/usr/lib/libSystem.B.dylib",
                "@rpath/FirebaseCore.framework/FirebaseCore",
                "@rpath/UnityFramework.framework/UnityFramework",
            ],
            rpaths: ["@executable_path/Frameworks", "@loader_path/Frameworks"],
            uuid: Array(0...15).map { UInt8($0) },
            entitlementsXML: sampleEntitlementsXML(),
            symbols: [
                ("_main", false, false),
                ("_SampleManager.currentMetadata", true, false),
                ("_OBJC_CLASS_$_NSObject", true, true),
                ("_OBJC_CLASS_$_SampleViewController", true, false),
                ("__ZN2IP7Kit4InfoEv", true, false),
            ],
            cstrings: [
                "https://api.example.com/v1/users",
                "https://cdn.example.net/static/app.js",
                "http://legacy.example.com/ping",
                "objc_class_name_SampleViewController",
            ]
        ))

        let frameworkBinary = thinMachO(MachOSpec(
            minOS: 0x000F_0000,                        // 15.0.0
            sdk: 0x0012_0000,
            dylibs: ["@rpath/FirebaseCore.framework/FirebaseCore"],
            symbols: [("_SampleKitInit", true, false)]
        ))

        let extensionBinary = thinMachO(MachOSpec(
            minOS: 0x000D_0000,
            symbols: [("_ShareMain", true, false)]
        ))

        let frameworkInfo = xmlPlist("""
        <dict>
            <key>CFBundleIdentifier</key><string>com.example.sample.SampleKit</string>
            <key>CFBundleShortVersionString</key><string>2.0.1</string>
            <key>CFBundleVersion</key><string>201</string>
            <key>CFBundleExecutable</key><string>SampleKit</string>
            <key>MinimumOSVersion</key><string>15.0</string>
        </dict>
        """)

        let extensionInfo = xmlPlist("""
        <dict>
            <key>CFBundleIdentifier</key><string>com.example.sample.Share</string>
            <key>CFBundleShortVersionString</key><string>1.2.3</string>
            <key>CFBundleVersion</key><string>42</string>
            <key>CFBundleExecutable</key><string>Share</string>
            <key>MinimumOSVersion</key><string>13.0</string>
            <key>NSExtension</key>
            <dict>
                <key>NSExtensionPointIdentifier</key><string>com.apple.share-services</string>
            </dict>
        </dict>
        """)

        let privacyManifest = xmlPlist("""
        <dict>
            <key>NSPrivacyTracking</key><true/>
            <key>NSPrivacyTrackingDomains</key><array><string>tracker.example.net</string></array>
            <key>NSPrivacyCollectedDataTypes</key>
            <array>
                <dict>
                    <key>NSPrivacyCollectedDataType</key><string>NSPrivacyCollectedDataTypeEmailAddress</string>
                    <key>NSPrivacyCollectedDataTypeLinked</key><true/>
                </dict>
            </array>
            <key>NSPrivacyAccessedAPITypes</key>
            <array>
                <dict>
                    <key>NSPrivacyAccessedAPIType</key><string>NSPrivacyAccessedAPICategoryFileTimestamp</string>
                </dict>
            </array>
        </dict>
        """)

        let config = """
        {
          "google_api_key": "AIza1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8S9t0",
          "endpoint": "https://api.example.com/v2",
          "image_cdn": "http://img.example-cdn.org/assets"
        }
        """

        let jsFile = """
        // sample bundle script
        function run(input) { return eval(input); }
        var endpoint = "http://insecure.example.org/report";
        document.write("<b>ok</b>");
        """

        let localizable = /*
        */ "\"greeting\" = \"Hello\";\n\"farewell\" = \"Goodbye\";\n"

        var specs: [ZipSpec] = [
            .init(path: "Payload/Sample.app/", contents: Data()),
            .init(path: "Payload/Sample.app/Info.plist", contents: sampleInfoPlist()),
            .init(path: "Payload/Sample.app/Sample", contents: mainBinary,
                  externalAttributes: executableAttributes()),
            .init(path: "Payload/Sample.app/GoogleService-Info.plist", contents: xmlPlist("""
            <dict>
                <key>BUNDLE_ID</key><string>com.example.sample</string>
                <key>API_KEY</key><string>AAaa11BBbb22CCcc33DDdd44EEee55FFff66GGgg</string>
            </dict>
            """)),
            .init(path: "Payload/Sample.app/Frameworks/", contents: Data()),
            .init(path: "Payload/Sample.app/Frameworks/SampleKit.framework/", contents: Data()),
            .init(path: "Payload/Sample.app/Frameworks/SampleKit.framework/Info.plist", contents: frameworkInfo),
            .init(path: "Payload/Sample.app/Frameworks/SampleKit.framework/SampleKit", contents: frameworkBinary,
                  externalAttributes: executableAttributes()),
            .init(path: "Payload/Sample.app/PlugIns/", contents: Data()),
            .init(path: "Payload/Sample.app/PlugIns/Share.appex/", contents: Data()),
            .init(path: "Payload/Sample.app/PlugIns/Share.appex/Info.plist", contents: extensionInfo),
            .init(path: "Payload/Sample.app/PlugIns/Share.appex/Share", contents: extensionBinary,
                  externalAttributes: executableAttributes()),
            .init(path: "Payload/Sample.app/PrivacyInfo.xcprivacy", contents: privacyManifest),
            .init(path: "Payload/Sample.app/config.json", contents: config),
            .init(path: "Payload/Sample.app/www/app.js", contents: jsFile),
            .init(path: "Payload/Sample.app/en.lproj/Localizable.strings", contents: localizable),
            .init(path: "Payload/Sample.app/de.lproj/Localizable.strings", contents: localizable),
            .init(path: "Payload/Sample.app/Data/", contents: Data()),
            .init(path: "Payload/Sample.app/Data/Managed/", contents: Data()),
            .init(path: "Payload/Sample.app/Data/Managed/Metadata/global-metadata.dat", contents: Data(repeating: 0x51, count: 4096)),
            .init(path: "Payload/Sample.app/Assets.car", contents: Data(repeating: 0x41, count: 2048)),
            .init(path: "Payload/Sample.app/AppIcon60x60@2x.png", contents: Data(repeating: 0x89, count: 512)),
        ]
        specs.append(contentsOf: extraEntries)
        return zip(specs)
    }
}

// MARK: - Data little/big endian helpers

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
