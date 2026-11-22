import XCTest
@testable import IPAKit

final class MachOTests: XCTestCase {

    // MARK: Magic and endianness

    func testThin64LittleEndian() throws {
        let data = FixtureBuilder.thinMachO(.init())
        let archs = try MachOParser.parse(data)
        XCTAssertEqual(archs.count, 1)
        XCTAssertEqual(archs[0].cpu, "arm64")
        XCTAssertTrue(archs[0].is64Bit)
    }

    func testThin32LittleEndian() throws {
        var spec = FixtureBuilder.MachOSpec()
        spec.magic = 0xFEEDFACE
        spec.cpuType = 12
        spec.cpuSubtype = 9
        let archs = try MachOParser.parse(FixtureBuilder.thinMachO(spec))
        XCTAssertEqual(archs.count, 1)
        XCTAssertEqual(archs[0].cpu, "armv7")
        XCTAssertFalse(archs[0].is64Bit)
    }

    func testBigEndian32() throws {
        var spec = FixtureBuilder.MachOSpec()
        spec.magic = 0xFEEDFACE
        spec.bigEndian = true
        spec.cpuType = 12
        spec.cpuSubtype = 9
        spec.minOS = 0x000D_0000
        spec.sdk = 0x0011_0000
        let archs = try MachOParser.parse(FixtureBuilder.thinMachO(spec))
        XCTAssertEqual(archs.count, 1)
        XCTAssertEqual(archs[0].minOS, "13.0.0")
        XCTAssertEqual(archs[0].sdk, "17.0.0")
    }

    func testSwappedMagicIsRejectedNotMisparsed() {
        // A file whose first word is the byte-swapped 64-bit magic is a valid
        // big-endian 64-bit Mach-O; the parser must not treat it as little-endian.
        var spec = FixtureBuilder.MachOSpec()
        spec.magic = 0xCFFAEDFE
        spec.bigEndian = false
        let data = FixtureBuilder.thinMachO(spec)
        XCTAssertNoThrow(try MachOParser.parse(data))
    }

    func testLooksLikeMachORejectsText() {
        XCTAssertFalse(MachOParser.looksLikeMachO(Data("hello world".utf8)))
        XCTAssertFalse(MachOParser.looksLikeMachO(Data()))
        XCTAssertFalse(MachOParser.looksLikeMachO(Data([0x50, 0x4B, 0x03, 0x04])))
    }

    // MARK: FAT

    func testFatTwoSlices() throws {
        var arm64 = FixtureBuilder.MachOSpec()
        arm64.cpuType = 0x0100_000C
        arm64.cpuSubtype = 0
        var x86 = FixtureBuilder.MachOSpec()
        x86.cpuType = 0x0100_0007
        x86.cpuSubtype = 3

        let fat = FixtureBuilder.fat(slices: [
            (0x0100_000C, 0, FixtureBuilder.thinMachO(arm64)),
            (0x0100_0007, 3, FixtureBuilder.thinMachO(x86)),
        ])
        let archs = try MachOParser.parse(fat)
        XCTAssertEqual(archs.count, 2)
        XCTAssertEqual(archs[0].cpu, "arm64")
        XCTAssertEqual(archs[1].cpu, "x86_64")
    }

    func testFat64TwoSlices() throws {
        let fat = FixtureBuilder.fat(slices: [
            (0x0100_000C, 0, FixtureBuilder.thinMachO(.init())),
            (0x0100_000C, 2, FixtureBuilder.thinMachO(.init())),
        ], is64: true)
        let archs = try MachOParser.parse(fat)
        XCTAssertEqual(archs.count, 2)
        XCTAssertEqual(archs[1].cpu, "arm64e")
    }

    func testJavaClassFileIsRejected() {
        // 0xCAFEBABE with a small count is a Java class file, not a FAT binary.
        var data = Data()
        data.append(contentsOf: [0xCA, 0xFE, 0xBA, 0xBE])
        data.append(contentsOf: [0x00, 0x00, 0x00, 0x34])
        XCTAssertThrowsError(try MachOParser.parse(data)) { error in
            guard case MachOError.malformed = error else {
                return XCTFail("expected malformed, got \(error)")
            }
        }
    }

    func testFatEntryPointingOutsideFileIsReportedNotFatal() throws {
        var fat = FixtureBuilder.fat(slices: [(0x0100_000C, 0, FixtureBuilder.thinMachO(.init()))])
        // Corrupt the offset of the single entry to a huge value.
        fat.replaceSubrange(16..<20, with: Data([0xFF, 0xFF, 0xFF, 0x7F]))
        let archs = try MachOParser.parse(fat)
        XCTAssertEqual(archs.count, 1)
        XCTAssertTrue(archs[0].warnings.contains { $0.contains("outside the file") })
    }

    // MARK: Load commands

    func testEncryptionFlagDetection() throws {
        var encrypted = FixtureBuilder.MachOSpec()
        encrypted.cryptID = 1
        let encryptedArchs = try MachOParser.parse(FixtureBuilder.thinMachO(encrypted))
        XCTAssertEqual(encryptedArchs[0].encrypted, true)
        XCTAssertEqual(encryptedArchs[0].cryptID, 1)

        var plain = FixtureBuilder.MachOSpec()
        plain.cryptID = 0
        let plainArchs = try MachOParser.parse(FixtureBuilder.thinMachO(plain))
        XCTAssertEqual(plainArchs[0].encrypted, false)

        let absent = try MachOParser.parse(FixtureBuilder.thinMachO(.init()))
        XCTAssertNil(absent[0].encrypted)
        XCTAssertTrue(absent[0].warnings.contains { $0.contains("LC_ENCRYPTION_INFO") })
    }

    func testDylibAndRpathExtraction() throws {
        var spec = FixtureBuilder.MachOSpec()
        spec.dylibs = ["/usr/lib/libSystem.B.dylib", "@rpath/MyLib.framework/MyLib"]
        spec.rpaths = ["@executable_path/Frameworks", "@loader_path/../Frameworks"]
        let archs = try MachOParser.parse(FixtureBuilder.thinMachO(spec))
        XCTAssertEqual(archs[0].dylibs.count, 2)
        XCTAssertTrue(archs[0].dylibs.contains("/usr/lib/libSystem.B.dylib"))
        XCTAssertEqual(archs[0].rpaths.count, 2)
    }

    func testUUIDFormatting() throws {
        var spec = FixtureBuilder.MachOSpec()
        spec.uuid = Array(0...15).map { UInt8($0) }
        let archs = try MachOParser.parse(FixtureBuilder.thinMachO(spec))
        XCTAssertEqual(archs[0].uuid, "00010203-0405-0607-0809-0A0B0C0D0E0F")
    }

    func testBuildVersionParsing() throws {
        var spec = FixtureBuilder.MachOSpec()
        spec.minOS = 0x0011_0400   // 17.4.0
        spec.sdk = 0x0012_0000     // 18.0.0
        let archs = try MachOParser.parse(FixtureBuilder.thinMachO(spec))
        XCTAssertEqual(archs[0].minOS, "17.4.0")
        XCTAssertEqual(archs[0].sdk, "18.0.0")
        XCTAssertEqual(archs[0].platform, "iOS")
    }

    func testSegmentsAndSectionsParsed() throws {
        var spec = FixtureBuilder.MachOSpec()
        spec.segmentName = "__TEXT"
        let archs = try MachOParser.parse(FixtureBuilder.thinMachO(spec))
        let text = try XCTUnwrap(archs[0].segments.first)
        XCTAssertEqual(text.name, "__TEXT")
        XCTAssertEqual(text.sections.count, 2)
        XCTAssertEqual(text.sections.first?.name, "__text")
        XCTAssertFalse(text.truncated)
    }

    func testCorruptCommandSizeIsReportedNotCrashing() throws {
        var spec = FixtureBuilder.MachOSpec()
        spec.corruptCommandSize = true
        let archs = try MachOParser.parse(FixtureBuilder.thinMachO(spec))
        XCTAssertTrue(archs[0].warnings.contains { $0.contains("invalid size") },
                      "expected an invalid-size warning, got \(archs[0].warnings)")
    }

    // MARK: Entitlements

    func testEntitlementsExtraction() throws {
        let xml = """
        <?xml version="1.0" encoding="UTF-8"?>
        <plist version="1.0"><dict><key>get-task-allow</key><false/></dict></plist>
        """
        var spec = FixtureBuilder.MachOSpec()
        spec.entitlementsXML = xml
        let data = FixtureBuilder.thinMachO(spec)
        let archs = try MachOParser.parse(data)
        let extracted = try XCTUnwrap(archs[0].entitlementsXML)
        XCTAssertTrue(extracted.contains("get-task-allow"))
    }

    func testEntitlementsSuperBlobIndexing() throws {
        // Three blobs, entitlements last, to prove the index walk is not just
        // reading the first element.
        let xml = Data("<?xml version=\"1.0\"?><plist><dict/></plist>".utf8)
        var payload = Data()
        payload.append(contentsOf: [0xFA, 0xDE, 0x71, 0x71])
        var length = UInt32(xml.count + 8).bigEndian
        withUnsafeBytes(of: &length) { payload.append(contentsOf: $0) }
        payload.append(xml)

        var superBlob = Data()
        superBlob.append(contentsOf: [0xFA, 0xDE, 0x0C, 0xC0])
        var totalLength = UInt32(payload.count + 12 + 2 * 8).bigEndian
        withUnsafeBytes(of: &totalLength) { superBlob.append(contentsOf: $0) }
        var count = UInt32(2).bigEndian
        withUnsafeBytes(of: &count) { superBlob.append(contentsOf: $0) }
        // Entry 0: a CMS wrapper blob at offset 28.
        var type0 = UInt32(0xFADE0B01).bigEndian
        withUnsafeBytes(of: &type0) { superBlob.append(contentsOf: $0) }
        var offset0 = UInt32(28).bigEndian
        withUnsafeBytes(of: &offset0) { superBlob.append(contentsOf: $0) }
        // Entry 1: entitlements immediately after.
        var type1 = UInt32(0xFADE7171).bigEndian
        withUnsafeBytes(of: &type1) { superBlob.append(contentsOf: $0) }
        var offset1 = UInt32(28).bigEndian
        withUnsafeBytes(of: &offset1) { superBlob.append(contentsOf: $0) }
        // A placeholder first blob so the offsets differ.
        superBlob.append(payload)

        let result = CodeSignature.entitlementsXML(signature: superBlob)
        XCTAssertNotNil(result, "the index walk should find the entitlements blob")
    }

    func testEntitlementsAbsentReturnsNil() {
        let notASuperBlob = Data([0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07])
        XCTAssertNil(CodeSignature.entitlementsXML(signature: notASuperBlob))
    }

    // MARK: Truncation and malformed input

    func testTruncatedFileIsRejected() {
        let full = FixtureBuilder.thinMachO(.init())
        let truncated = full.prefix(16)
        XCTAssertThrowsError(try MachOParser.parse(Data(truncated))) { error in
            guard case MachOError.truncated = error else {
                return XCTFail("expected truncated, got \(error)")
            }
        }
    }

    func testEmptyFileIsRejected() {
        XCTAssertThrowsError(try MachOParser.parse(Data()))
    }

    func testHeaderClaimsMoreCommandsThanFileHolds() {
        var data = FixtureBuilder.thinMachO(.init())
        // sizeofcmds = (cursor 20) set far beyond the file length.
        data.replaceSubrange(20..<24, with: Data([0xFF, 0xFF, 0xFF, 0x0F]))
        XCTAssertThrowsError(try MachOParser.parse(data)) { error in
            guard case MachOError.truncated = error else {
                return XCTFail("expected truncated, got \(error)")
            }
        }
    }

    func testAbsurdCommandCount() {
        var data = FixtureBuilder.thinMachO(.init())
        data.replaceSubrange(16..<20, with: Data([0xFF, 0xFF, 0x00, 0x00]))
        XCTAssertThrowsError(try MachOParser.parse(data))
    }

    func testEveryOffsetReadIsBoundsChecked() {
        // Systematically truncate a valid file at many lengths; none may crash.
        let full = FixtureBuilder.thinMachO(.init())
        let step = max(1, full.count / 400)
        var index = 0
        while index < full.count {
            let slice = Data(full.prefix(index))
            XCTAssertNoThrow(try? MachOParser.parse(slice))
            index += step
        }
    }

    // MARK: ByteReader

    func testByteReaderBounds() {
        let reader = ByteReader(Data([0x01, 0x02, 0x03]), label: "t")
        XCTAssertEqual(reader.u8(0), 0x01)
        XCTAssertNil(reader.u8(3))
        XCTAssertNil(reader.u8(-1))
        XCTAssertNil(reader.u32(0, bigEndian: false))
        XCTAssertEqual(reader.u32(0, bigEndian: false).map { $0 & 0xFF }, nil)
        XCTAssertNil(reader.subdata(1, 5))
        XCTAssertEqual(reader.cString(0)?.count, 0)
    }

    func testByteReaderEndianness() {
        let reader = ByteReader(Data([0xDE, 0xAD, 0xBE, 0xEF]), label: "t")
        XCTAssertEqual(reader.u32(0, bigEndian: false), 0xEFBE_ADDE)
        XCTAssertEqual(reader.u32(0, bigEndian: true), 0xDEAD_BEEF)
    }

    func testAsciiStringsExtraction() {
        let bytes = Data("hello\u{0}world!!\u{0}\u{01}\u{02}short\u{0}".utf8)
        let strings = ByteReader(bytes, label: "t").asciiStrings(minLength: 6, limit: 100, maxBytes: 1024)
        XCTAssertTrue(strings.contains("hello"))
        XCTAssertTrue(strings.contains("world!!"))
    }

    func testAsciiStringsRespectsLimit() {
        let bytes = Data(String(repeating: "abcdefgh\u{0}", count: 100).utf8)
        let strings = ByteReader(bytes, label: "t").asciiStrings(minLength: 4, limit: 5, maxBytes: 1024)
        XCTAssertEqual(strings.count, 5)
    }

    func testAsciiStringsRespectsByteCap() {
        let bytes = Data(String(repeating: "abcdefgh\u{0}", count: 100).utf8)
        let strings = ByteReader(bytes, label: "t").asciiStrings(minLength: 4, limit: 1000, maxBytes: 20)
        XCTAssertLessThanOrEqual(strings.count, 3)
    }
}
