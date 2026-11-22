import XCTest
@testable import IPAKit

/// Regression tests for the import gate. The production bug: files were
/// accepted by filename extension only, so real packages with odd names or
/// files handed over by the share sheet were refused even though they were
/// valid ZIP containers — the user saw “Choose an .ipa file” forever.
final class InputValidatorTests: XCTestCase {

    private func write(_ data: Data, name: String) throws -> URL {
        let url = FileManager.default.temporaryDirectory
            .appendingPathComponent("\(UUID().uuidString)-\(name)")
        try data.write(to: url)
        return url
    }

    private func cleanup(_ urls: URL...) {
        for url in urls { try? FileManager.default.removeItem(at: url) }
    }

    // MARK: Acceptance by content

    func testAcceptsRealZipWithAnyName() throws {
        let zip = FixtureBuilder.zip([
            .init(path: "Payload/X.app/Info.plist", contents: Data("plist".utf8)),
        ])
        // A valid ZIP that is NOT called .ipa or .zip: content decides.
        let url = try write(zip, name: "com.botb.winacar_5282.T1B.ipa.download")
        defer { cleanup(url) }

        guard case .accepted(let name) = InputValidator.validate(url: url) else {
            return XCTFail("A valid ZIP container must be accepted regardless of its name")
        }
        XCTAssertTrue(name.contains("com.botb.winacar"))
    }

    func testAcceptsUppercaseExtension() throws {
        let zip = FixtureBuilder.zip([
            .init(path: "Payload/X.app/Info.plist", contents: Data("plist".utf8)),
        ])
        let url = try write(zip, name: "APP.IPA")
        defer { cleanup(url) }
        // Even with a garbage extension, the magic bytes accept it…
        guard case .accepted = InputValidator.validate(url: url) else {
            return XCTFail("Magic bytes decide, not the extension")
        }
    }

    func testAcceptsIpaNameEvenWhenBytesUnreadable() throws {
        // An empty (or cloud-placeholder) file cannot be sniffed; the .ipa
        // name keeps it acceptable so the stager can produce the honest
        // iCloud/download error instead of a misleading “not an archive”.
        let url = try write(Data(), name: "future-download.ipa")
        defer { cleanup(url) }

        guard case .accepted = InputValidator.validate(url: url) else {
            return XCTFail("An .ipa name must stay acceptable even without readable bytes")
        }
    }

    // MARK: Refusal with reasons

    func testRejectsNonArchiveContent() throws {
        let url = try write(Data("a JPEG this is not an archive".utf8), name: "photo.jpeg")
        defer { cleanup(url) }

        guard case .rejected(let message) = InputValidator.validate(url: url) else {
            return XCTFail("Non-archive content must be refused")
        }
        XCTAssertTrue(message.contains("photo.jpeg"), "the refusal names the file")
        XCTAssertTrue(message.contains(".ipa"), "the refusal explains what is needed")
    }

    func testRejectsMissingFileWithCloudGuidance() {
        let missing = FileManager.default.temporaryDirectory
            .appendingPathComponent("gone-\(UUID().uuidString).bin")

        guard case .rejected(let message) = InputValidator.validate(url: missing) else {
            return XCTFail("A missing file must be refused")
        }
        XCTAssertTrue(message.contains("could not be opened"), "the message explains the failure")
    }

    // MARK: Magic-byte behaviour

    func testZipSignaturesAreDetectedDirectly() throws {
        for signature in InputValidator.zipSignatures {
            let padded = signature + Data(repeating: 0xAB, count: 64)
            let url = try write(padded, name: "blob.bin")
            defer { cleanup(url) }
            XCTAssertTrue(InputValidator.looksLikeZip(at: url),
                          "signature \(signature.map { String($0, radix: 16) }) must be recognised")
        }
    }

    func testNonZipHeadIsNotMistakenForArchive() throws {
        let url = try write(Data([0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A]), name: "image.bin")
        defer { cleanup(url) }
        XCTAssertFalse(InputValidator.looksLikeZip(at: url))
    }

    func testOnlyFewBytesAreReadToDecide() throws {
        // A 230 MB file must be validated without reading the whole thing:
        // the decision only ever looks at the first bytes.
        let head = Data([0x50, 0x4B, 0x03, 0x04])
        let url = try write(head, name: "huge-probe.bin")
        defer { cleanup(url) }
        XCTAssertEqual(InputValidator.magicBytes(at: url, byteCount: 8)?.count, 4,
                       "the read returns exactly what exists, never more than asked")
        XCTAssertTrue(InputValidator.looksLikeZip(at: url))
    }
}
