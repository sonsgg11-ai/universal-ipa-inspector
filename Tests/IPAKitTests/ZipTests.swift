import XCTest
@testable import IPAKit

final class ZipTests: XCTestCase {

    private func write(_ data: Data, name: String = "fixture.zip") throws -> URL {
        let url = FileManager.default.temporaryDirectory
            .appendingPathComponent("\(UUID().uuidString)-\(name)")
        try data.write(to: url)
        return url
    }

    // MARK: Directory reading

    func testReadsSimpleArchive() throws {
        let data = FixtureBuilder.zip([
            .init(path: "a.txt", contents: Data("aaa".utf8)),
            .init(path: "dir/b.txt", contents: Data("bbbb".utf8)),
        ])
        let url = try write(data)
        defer { try? FileManager.default.removeItem(at: url) }

        let entries = try ZipArchive.readDirectory(at: url)
        XCTAssertEqual(entries.count, 2)
        XCTAssertEqual(entries.map(\.path), ["a.txt", "dir/b.txt"])
        XCTAssertEqual(entries[0].uncompressedSize, 3)
        XCTAssertEqual(entries[1].compressedSize, 4)
    }

    func testRejectsNonZip() throws {
        let url = try write(Data("this is not a zip file at all, not even close".utf8))
        defer { try? FileManager.default.removeItem(at: url) }
        XCTAssertThrowsError(try ZipArchive.readDirectory(at: url))
    }

    func testRejectsEmptyFile() throws {
        let url = try write(Data())
        defer { try? FileManager.default.removeItem(at: url) }
        XCTAssertThrowsError(try ZipArchive.readDirectory(at: url))
    }

    func testEncryptedFlagIsReadForSymlinks() throws {
        let data = FixtureBuilder.zip([
            .init(path: "good.txt", contents: Data("ok".utf8),
                  externalAttributes: FixtureBuilder.regularAttributes()),
            .init(path: "link", contents: Data("/etc/passwd".utf8),
                  externalAttributes: FixtureBuilder.symlinkAttributes()),
        ])
        let url = try write(data)
        defer { try? FileManager.default.removeItem(at: url) }
        let entries = try ZipArchive.readDirectory(at: url)
        XCTAssertTrue(entries[0].isSymlink == false)
        XCTAssertTrue(entries[1].isSymlink, "symlink entries must be identifiable from the Unix mode")
    }

    // MARK: Extraction policy — the security boundary

    func testRejectsPathTraversal() {
        var plan = ZipArchive.buildPlan([
            .init(path: "../../etc/passwd", contents: Data(), compressionMethod: 0, localHeaderOffset: 0),
            .init(path: "Payload/App.app/ok.txt", contents: Data(), compressionMethod: 0, localHeaderOffset: 0),
        ])
        XCTAssertEqual(plan.accepted.map(\.path), ["Payload/App.app/ok.txt"])
        XCTAssertEqual(plan.rejected.count, 1)
        XCTAssertTrue(plan.rejected[0].reason.contains("relative"))
        plan = ZipArchive.buildPlan([])
        XCTAssertTrue(plan.accepted.isEmpty)
    }

    func testRejectsAbsolutePath() {
        let plan = ZipArchive.buildPlan([
            .init(path: "/etc/hosts", contents: Data(), compressionMethod: 0, localHeaderOffset: 0),
        ])
        XCTAssertTrue(plan.accepted.isEmpty)
        XCTAssertTrue(plan.rejected[0].reason.contains("absolute"))
    }

    func testRejectsWindowsAbsolutePath() {
        let plan = ZipArchive.buildPlan([
            .init(path: "C:\\Windows\\System32\\evil.dll", contents: Data(), compressionMethod: 0, localHeaderOffset: 0),
        ])
        XCTAssertTrue(plan.accepted.isEmpty)
    }

    func testRejectsNestedTraversal() {
        let plan = ZipArchive.buildPlan([
            .init(path: "Payload/App.app/../../../outside.txt", contents: Data(), compressionMethod: 0, localHeaderOffset: 0),
        ])
        XCTAssertTrue(plan.accepted.isEmpty)
        XCTAssertTrue(plan.rejected.count == 1)
    }

    func testRejectsDotDotEncoded() {
        let plan = ZipArchive.buildPlan([
            .init(path: "a/./b.txt", contents: Data(), compressionMethod: 0, localHeaderOffset: 0),
        ])
        XCTAssertTrue(plan.accepted.isEmpty)
    }

    func testRejectsSymlinks() {
        let plan = ZipArchive.buildPlan([
            .init(path: "link", contents: Data(), compressionMethod: 0,
                  localHeaderOffset: 0, isSymlink: true, isDirectory: false),
        ])
        XCTAssertTrue(plan.accepted.isEmpty)
        XCTAssertTrue(plan.rejected[0].reason.contains("symlink"))
    }

    func testDuplicateEntriesFirstWins() {
        let plan = ZipArchive.buildPlan([
            .init(path: "same.txt", contents: Data("one".utf8), compressionMethod: 0, localHeaderOffset: 0),
            .init(path: "same.txt", contents: Data("two".utf8), compressionMethod: 0, localHeaderOffset: 100),
        ])
        XCTAssertEqual(plan.accepted.count, 1)
        XCTAssertEqual(plan.rejected.count, 1)
        XCTAssertTrue(plan.rejected[0].reason.contains("duplicate"))
    }

    func testZipBombRatioIsRejected() {
        // 1 KiB compressed claiming 1 GiB uncompressed.
        let plan = ZipArchive.buildPlan([
            .init(path: "bomb", contents: Data(), compressionMethod: 8,
                  localHeaderOffset: 0, isSymlink: false, isDirectory: false,
                  compressedSize: 1024, uncompressedSize: Int64(1024 * 1024 * 1024),
                  unixMode: nil),
        ])
        XCTAssertTrue(plan.accepted.isEmpty)
        XCTAssertTrue(plan.rejected[0].reason.contains("zip bomb"))
    }

    func testPerEntryLimit() {
        let plan = ZipArchive.buildPlan(
            [.init(path: "big", contents: Data(), compressionMethod: 0, localHeaderOffset: 0,
                   isSymlink: false, isDirectory: false, compressedSize: 10,
                   uncompressedSize: 5000, unixMode: nil)],
            maxEntryBytes: 1024)
        XCTAssertTrue(plan.accepted.isEmpty)
        XCTAssertTrue(plan.rejected[0].reason.contains("per-entry"))
    }

    func testTotalLimit() {
        var entries: [ZipArchive.Entry] = []
        for i in 0..<10 {
            entries.append(.init(path: "f\(i)", contents: Data(), compressionMethod: 0,
                                 localHeaderOffset: 0, isSymlink: false, isDirectory: false,
                                 compressedSize: 1000, uncompressedSize: 1000, unixMode: nil))
        }
        let plan = ZipArchive.buildPlan(entries, maxEntryBytes: 10_000, maxTotalBytes: 3500)
        XCTAssertEqual(plan.accepted.count, 3)
        XCTAssertEqual(plan.totalUncompressed, 3000)
    }

    func testDirectoryEntriesAreSkippedNotRejected() {
        let plan = ZipArchive.buildPlan([
            .init(path: "Payload/", contents: Data(), compressionMethod: 0, localHeaderOffset: 0,
                  isSymlink: false, isDirectory: true, unixMode: nil),
            .init(path: "Payload/App.app/", contents: Data(), compressionMethod: 0, localHeaderOffset: 0,
                  isSymlink: false, isDirectory: true, unixMode: nil),
            .init(path: "Payload/App.app/x", contents: Data("x".utf8), compressionMethod: 0,
                  localHeaderOffset: 0, isSymlink: false, isDirectory: false, unixMode: nil),
        ])
        XCTAssertEqual(plan.accepted.count, 1)
        XCTAssertTrue(plan.rejected.isEmpty)
    }

    func testNulByteInPathIsRejected() {
        let plan = ZipArchive.buildPlan([
            .init(path: "Payload/App.app/e\u{0}vil", contents: Data(), compressionMethod: 0,
                  localHeaderOffset: 0, isSymlink: false, isDirectory: false, unixMode: nil),
        ])
        XCTAssertTrue(plan.accepted.isEmpty)
    }

    // MARK: Raw entry reads

    func testRawDataReadsEntryBytes() throws {
        let payload = Data("the quick brown fox".utf8)
        let data = FixtureBuilder.zip([.init(path: "f.txt", contents: payload)])
        let url = try write(data)
        defer { try? FileManager.default.removeItem(at: url) }

        let entry = try ZipArchive.readDirectory(at: url)[0]
        let raw = try ZipArchive.rawData(at: url, entry: entry)
        XCTAssertEqual(raw, payload)
    }

    func testCRC32MatchesReference() {
        // Reference values for the standard CRC-32 polynomial.
        XCTAssertEqual(FixtureBuilder.crc32(Data("123456789".utf8)), 0xCBF4_3926)
        XCTAssertEqual(FixtureBuilder.crc32(Data()), 0)
    }
}
