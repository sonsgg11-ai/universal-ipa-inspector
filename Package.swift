// swift-tools-version:5.9
import PackageDescription

let package = Package(
    name: "IPAInspector",
    platforms: [
        .iOS(.v17),
        .macOS(.v13),
    ],
    products: [
        .library(name: "IPAKit", targets: ["IPAKit"]),
    ],
    dependencies: [
        .package(url: "https://github.com/weichsel/ZIPFoundation", from: "0.9.19"),
        .package(url: "https://github.com/apple/swift-crypto", from: "3.3.0"),
    ],
    targets: [
        .target(
            name: "IPAKit",
            dependencies: [
                .product(name: "ZIPFoundation", package: "ZIPFoundation"),
                .product(name: "Crypto", package: "swift-crypto"),
            ],
            path: "Sources/IPAKit"
        ),
        .testTarget(
            name: "IPAKitTests",
            dependencies: [
                "IPAKit",
                .product(name: "ZIPFoundation", package: "ZIPFoundation"),
            ],
            path: "Tests/IPAKitTests"
        ),
    ]
)
