// swift-tools-version:5.9
import PackageDescription

let package = Package(
    name: "IPAKit",
    products: [
        .library(name: "IPAKit", targets: ["IPAKit"])
    ],
    dependencies: [
        // SHA-256 on Linux. On Apple platforms CryptoKit is used directly and
        // this package is only a build-time guest (its Crypto product re-exports
        // CryptoKit there), so the iOS app gains no extra dependency from it.
        .package(url: "https://github.com/apple/swift-crypto.git", "2.0.0"..<"4.0.0")
    ],
    targets: [
        .target(
            name: "IPAKit",
            dependencies: [
                .product(name: "Crypto", package: "swift-crypto")
            ],
            path: "Sources/IPAKit"
        ),
        .testTarget(
            name: "IPAKitTests",
            dependencies: ["IPAKit"],
            path: "Tests/IPAKitTests"
        )
    ]
)
