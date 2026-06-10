// swift-tools-version: 5.9
import PackageDescription

let package = Package(
    name: "Kiskis",
    platforms: [
        .iOS(.v14),
        .macOS(.v11),     // DCAppAttestService, HKDF, file-protection APIs require 11.0
    ],
    products: [
        .library(
            name: "Kiskis",
            targets: ["Kiskis"]
        ),
    ],
    targets: [
        .target(
            name: "Kiskis",
            path: "Sources/Kiskis",
            resources: [
                .copy("PrivacyInfo.xcprivacy"),
            ]
        ),
        .testTarget(
            name: "KiskisTests",
            dependencies: ["Kiskis"],
            path: "Tests/KiskisTests"
        ),
    ]
)
