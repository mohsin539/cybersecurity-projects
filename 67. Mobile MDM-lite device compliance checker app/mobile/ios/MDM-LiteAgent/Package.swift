// swift-tools-version:5.9
import PackageDescription

let package = Package(
    name: "MDM-LiteAgent",
    platforms: [.iOS(.v15), .macOS(.v12)],
    products: [
        .library(name: "MDM-LiteAgent", targets: ["MDM-LiteAgent"])
    ],
    targets: [
        .target(
            name: "MDM-LiteAgent",
            path: "Sources/MDM-LiteAgent"
        ),
        .testTarget(
            name: "MDM-LiteAgentTests",
            path: "Tests/MDM-LiteAgentTests"
        )
    ]
)