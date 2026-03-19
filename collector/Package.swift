// swift-tools-version: 5.9
import PackageDescription

let package = Package(
    name: "rootstock-collector",
    platforms: [.macOS(.v14)],
    dependencies: [
        .package(
            url: "https://github.com/apple/swift-argument-parser",
            from: "1.3.0"
        ),
    ],
    targets: [
        .executableTarget(
            name: "RootstockCLI",
            dependencies: [
                .product(name: "ArgumentParser", package: "swift-argument-parser"),
                "Models",
                "TCC",
                "Entitlements",
                "CodeSigning",
                "Export",
                "XPCServices",
                "Persistence",
                "Keychain",
                "MDM",
            ]
        ),
        .target(
            name: "Models",
            dependencies: []
        ),
        .target(
            name: "TCC",
            dependencies: ["Models"],
            linkerSettings: [.linkedLibrary("sqlite3")]
        ),
        .target(
            name: "Entitlements",
            dependencies: ["Models"],
            linkerSettings: [.linkedFramework("Security")]
        ),
        .target(
            name: "CodeSigning",
            dependencies: ["Models"],
            linkerSettings: [.linkedFramework("Security")]
        ),
        .target(
            name: "Export",
            dependencies: ["Models"]
        ),
        .target(
            name: "XPCServices",
            dependencies: ["Models"]
        ),
        .target(
            name: "Persistence",
            dependencies: ["Models", "XPCServices"]
        ),
        .target(
            name: "Keychain",
            dependencies: ["Models"],
            linkerSettings: [.linkedFramework("Security")]
        ),
        .target(
            name: "MDM",
            dependencies: ["Models"]
        ),
        .testTarget(
            name: "TCCTests",
            dependencies: ["TCC", "Models"],
            linkerSettings: [.linkedLibrary("sqlite3")]
        ),
        .testTarget(
            name: "EntitlementTests",
            dependencies: ["Entitlements", "Models"],
            linkerSettings: [.linkedFramework("Security")]
        ),
        .testTarget(
            name: "CodeSigningTests",
            dependencies: ["CodeSigning", "Models"],
            linkerSettings: [.linkedFramework("Security")]
        ),
        .testTarget(
            name: "XPCTests",
            dependencies: ["XPCServices", "Models"],
            linkerSettings: [.linkedFramework("Security")]
        ),
        .testTarget(
            name: "PersistenceTests",
            dependencies: ["Persistence", "Models"]
        ),
        .testTarget(
            name: "KeychainTests",
            dependencies: ["Keychain", "Models"],
            linkerSettings: [.linkedFramework("Security")]
        ),
        .testTarget(
            name: "MDMTests",
            dependencies: ["MDM", "Models"]
        ),
        .testTarget(
            name: "ExportTests",
            dependencies: ["Export", "Models"]
        ),
    ]
)
