import Foundation
import RootstockCore

/// Developer toolchain dual-use surface (path heuristics only).
///
/// Research basis: PEASS / red-team "dev tools as LOOBins" inventories; Xcode / CLT presence
/// as dual-use compile-and-sign surface.
/// Safety and behavior: typed `DeveloperToolchainState`; presence of clang/swift/codesign only,
/// never runs compilers, never codesigns payloads, never harvests certs/keychains.
public struct DeveloperToolchainCollector: Collector {
    public static let id = "collect.developer_toolchain"
    public static let cost: CollectorCost = .low

    private static let xcodePaths: [String] = [
        "/Applications/Xcode.app",
        "/Applications/Xcode-beta.app",
    ]

    private static let cltPaths: [String] = [
        "/Library/Developer/CommandLineTools",
        "/Library/Developer/CommandLineTools/usr/bin/clang",
    ]

    /// Dual-use toolchain binaries (presence = inventory; not execution).
    private static let dualUseBinaryProbes: [(name: String, path: String)] = [
        ("clang", "/usr/bin/clang"),
        ("clang++", "/usr/bin/clang++"),
        ("swift", "/usr/bin/swift"),
        ("swiftc", "/usr/bin/swiftc"),
        ("codesign", "/usr/bin/codesign"),
        ("ld", "/usr/bin/ld"),
        ("dsymutil", "/usr/bin/dsymutil"),
        ("otool", "/usr/bin/otool"),
        ("nm", "/usr/bin/nm"),
        ("lipo", "/usr/bin/lipo"),
        ("install_name_tool", "/usr/bin/install_name_tool"),
        ("xcrun", "/usr/bin/xcrun"),
        ("xcodebuild", "/usr/bin/xcodebuild"),
        ("xcode-select", "/usr/bin/xcode-select"),
        ("llvm-codesign", "/usr/bin/llvm-codesign"),
        ("llvm-objcopy", "/usr/bin/llvm-objcopy"),
        ("nasm", "/usr/local/bin/nasm"),
        ("gcc", "/usr/bin/gcc"),
        ("make", "/usr/bin/make"),
        ("git", "/usr/bin/git"),
        ("python3", "/usr/bin/python3"),
    ]

    private static let extraToolchainPaths: [String] = [
        "/Applications/Xcode.app/Contents/Developer",
        "/Applications/Xcode.app/Contents/Developer/Toolchains",
        "/Library/Developer/CommandLineTools/SDKs",
        "/opt/homebrew/bin/clang",
        "/usr/local/bin/clang",
        "/opt/homebrew/opt/llvm/bin/clang",
    ]

    public init() {}

    public func collect(context: EvaluationContext) async throws -> CollectedState {
        let fm = FileManager.default
        var notes: [String] = [
            "Developer toolchain dual-use inventory - path presence only; no compile/sign/run",
        ]

        var xcodePresent: Bool?
        for path in Self.xcodePaths {
            if fm.fileExists(atPath: path) {
                xcodePresent = true
                notes.append("Xcode present: \(path)")
            }
        }
        if xcodePresent == nil {
            xcodePresent = false
            notes.append("Xcode.app not observed under /Applications")
        }

        var commandLineToolsPresent: Bool?
        for path in Self.cltPaths {
            if fm.fileExists(atPath: path) {
                commandLineToolsPresent = true
                notes.append("CommandLineTools path: \(path)")
            }
        }
        if commandLineToolsPresent == nil {
            commandLineToolsPresent = false
            notes.append("CommandLineTools not observed at catalog paths")
        }

        var toolchainPaths: [String] = []
        for path in Self.xcodePaths + Self.cltPaths + Self.extraToolchainPaths {
            if fm.fileExists(atPath: path) {
                toolchainPaths.append(path)
            }
        }

        var dualUseBinaries: [String] = []
        for probe in Self.dualUseBinaryProbes {
            if fm.fileExists(atPath: probe.path) {
                dualUseBinaries.append(probe.path)
                notes.append("dual_use: \(probe.name) path=\(probe.path)")
            }
        }

        // Home-dir toolchains (optional shallow probes).
        let home = NSHomeDirectory()
        let userToolchainHints = [
            "\(home)/.swiftpm",
            "\(home)/Library/Developer/Xcode",
            "\(home)/Library/Developer/Toolchains",
        ]
        for path in userToolchainHints {
            if fm.fileExists(atPath: path) {
                toolchainPaths.append(path)
                notes.append("user_toolchain: \(path)")
            }
        }

        toolchainPaths = Array(Set(toolchainPaths)).sorted()
        dualUseBinaries = Array(Set(dualUseBinaries)).sorted()

        var state = CollectedState()
        state.developerToolchain = DeveloperToolchainState(
            xcodePresent: xcodePresent,
            commandLineToolsPresent: commandLineToolsPresent,
            toolchainPaths: toolchainPaths,
            dualUseBinaries: dualUseBinaries,
            notes: notes
        )
        state.collectorNotes[Self.id] =
            "xcode=\(xcodePresent.map(String.init(describing:)) ?? "nil") "
            + "clt=\(commandLineToolsPresent.map(String.init(describing:)) ?? "nil") "
            + "toolchainPaths=\(toolchainPaths.count) "
            + "dualUse=\(dualUseBinaries.count)"
        return state
    }
}
