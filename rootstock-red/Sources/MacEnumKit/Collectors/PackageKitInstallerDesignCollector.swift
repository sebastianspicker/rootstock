import Foundation
import RootstockCore

/// PackageKit installer design-based persistence posture (Wave-9).
///
/// Research basis: PackageKit design-based research (installd / package_script_service /
/// InstallerSandboxes class); pkg receipt inventory ideas from MacPEAS-class tools.
/// Safety and behavior: typed `PackageKitInstallerDesignState`; never builds pkgs or invokes installd.
public struct PackageKitInstallerDesignCollector: Collector {
    public static let id = "collect.packagekit_installer_design"
    public static let cost: CollectorCost = .low

    private static let servicePaths: [String] = [
        "/System/Library/PrivateFrameworks/PackageKit.framework/Versions/A/XPCServices/package_script_service.xpc",
        "/System/Library/PrivateFrameworks/PackageKit.framework/Versions/A/XPCServices/package_script_service.xpc/Contents/MacOS/package_script_service",
        "/usr/libexec/installd",
        "/System/Library/PrivateFrameworks/PackageKit.framework/Resources/installd",
        "/usr/libexec/system_installd",
        "/System/Library/LaunchDaemons/com.apple.installd.plist",
        "/System/Library/LaunchDaemons/com.apple.system_installd.plist",
    ]

    private static let receiptHistoryPaths: [String] = [
        "/Library/Receipts",
        "/private/var/db/receipts",
        "/var/db/receipts",
        "/Library/Receipts/InstallHistory.plist",
        "/Library/InstallerSandboxes",
        "/private/var/folders",
        "/System/Library/PrivateFrameworks/PackageKit.framework",
    ]

    private static let pluginPaths: [String] = [
        "/Library/Installer Plugins",
        "/System/Library/InstallerPlugins",
        "/Library/InstallerPlugins",
    ]

    private static let toolingPaths: [String] = [
        "/usr/sbin/installer",
        "/usr/sbin/pkgutil",
        "/usr/bin/pkgbuild",
        "/usr/bin/productbuild",
        "/System/Library/CoreServices/Installer.app",
        "/System/Library/PrivateFrameworks/PackageKit.framework",
    ]

    public init() {}

    public func collect(context: EvaluationContext) async throws -> CollectedState {
        let fm = FileManager.default
        var notes: [String] = [
            "PackageKit installer design surface: path presence only - never builds pkgs, never invokes installd/package_script_service",
        ]

        var services: [String] = []
        for path in Self.servicePaths where fm.fileExists(atPath: path) {
            services.append(path)
            notes.append("installer_service: \(path)")
        }

        var receipts: [String] = []
        for path in Self.receiptHistoryPaths where fm.fileExists(atPath: path) {
            // Skip generic /private/var/folders (always present) unless paired with InstallerSandboxes note.
            if path == "/private/var/folders" {
                notes.append("var_folders_present: \(path) (InstallerSandboxes class may live under randomized subpaths - not enumerated)")
                continue
            }
            receipts.append(path)
            notes.append("receipt_or_history: \(path)")
        }

        var plugins: [String] = []
        for path in Self.pluginPaths where fm.fileExists(atPath: path) {
            plugins.append(path)
            notes.append("installer_plugin_dir: \(path)")
        }

        var tooling: [String] = []
        for path in Self.toolingPaths where fm.fileExists(atPath: path) {
            tooling.append(path)
            notes.append("installer_tool: \(path)")
        }

        services = Array(Set(services)).sorted()
        receipts = Array(Set(receipts)).sorted()
        plugins = Array(Set(plugins)).sorted()
        tooling = Array(Set(tooling)).sorted()

        let surface =
            !services.isEmpty
            || receipts.count >= 1
            || tooling.count >= 2

        var state = CollectedState()
        state.packageKitInstallerDesign = PackageKitInstallerDesignState(
            installerServicePaths: services,
            receiptAndHistoryPaths: receipts,
            installerPluginPaths: plugins,
            toolingPaths: tooling,
            designSurfacePresent: surface,
            notes: notes
        )
        state.collectorNotes[Self.id] =
            "services=\(services.count) receipts=\(receipts.count) "
            + "plugins=\(plugins.count) tooling=\(tooling.count) surface=\(surface)"
        return state
    }
}
