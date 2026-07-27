import Foundation
import RootstockCore

/// App sandbox / entitlement thick-client surface (Wave-7).
///
/// Research basis: MacPEAS / inject-check entitlement inventories; thick-client risk lists.
/// Safety and behavior: typed `AppSandboxEntitlementState`; reuses inject/codesign signals; never
/// mutates entitlements or strips sandbox.
public struct AppSandboxEntitlementsCollector: Collector {
    public static let id = "collect.app_sandbox_entitlements"
    public static let cost: CollectorCost = .low

    /// High-value thick-client samples under /Applications (path presence only).
    private static let thickClientCandidates: [String] = [
        "/Applications/Google Chrome.app",
        "/Applications/Firefox.app",
        "/Applications/Microsoft Edge.app",
        "/Applications/Slack.app",
        "/Applications/Zoom.app",
        "/Applications/Microsoft Teams.app",
        "/Applications/Discord.app",
        "/Applications/Visual Studio Code.app",
        "/Applications/Cursor.app",
        "/Applications/Spotify.app",
        "/Applications/1Password.app",
        "/Applications/Docker.app",
        "/Applications/Notion.app",
        "/Applications/Figma.app",
        "/Applications/Postman.app",
        "/Applications/iTerm.app",
        "/Applications/Warp.app",
        "/Applications/Obsidian.app",
        "/Applications/Telegram.app",
        "/Applications/WhatsApp.app",
    ]

    public init() {}

    public func collect(context: EvaluationContext) async throws -> CollectedState {
        let fm = FileManager.default
        var notes: [String] = [
            "App sandbox/entitlement surface: path + risk-class inventory - no entitlement mutation",
        ]

        var appSamples: [String] = []
        for path in Self.thickClientCandidates {
            if fm.fileExists(atPath: path) {
                appSamples.append(path)
                notes.append("thick_client_present: \(path)")
            }
        }

        // Shallow extra sample from home Applications when present.
        let userApps = NSHomeDirectory() + "/Applications"
        if let names = try? fm.contentsOfDirectory(atPath: userApps) {
            for name in names.prefix(12) where name.hasSuffix(".app") {
                let full = (userApps as NSString).appendingPathComponent(name)
                appSamples.append(full)
                notes.append("user_app_sample: \(full)")
            }
        }

        appSamples = Array(Set(appSamples)).sorted()

        // Infer sandboxed vs risk from existing codesign/inject signals when available is done
        // at vector time; collector records path inventory + common entitlement-support paths.
        var sandboxedHints: [String] = []
        var dangerousEntitlementHints: [String] = []
        var unsandboxedRiskPaths: [String] = []

        let sandboxSupportPaths = [
            "/System/Library/Sandbox",
            "/usr/lib/libsandbox.1.dylib",
            "/System/Library/Frameworks/Security.framework",
        ]
        for path in sandboxSupportPaths {
            if fm.fileExists(atPath: path) {
                sandboxedHints.append(path)
                notes.append("sandbox_support: \(path)")
            }
        }

        // Debug / inject-class entitlement support tooling (presence only).
        let dangerousSupport = [
            "/usr/bin/codesign",
            "/usr/bin/security",
            "/usr/bin/csreq",
        ]
        for path in dangerousSupport {
            if fm.fileExists(atPath: path) {
                dangerousEntitlementHints.append("tool:\(path)")
            }
        }

        // Apps without typical sandboxed container layout under Containers are hints only.
        let containersRoot = NSHomeDirectory() + "/Library/Containers"
        if fm.fileExists(atPath: containersRoot) {
            notes.append("containers_root_present: \(containersRoot)")
            sandboxedHints.append(containersRoot)
        } else {
            notes.append("containers_root_absent (many unsandboxed apps expected)")
        }

        // Flag Electron/thick clients as unsandboxed-risk candidates when present
        // (actual sandbox claim requires codesign; vector compounds with inject samples).
        let electronLike = appSamples.filter {
            let lower = $0.lowercased()
            return lower.contains("slack")
                || lower.contains("code")
                || lower.contains("discord")
                || lower.contains("cursor")
                || lower.contains("postman")
                || lower.contains("obsidian")
        }
        unsandboxedRiskPaths.append(contentsOf: electronLike)
        for p in electronLike {
            notes.append("thick_client_risk_class: \(p)")
        }

        sandboxedHints = Array(Set(sandboxedHints)).sorted()
        dangerousEntitlementHints = Array(Set(dangerousEntitlementHints)).sorted()
        unsandboxedRiskPaths = Array(Set(unsandboxedRiskPaths)).sorted()

        var state = CollectedState()
        state.appSandboxEntitlements = AppSandboxEntitlementState(
            appSamples: appSamples,
            sandboxedHints: sandboxedHints,
            dangerousEntitlementHints: dangerousEntitlementHints,
            unsandboxedRiskPaths: unsandboxedRiskPaths,
            notes: notes
        )
        state.collectorNotes[Self.id] =
            "apps=\(appSamples.count) sandboxedHints=\(sandboxedHints.count) "
            + "dangerous=\(dangerousEntitlementHints.count) riskPaths=\(unsandboxedRiskPaths.count)"
        return state
    }
}
