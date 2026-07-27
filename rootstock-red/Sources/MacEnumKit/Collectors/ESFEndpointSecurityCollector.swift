import Foundation
import RootstockCore

/// Endpoint Security / EDR sensor posture via path heuristics (assess-safe).
///
/// Research basis: ESF research talks, commercial EDR path catalogs, sysext inventory ideas.
/// Safety and behavior: typed `ESFPostureState` + sensor-gap inputs for vectors; no client unload;
/// **Apple ES infrastructure is never counted as a third-party EDR client** (stock macOS
/// always has EndpointSecurity.framework / endpointsecurityd).
public struct ESFEndpointSecurityCollector: Collector {
    public static let id = "collect.esf_endpoint_security"
    public static let cost: CollectorCost = .medium

    /// Always-present (or near-always) Apple ES infrastructure - not third-party clients.
    private static let appleInfrastructureProbes: [(name: String, path: String)] = [
        ("EndpointSecurity.framework", "/System/Library/Frameworks/EndpointSecurity.framework"),
        ("EndpointSecurity.framework (Library)", "/Library/Frameworks/EndpointSecurity.framework"),
        ("endpointsecurityd", "/usr/libexec/endpointsecurityd"),
    ]

    /// Third-party ES client / EDR support path probes (presence only).
    /// Do not include bare `/Library/SystemExtensions` - that directory exists on stock macOS.
    private static let thirdPartyClientProbes: [(name: String, path: String)] = [
        ("CrowdStrike Falcon", "/Library/CS/falconctl"),
        ("CrowdStrike app", "/Applications/Falcon.app"),
        ("SentinelOne", "/Applications/SentinelOne"),
        ("SentinelOne agent", "/Library/Sentinel"),
        ("CarbonBlack", "/Applications/VMware Carbon Black Cloud"),
        ("CarbonBlack sensor", "/Library/Application Support/com.vmware.carbonblack"),
        ("Microsoft Defender", "/Applications/Microsoft Defender.app"),
        ("Microsoft Defender data", "/Library/Application Support/Microsoft/Defender"),
        ("Jamf Protect", "/Library/Application Support/JamfProtect"),
        ("Jamf Protect app", "/Applications/JamfProtect.app"),
        ("Cortex XDR", "/Library/Application Support/PaloAltoNetworks/Traps"),
        ("Osquery", "/usr/local/bin/osqueryd"),
        ("Osquery app", "/opt/osquery/bin/osqueryd"),
        ("Santa", "/Applications/Santa.app"),
        ("BlockBlock", "/Applications/BlockBlock.app"),
        ("LuLu", "/Applications/LuLu.app"),
    ]

    /// Path substrings that indicate Apple-owned system extensions (not third-party EDR).
    private static let appleSysextMarkers: [String] = [
        "com.apple.",
        "/System/Library/",
    ]

    public init() {}

    public func collect(context: EvaluationContext) async throws -> CollectedState {
        let fm = FileManager.default
        var notes: [String] = [
            "ESF/EDR posture: Apple infrastructure vs third-party clients separated - no client unload",
        ]
        var appleInfra: [String] = []
        var thirdPartyClients: [String] = []
        var edrHints: [String] = []

        // MARK: Apple ES infrastructure (framework / daemon) - never clientPaths
        var frameworkPresent: Bool?
        var anyFrameworkHit = false
        for probe in Self.appleInfrastructureProbes {
            if fm.fileExists(atPath: probe.path) {
                appleInfra.append(probe.path)
                notes.append("apple_infra: \(probe.name) path=\(probe.path)")
                if probe.path.contains("EndpointSecurity.framework") {
                    anyFrameworkHit = true
                }
            }
        }
        frameworkPresent = anyFrameworkHit ? true : nil
        if frameworkPresent == nil {
            notes.append("EndpointSecurity.framework path not observed (unexpected on modern macOS)")
        }

        // MARK: Third-party EDR / ES client paths only
        for probe in Self.thirdPartyClientProbes {
            if fm.fileExists(atPath: probe.path) {
                thirdPartyClients.append(probe.path)
                edrHints.append(probe.name)
                notes.append("third_party_client: \(probe.name) path=\(probe.path)")
            }
        }

        // MARK: System extensions - count third-party .systemextension bundles only
        // Bare directory existence is NOT a client hit.
        var thirdPartySysextCount = 0
        var thirdPartySysextPaths: [String] = []
        let sysextRoot = URL(fileURLWithPath: "/Library/SystemExtensions", isDirectory: true)
        if fm.fileExists(atPath: sysextRoot.path) {
            notes.append("systemExtension root present (directory existence ≠ EDR client)")
            if let contents = try? fm.contentsOfDirectory(
                at: sysextRoot,
                includingPropertiesForKeys: nil,
                options: [.skipsHiddenFiles]
            ) {
                var allSysext: [String] = []
                for item in contents {
                    if item.pathExtension == "systemextension" {
                        allSysext.append(item.path)
                    } else if let nested = try? fm.contentsOfDirectory(
                        at: item,
                        includingPropertiesForKeys: nil,
                        options: [.skipsHiddenFiles]
                    ) {
                        allSysext.append(
                            contentsOf: nested.filter { $0.pathExtension == "systemextension" }.map(\.path)
                        )
                    }
                }
                for path in allSysext {
                    if Self.isAppleOwnedSysext(path) {
                        notes.append("apple_sysext (ignored for client count): \(path)")
                    } else {
                        thirdPartySysextCount += 1
                        thirdPartySysextPaths.append(path)
                        thirdPartyClients.append(path)
                        notes.append("third_party_sysext: \(path)")
                    }
                }
                notes.append(
                    "sysext thirdParty=\(thirdPartySysextCount) totalListed=\(allSysext.count)"
                )
            } else {
                notes.append("systemExtension root present but listing denied")
            }
        } else {
            notes.append("systemExtension root absent")
        }

        // Deduplicate
        var seenClients = Set<String>()
        thirdPartyClients = thirdPartyClients.filter { seenClients.insert($0).inserted }
        edrHints = Array(Set(edrHints)).sorted()
        appleInfra = Array(Set(appleInfra)).sorted()

        var state = CollectedState()
        state.esf = ESFPostureState(
            frameworkPresent: frameworkPresent,
            clientPaths: thirdPartyClients,
            systemExtensionCount: thirdPartySysextCount,
            edrHints: edrHints,
            notes: notes
        )
        // Record apple infra in notes only (also mirror in collector note for gap detection).
        state.collectorNotes[Self.id] =
            "framework=\(frameworkPresent.map(String.init(describing:)) ?? "nil") "
            + "thirdPartyClients=\(thirdPartyClients.count) "
            + "thirdPartySysext≈\(thirdPartySysextCount) "
            + "edrHints=\(edrHints.count) "
            + "appleInfra=\(appleInfra.count)"
        // Explicit gap-friendly token when no third-party clients (stock OS still has appleInfra).
        if thirdPartyClients.isEmpty && edrHints.isEmpty {
            state.collectorNotes["esf.sensor_gap"] =
                "third_party_clients=0 apple_infra_only=\(appleInfra.isEmpty ? "false" : "true")"
        }
        return state
    }

    /// Whether a systemextension path looks Apple-owned (not a third-party EDR client).
    public static func isAppleOwnedSysext(_ path: String) -> Bool {
        let lower = path.lowercased()
        return appleSysextMarkers.contains { lower.contains($0.lowercased()) }
    }

    /// Test helper: classify a probe path as Apple infrastructure (not third-party client).
    public static func isAppleInfrastructurePath(_ path: String) -> Bool {
        appleInfrastructureProbes.contains { $0.path == path }
            || path == "/Library/SystemExtensions"
            || path.hasPrefix("/System/Library/Frameworks/EndpointSecurity")
            || path == "/usr/libexec/endpointsecurityd"
    }
}
