import Foundation
import RootstockCore

/// Path-to-impact: system LaunchDaemons / system LaunchAgents as persistence and privesc surface.
///
/// Research basis: PersistentJXA / PEASS system launchd inventory; Objective-See persistence taxonomy.
/// Safety and behavior: path-to-impact ranking (writable, unlabeled, compound weak SIP) vs pure inventory
/// (see also `SystemLaunchdInventoryCheck` for info-only listing).
public struct SystemLaunchDaemonSurfaceVector: Check {
    public static let id = "rootstock.vector.persist.system_launchdaemon_surface"
    public static let cost: CollectorCost = .low

    public init() {}

    public func evaluate(state: CollectedState, context: EvaluationContext) async throws -> [Finding] {
        let agents = state.systemLaunchAgents
        let daemons = state.launchDaemons
        let combined = agents + daemons
        guard !combined.isEmpty else { return [] }

        var writable: [LaunchAgentEntry] = []
        var unlabeled: [LaunchAgentEntry] = []
        for entry in combined {
            let parent = URL(fileURLWithPath: entry.path).deletingLastPathComponent().path
            let isWritable =
                FileManager.default.isWritableFile(atPath: entry.path)
                || FileManager.default.isWritableFile(atPath: parent)
            if isWritable { writable.append(entry) }
            if entry.label == nil || entry.label?.isEmpty == true { unlabeled.append(entry) }
        }

        // Path-to-impact threshold: writable, large surface, unlabeled cluster, or weak SIP compound.
        let sipOff = state.protections?.sipEnabled == false
        let largeSurface = combined.count >= 3
        guard !writable.isEmpty || largeSurface || !unlabeled.isEmpty || (sipOff && !combined.isEmpty) else {
            return []
        }

        var evidence: [Evidence] = [
            Evidence(
                type: "summary",
                detail:
                    "systemLaunchAgents=\(agents.count) launchDaemons=\(daemons.count) "
                    + "writable=\(writable.count) unlabeled=\(unlabeled.count) sipOff=\(sipOff)"
            ),
        ]
        for entry in writable.prefix(20) {
            evidence.append(
                Evidence(
                    type: "writable_system_launchd",
                    path: entry.path,
                    detail: "label=\(entry.label ?? "unlabeled") program=\(entry.programArguments.prefix(2).joined(separator: " "))"
                )
            )
        }
        for entry in (writable.isEmpty ? combined : daemons).prefix(20) {
            if writable.contains(where: { $0.path == entry.path }) { continue }
            evidence.append(
                Evidence(
                    type: "system_launchd",
                    path: entry.path,
                    detail: "label=\(entry.label ?? "unlabeled")"
                )
            )
        }
        if sipOff {
            evidence.append(
                Evidence(
                    type: "sip_compound",
                    detail: "SIP disabled compounds system launchd abuse into higher impact"
                )
            )
        }
        evidence.append(
            Evidence(
                type: "btm_honesty",
                detail:
                    "System LaunchDaemons are not user BTM login items; still monitor launchd loads via ESF"
            )
        )

        let severity: Severity
        let title: String
        if !writable.isEmpty && sipOff {
            severity = .critical
            title = "System launchd vector: writable daemons/agents with SIP off (\(writable.count))"
        } else if !writable.isEmpty {
            severity = .high
            title = "System launchd vector: user-writable system agents/daemons (\(writable.count))"
        } else if sipOff {
            severity = .medium
            title = "System launchd surface (\(combined.count)) with SIP disabled"
        } else {
            severity = .medium
            title = "System LaunchDaemon / system LaunchAgent attack surface (\(combined.count))"
        }

        return [
            Finding(
                id: Self.id,
                title: title,
                severity: severity,
                confidence: writable.isEmpty ? .medium : .high,
                category: .persist,
                evidence: evidence,
                attackTechniques: ["T1543.001", "T1543.004", "T1068", "T1053.004"],
                remediation: [
                    "Audit /Library/LaunchDaemons and /Library/LaunchAgents for unexpected Labels",
                    "Enforce root:wheel ownership and non-user-writable modes on system launchd plists",
                    "Re-enable SIP if disabled; manage daemons via signed packages / MDM",
                    "OPSEC: reading system launchd dirs is low noise; writing them requires root and is lab-gated",
                ],
                falsePositiveNotes:
                    "Vendor system daemons are normal. Writable hits under temp/lab trees may be synthetic. "
                    + "Inventory-only hosts with locked plists may still fire at medium when surface is large.",
                dryRunSafe: true,
                opsecScore: 24,
                esfExpected: ["OPEN", "WRITE"]
            ),
        ]
    }
}
