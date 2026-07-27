import Foundation
import RootstockCore

/// Path-to-impact: Continuity / AirDrop proximity transfer surface.
///
/// Research basis: AirDrop preference checklists; proximity data-transfer research.
/// Safety and behavior: typed compound with FDA/session paths; never scrapes pasteboard or forces sends.
public struct ContinuityAirDropSurfaceVector: Check {
    public static let id = "rootstock.vector.continuity.airdrop_surface"
    public static let cost: CollectorCost = .low

    public init() {}

    public func evaluate(state: CollectedState, context: EvaluationContext) async throws -> [Finding] {
        let cont = state.continuityAirDrop
        let airdrop = cont?.airdropPrefPaths.count ?? 0
        let continuity = cont?.continuityFrameworkPaths.count ?? 0
        let nearby = cont?.nearbyShareHints.count ?? 0
        let surface = cont?.proximitySurfacePresent == true || airdrop + continuity + nearby > 0
        let note = state.collectorNotes["collect.continuity_airdrop"] != nil

        guard surface || note else { return [] }

        let fda = state.tcc?.fullDiskAccessLikely == true
        let sensitive =
            state.browserMeta.contains(where: \.exists)
            || state.credPaths.contains(where: \.exists)
        let remote =
            state.network?.remoteLoginSSH == true
            || state.network?.screenSharingARD == true
        let axSignals = state.tcc?.domainSignals.contains {
            $0.lowercased().contains("screen") || $0.lowercased().contains("accessib")
        } ?? false

        // Path-to-impact: proximity surface + (sensitive session OR FDA OR remote OR AX)
        guard fda || sensitive || remote || axSignals || (airdrop + continuity >= 2) else {
            return []
        }

        var evidence: [Evidence] = [
            Evidence(
                type: "continuity_summary",
                detail:
                    "airdropPrefs=\(airdrop) continuity=\(continuity) nearby=\(nearby) "
                    + "fda=\(fda) sensitivePaths=\(sensitive) remote=\(remote)"
            ),
        ]
        if let cont {
            for path in (cont.airdropPrefPaths + cont.continuityFrameworkPaths + cont.nearbyShareHints)
                .prefix(12)
            {
                evidence.append(Evidence(type: "continuity_path", path: path, detail: "proximity component"))
            }
            for n in cont.notes.prefix(6) {
                evidence.append(Evidence(type: "continuity_note", detail: n))
            }
        }
        evidence.append(
            Evidence(
                type: "honesty",
                detail:
                    "Assess never reads Universal Clipboard contents, never forces AirDrop transfers, "
                    + "never builds proximity malware."
            )
        )

        let severity: Severity = (fda && sensitive) ? .medium : .low

        return [
            Finding(
                id: Self.id,
                title: sensitive
                    ? "Continuity/AirDrop proximity surface near sensitive session path inventory"
                    : "Continuity / AirDrop proximity transfer surface",
                severity: severity,
                confidence: .low,
                category: .network,
                evidence: evidence,
                attackTechniques: ["T1091", "T1005", "T1011"],
                remediation: [
                    "Restrict AirDrop to contacts-only or off on high-value endpoints via MDM",
                    "Disable Continuity features where policy forbids multi-device handoff",
                    "Physically secure endpoints with open proximity transfer",
                    "OPSEC: Rootstock Red does not exfil pasteboard or weaponize AirDrop",
                ],
                falsePositiveNotes:
                    "Continuity frameworks are stock on modern macOS. Prioritize open-receive policy "
                    + "compounds with high-value data paths when policy signals exist.",
                dryRunSafe: true,
                opsecScore: 15,
                tccDomains: fda ? ["FullDiskAccess"] : [],
                esfExpected: ["OPEN"]
            ),
        ]
    }
}
