import Foundation
import RootstockCore

/// Path-to-impact: Time Machine / local snapshot as alternate data-access surface.
///
/// Research basis: backup/snapshot data-access research; PEASS filesystem themes.
/// Safety and behavior: typed TimeMachineState × FDA/cred compound; never dumps backup contents.
public struct TimeMachineSnapshotAccessVector: Check {
    public static let id = "rootstock.vector.tm.snapshot_data_access"
    public static let cost: CollectorCost = .low

    public init() {}

    public func evaluate(state: CollectedState, context: EvaluationContext) async throws -> [Finding] {
        let tm = state.timeMachine
        let prefs = tm?.preferencesPresent == true
        let backups = tm?.backupPaths.count ?? 0
        let snapshots = tm?.localSnapshotHints.count ?? 0
        let volumes = tm?.volumeMountHints.count ?? 0
        let note = state.collectorNotes["collect.time_machine"] != nil
            || state.collectorNotes["tm.snapshot_surface"] != nil

        let surface = prefs || backups > 0 || snapshots > 0 || volumes > 0 || note
        guard surface else { return [] }

        let fda = state.tcc?.fullDiskAccessLikely == true
        let sensitivePaths =
            state.credPaths.contains(where: \.exists)
            || state.browserMeta.contains(where: \.exists)
        // Fire when TM surface + (FDA or sensitive path inventory or remote)
        let remote =
            state.network?.remoteLoginSSH == true
            || state.network?.screenSharingARD == true
        // Prefs-only with no compound still useful for inventory depth.
        guard fda || sensitivePaths || remote || snapshots > 0 || backups > 0 || prefs else {
            return []
        }

        var evidence: [Evidence] = [
            Evidence(
                type: "tm_summary",
                detail:
                    "preferencesPresent=\((tm?.preferencesPresent).rootstockDescribe) "
                    + "backupPaths=\(backups) localSnapshots=\(snapshots) volumeHints=\(volumes)"
            ),
        ]
        if let tm {
            for path in (tm.backupPaths + tm.localSnapshotHints + tm.volumeMountHints).prefix(10) {
                evidence.append(Evidence(type: "tm_path", path: path, detail: "TM/snapshot path hint"))
            }
            for n in tm.notes.prefix(8) {
                evidence.append(Evidence(type: "tm_note", detail: n))
            }
        }
        if fda {
            evidence.append(Evidence(type: "compound_fda", detail: "fullDiskAccessLikely=true"))
        }
        if sensitivePaths {
            evidence.append(
                Evidence(
                    type: "compound_sensitive",
                    detail:
                        "credPaths=\(state.credPaths.filter(\.exists).count) "
                        + "browserMetaExists=\(state.browserMeta.filter(\.exists).count)"
                )
            )
        }
        evidence.append(
            Evidence(
                type: "honesty",
                detail:
                    "Assess never reads backup payloads, keychains inside snapshots, or browser DBs. "
                    + "Local snapshots may retain deleted material - treat as data-access surface."
            )
        )

        let severity: Severity = (fda && (backups > 0 || snapshots > 0)) ? .medium : .low

        return [
            Finding(
                id: Self.id,
                title: fda
                    ? "Time Machine / snapshot data-access surface with FDA-likely posture"
                    : "Time Machine / local snapshot data-access surface",
                severity: severity,
                confidence: .low,
                category: .misconfig,
                evidence: evidence,
                attackTechniques: ["T1005", "T1530", "T1083"],
                remediation: [
                    "Encrypt Time Machine destinations; restrict who has FDA on backup-capable hosts",
                    "Review local snapshot retention on high-value endpoints",
                    "Ensure backup volumes are not world-readable when mounted",
                    "OPSEC: Rootstock Red never restores or dumps TM contents",
                ],
                falsePositiveNotes:
                    "TM prefs present on many Macs; prioritize FDA + mounted backup compounds.",
                dryRunSafe: true,
                opsecScore: 20,
                tccDomains: fda ? ["FullDiskAccess"] : [],
                esfExpected: ["OPEN"]
            ),
        ]
    }

}
