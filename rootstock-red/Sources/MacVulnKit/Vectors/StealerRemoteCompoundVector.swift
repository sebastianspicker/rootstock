import Foundation
import RootstockCore

/// Wave-10 compound depth: multi-app stealer paths × remote access or FDA.
///
/// Research basis: AMOS/Atomic/Odyssey/PXA 2025–2026 infostealer collection themes.
/// Safety and behavior: multi-app path plane compounded with SSH/ARD or FDA; never dumps secrets.
public struct StealerRemoteCompoundVector: Check {
    public static let id = "rootstock.vector.data.stealer_remote_compound"
    public static let cost: CollectorCost = .low

    public init() {}

    public func evaluate(state: CollectedState, context: EvaluationContext) async throws -> [Finding] {
        let sp = state.infoStealerPathPlane
        let browser = sp?.browserAdjacentPaths.count ?? 0
        let messaging = sp?.messagingAndVaultPaths.count ?? 0
        let wallet = sp?.walletAndSyncPaths.count ?? 0
        let total = browser + messaging + wallet

        // Multi-app stealer plane: total ≥ 3 OR (browser + messaging).
        let multiApp = total >= 3 || (browser >= 1 && messaging >= 1)
        guard multiApp else { return [] }

        let remote =
            state.network?.remoteLoginSSH == true
            || state.network?.screenSharingARD == true
        let fda = state.tcc?.fullDiskAccessLikely == true

        // Compound gate: multi-app paths AND (remote SSH/ARD OR FDA).
        guard remote || fda else { return [] }

        let sensorThin =
            state.esf?.clientPaths.isEmpty == true
            || state.securityProducts.filter(\.present).isEmpty

        var evidence: [Evidence] = [
            Evidence(
                type: "stealer_remote_compound_summary",
                detail:
                    "browser=\(browser) messagingVault=\(messaging) walletSync=\(wallet) total=\(total) "
                    + "remote=\(remote) fda=\(fda) sensorThin=\(sensorThin)"
            ),
        ]
        if let sp {
            for path in (sp.browserAdjacentPaths + sp.messagingAndVaultPaths + sp.walletAndSyncPaths).prefix(12) {
                evidence.append(
                    Evidence(type: "collection_path", path: path, detail: "stealer-class path (meta only)")
                )
            }
            for n in sp.notes.prefix(4) {
                evidence.append(Evidence(type: "collection_note", detail: n))
            }
        }
        evidence.append(
            Evidence(
                type: "compound_amplifier",
                detail:
                    "impact amplifiers: remote=\(remote) fda=\(fda) "
                    + "(path-to-impact ranking - no secret harvest)"
            )
        )
        evidence.append(
            Evidence(
                type: "honesty",
                detail:
                    "Assess never dumps cookies, passwords, keychain items, Messages/Mail contents, "
                    + "or crypto wallet material. Multi-app path compounds only."
            )
        )

        let severity: Severity
        if fda && remote && total >= 6 {
            severity = .high
        } else if (fda && total >= 4) || (remote && browser >= 1 && messaging >= 1) {
            severity = .medium
        } else {
            severity = .low
        }

        return [
            Finding(
                id: Self.id,
                title: remote && fda
                    ? "Info-stealer multi-app paths compound with remote access and FDA"
                    : (fda
                        ? "Info-stealer multi-app paths under likely Full Disk Access"
                        : "Info-stealer multi-app paths compound with remote access"),
                severity: severity,
                confidence: .medium,
                category: .misconfig,
                evidence: evidence,
                attackTechniques: ["T1555", "T1005", "T1539", "T1021.004"],
                remediation: [
                    "Limit Full Disk Access grants to approved security/backup agents only",
                    "Disable unnecessary Remote Login / Screen Sharing on high-value collection hosts",
                    "Monitor multi-app data-store access patterns (browser + Mail/Messages + vault apps)",
                    "OPSEC: Rootstock Red does not harvest cookies, passwords, or wallet keys",
                ],
                falsePositiveNotes:
                    "Browser and Documents paths exist on typical Macs. Prioritize multi-family path "
                    + "co-presence with FDA or remote access for stealer-class engagement narrative.",
                dryRunSafe: true,
                opsecScore: 26,
                esfExpected: ["OPEN", "READ"]
            ),
        ]
    }
}
