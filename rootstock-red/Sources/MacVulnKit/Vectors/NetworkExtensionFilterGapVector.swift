import Foundation
import RootstockCore

/// Path-to-impact: thin NetworkExtension / VPN / content-filter inventory with remote or high-value surface.
///
/// Research basis: NE firewall research; content-filter bypass classes; vendor filter catalogs.
/// Safety and behavior: typed NE posture compound with remote/identity; never modifies NE config.
public struct NetworkExtensionFilterGapVector: Check {
    public static let id = "rootstock.vector.ne.vpn_content_filter_gap"
    public static let cost: CollectorCost = .low

    public init() {}

    public func evaluate(state: CollectedState, context: EvaluationContext) async throws -> [Finding] {
        let ne = state.networkExtension
        // Enterprise filter hints only - stock pf/ALF must never suppress gap (see collector).
        let enterpriseFilters = (ne?.contentFilterHints ?? []).filter { hint in
            let lower = hint.lowercased()
            return !lower.contains("pf_conf")
                && !lower.contains("pf_anchors")
                && !lower.contains("/etc/pf.")
                && !lower.contains("application_firewall")
                && !lower.contains("com.apple.alf")
        }
        let filterHints = enterpriseFilters.count
        let vpnPaths = ne?.vpnConfigPaths.count ?? 0
        let neApps = ne?.neAppPaths.count ?? 0
        let thinFilter = filterHints == 0 && neApps == 0

        let remote =
            state.network?.remoteLoginSSH == true
            || state.network?.screenSharingARD == true
        let highValue =
            state.credPaths.contains(where: \.exists)
            || state.identity?.platformSSO == true
            || state.identity?.adBound == true

        let gapNote = state.collectorNotes["ne.filter_gap"] != nil
            || state.collectorNotes["collect.network_extension"]?
                .contains("contentFilter=0") == true
            || state.collectorNotes["collect.network_extension"]?
                .contains("filters=0") == true

        let shouldFire = thinFilter && (remote || highValue || gapNote || vpnPaths > 0)
        guard shouldFire else { return [] }

        var evidence: [Evidence] = [
            Evidence(
                type: "ne_summary",
                detail:
                    "framework=\((ne?.frameworkPresent).rootstockDescribe) "
                    + "vpnConfigs=\(vpnPaths) contentFilterHints=\(filterHints) "
                    + "packetTunnel=\(ne?.packetTunnelHints.count ?? 0) neApps=\(neApps)"
            ),
        ]
        if let ne {
            for note in ne.notes.prefix(10) {
                evidence.append(Evidence(type: "ne_note", detail: note))
            }
            for path in (ne.vpnConfigPaths + ne.neAppPaths).prefix(8) {
                evidence.append(Evidence(type: "ne_path", path: path, detail: "NE-related path"))
            }
        }
        if remote {
            evidence.append(
                Evidence(
                    type: "compound_remote",
                    detail:
                        "ssh=\((state.network?.remoteLoginSSH).rootstockDescribe) "
                        + "ard=\((state.network?.screenSharingARD).rootstockDescribe)"
                )
            )
        }
        if highValue {
            evidence.append(
                Evidence(
                    type: "compound_high_value",
                    detail:
                        "credPaths=\(state.credPaths.filter(\.exists).count) "
                        + "platformSSO=\((state.identity?.platformSSO).rootstockDescribe) "
                        + "adBound=\((state.identity?.adBound).rootstockDescribe)"
                )
            )
        }
        evidence.append(
            Evidence(
                type: "honesty",
                detail:
                    "Path probes miss MDM-deployed filters and in-kernel pf rules. "
                    + "Thin inventory ≠ proof that network filtering is absent."
            )
        )

        let severity: Severity = (thinFilter && remote) ? .medium : .low

        return [
            Finding(
                id: Self.id,
                title: thinFilter && remote
                    ? "NetworkExtension gap: thin content-filter inventory with remote access enabled"
                    : "NetworkExtension / VPN / content-filter posture gap candidate",
                severity: severity,
                confidence: .low,
                category: .network,
                evidence: evidence,
                attackTechniques: ["T1562.004", "T1090", "T1021"],
                remediation: [
                    "Deploy approved content-filter / NE clients via MDM on remotely accessible hosts",
                    "Inventory VPN and packet-tunnel providers against corporate allow-list",
                    "Purple: pair assess findings with expected NE/filter telemetry events",
                    "OPSEC: Rootstock Red never modifies NetworkExtension configuration",
                ],
                falsePositiveNotes:
                    "Many enterprise filters install as system extensions under vendor paths not in the probe catalog.",
                dryRunSafe: true,
                opsecScore: 14,
                esfExpected: ["OPEN", "NW_CONNECTION"]
            ),
        ]
    }

}
