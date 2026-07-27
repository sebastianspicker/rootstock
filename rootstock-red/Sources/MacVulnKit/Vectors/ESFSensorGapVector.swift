import Foundation
import RootstockCore

/// Path-to-impact: Endpoint Security / EDR sensor gap vs remote or high-value surface.
///
/// Research basis: ESF talks; Atomic purple pairs; security product path catalogs.
/// Safety and behavior: typed ESF posture compound with remote/identity; never auto-disables sensors.
public struct ESFSensorGapVector: Check {
    public static let id = "rootstock.vector.esf.sensor_gap"
    public static let cost: CollectorCost = .low

    public init() {}

    public func evaluate(state: CollectedState, context: EvaluationContext) async throws -> [Finding] {
        let esf = state.esf
        let productPresent = state.securityProducts.contains(where: \.present)
        // clientPaths = third-party EDR/ES clients only (Apple infra excluded by collector).
        let thirdPartyClientCount = esf?.clientPaths.count ?? 0
        let hints = esf?.edrHints ?? []
        let thirdPartySysext = esf?.systemExtensionCount ?? 0

        // Thin third-party sensor: no product catalog hits, no third-party clients/hints.
        // Stock Apple ES infrastructure (endpointsecurityd / framework) must NOT suppress this.
        let thinThirdPartySensor =
            !productPresent
            && thirdPartyClientCount == 0
            && hints.isEmpty

        let remote =
            state.network?.remoteLoginSSH == true
            || state.network?.screenSharingARD == true
        let highValue =
            state.credPaths.contains(where: \.exists)
            || state.identity?.platformSSO == true
            || state.identity?.adBound == true

        let gapNote = state.collectorNotes["esf.sensor_gap"] != nil
            || state.collectorNotes["collect.esf_endpoint_security"]?
                .contains("thirdPartyClients=0") == true

        let shouldFire =
            thinThirdPartySensor && (remote || highValue || gapNote)
        guard shouldFire else { return [] }

        var evidence: [Evidence] = [
            Evidence(
                type: "sensor_summary",
                detail:
                    "securityProductsPresent=\(state.securityProducts.filter(\.present).count) "
                    + "thirdPartyClients=\(thirdPartyClientCount) edrHints=\(hints.count) "
                    + "thirdPartySysext≈\(thirdPartySysext) "
                    + "(Apple ES infrastructure excluded from client count)"
            ),
        ]
        if let esf {
            for note in esf.notes.prefix(12) {
                evidence.append(Evidence(type: "esf_note", detail: note))
            }
            for path in esf.clientPaths.prefix(12) {
                evidence.append(
                    Evidence(type: "third_party_client", path: path, detail: "third-party ES/EDR path")
                )
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
                    "Path probes miss many commercial agents (MDM-deployed sysexts). "
                    + "Treat as posture gap candidate, not proof of disabled EDR."
            )
        )

        let severity: Severity = (thinThirdPartySensor && remote) ? .medium : .low

        return [
            Finding(
                id: Self.id,
                title: thinThirdPartySensor && remote
                    ? "ESF/EDR sensor gap: no third-party sensor inventory with remote access enabled"
                    : "ESF/EDR sensor posture: thin third-party Endpoint Security coverage",
                severity: severity,
                confidence: .low,
                category: .securityProduct,
                evidence: evidence,
                attackTechniques: ["T1518.001", "T1562.001", "T1021"],
                remediation: [
                    "Confirm EDR/ES client deployment via MDM inventory (not only local paths)",
                    "Prioritize sensor coverage on hosts with Remote Login / Screen Sharing",
                    "Purple: pair assess findings with ESF OPEN/EXEC expectations for dual-use bins",
                    "OPSEC: Rootstock Red never unloads ES clients or disables security products",
                ],
                falsePositiveNotes:
                    "Many enterprise agents install under vendor-specific paths not in the probe catalog. "
                    + "Absence of path hits ≠ confirmed absence of telemetry.",
                dryRunSafe: true,
                opsecScore: 12,
                esfExpected: ["OPEN"]
            ),
        ]
    }

}
