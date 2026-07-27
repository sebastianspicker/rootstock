import Foundation
import RootstockCore

/// Path-to-impact: Platform SSO / Kerberos / AD identity as lateral and ticket-abuse surface.
///
/// Research basis: bifrost Kerberos themes, Orchard AD enum ideas, Empire identity modules.
/// Safety and behavior: filesystem-heuristic only (no ticket dump / ptt); ATT&CK + OPSEC honesty;
/// compounds with remote access and high-value cred paths without secret material.
public struct PlatformSSOLateralVector: Check {
    public static let id = "rootstock.vector.auth.platform_sso_lateral"
    public static let cost: CollectorCost = .low

    public init() {}

    public func evaluate(state: CollectedState, context: EvaluationContext) async throws -> [Finding] {
        guard let identity = state.identity else { return [] }

        let pSSO = identity.platformSSO == true
        let ad = identity.adBound == true
        let krb = identity.kerberosConfigPresent == true
        let ssoPaths = identity.ssoPaths
        let odPaths = identity.odConfigPaths

        // Distinct from generic cred_or_identity_pivot: require directory/SSO identity plane.
        guard pSSO || ad || (krb && (!ssoPaths.isEmpty || !odPaths.isEmpty)) else { return [] }

        var evidence: [Evidence] = [
            Evidence(
                type: "identity_lateral",
                detail:
                    "platformSSO=\(identity.platformSSO.rootstockDescribe) "
                    + "adBound=\(identity.adBound.rootstockDescribe) "
                    + "kerberosConfig=\(identity.kerberosConfigPresent.rootstockDescribe) "
                    + "(no tickets dumped; no keytab read)"
            ),
        ]
        for path in ssoPaths.prefix(12) {
            evidence.append(Evidence(type: "sso_path", path: path, detail: "Platform SSO / AppSSO support path"))
        }
        for path in odPaths.prefix(12) {
            evidence.append(Evidence(type: "od_path", path: path, detail: "Open Directory / AD config path"))
        }
        for note in identity.notes.prefix(10) {
            evidence.append(Evidence(type: "note", detail: note))
        }

        let remote =
            state.network?.remoteLoginSSH == true
            || state.network?.screenSharingARD == true
        if remote {
            evidence.append(
                Evidence(
                    type: "compound_remote",
                    detail: "Remote access enabled - identity plane increases lateral value of this host"
                )
            )
        }
        let cloudCreds = state.credPaths.filter {
            $0.exists && ["aws", "gcp", "azure", "ssh"].contains($0.kind)
        }
        if !cloudCreds.isEmpty {
            evidence.append(
                Evidence(
                    type: "compound_cred_paths",
                    detail: "cloud/ssh path presence=\(cloudCreds.count) (metadata only)"
                )
            )
        }

        let severity: Severity
        let title: String
        if pSSO && ad {
            severity = .medium
            title = "Identity lateral vector: Platform SSO + AD-bound posture"
        } else if pSSO {
            severity = remote || !cloudCreds.isEmpty ? .medium : .low
            title = "Identity lateral vector: Platform SSO surface"
        } else if ad && krb {
            severity = .medium
            title = "Identity lateral vector: AD-bound + Kerberos config surface"
        } else {
            severity = .low
            title = "Identity lateral vector: directory/SSO configuration surface"
        }

        return [
            Finding(
                id: Self.id,
                title: title,
                severity: severity,
                confidence: .medium,
                category: .auth,
                evidence: evidence,
                attackTechniques: ["T1078.002", "T1558", "T1550.003", "T1087.002", "T1550"],
                remediation: [
                    "Validate Platform SSO / AD join via MDM inventory; remove stale directory bindings",
                    "Prefer short-lived SSO tokens over long-lived key files beside identity join",
                    "Monitor anomalous Kerberos ticket requests from endpoints (SOC), not local keytab dumps",
                    "OPSEC: Rootstock Red never dumps tickets or performs pass-the-ticket - assess only",
                ],
                falsePositiveNotes:
                    "Path heuristics are not live SSO/AD bind proofs. Kerberos conf alone is common on "
                    + "developer images without enterprise join.",
                dryRunSafe: true,
                opsecScore: 20,
                esfExpected: ["OPEN"]
            ),
        ]
    }

}
