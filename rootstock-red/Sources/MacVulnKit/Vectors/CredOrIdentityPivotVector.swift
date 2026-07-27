import Foundation
import RootstockCore

/// Credential-path or directory-identity pivot vector - never dumps secrets.
public struct CredOrIdentityPivotVector: Check {
    public static let id = "rootstock.vector.auth.cred_or_identity_pivot"
    public static let cost: CollectorCost = .low

    public init() {}

    public func evaluate(state: CollectedState, context: EvaluationContext) async throws -> [Finding] {
        let existingCreds = state.credPaths.filter(\.exists)
        let identity = state.identity
        let adBound = identity?.adBound == true
        let platformSSO = identity?.platformSSO == true
        let kerberos = identity?.kerberosConfigPresent == true

        guard !existingCreds.isEmpty || adBound || platformSSO else { return [] }

        var evidence: [Evidence] = []
        evidence.append(
            Evidence(
                type: "pivot_summary",
                detail:
                    "credPathsPresent=\(existingCreds.count) adBound=\(adBound) "
                    + "platformSSO=\(platformSSO) kerberosConfig=\(kerberos) "
                    + "(metadata only - no secret material read)"
            )
        )

        for cred in existingCreds.prefix(25) {
            evidence.append(
                Evidence(
                    type: "cred_path",
                    path: cred.path,
                    detail: "kind=\(cred.kind) exists=true (path presence only)"
                )
            )
        }

        if let identity {
            evidence.append(
                Evidence(
                    type: "identity",
                    detail:
                        "adBound=\(identity.adBound.rootstockDescribe) "
                        + "platformSSO=\(identity.platformSSO.rootstockDescribe) "
                        + "kerberosConfigPresent=\(identity.kerberosConfigPresent.rootstockDescribe)"
                )
            )
            for path in identity.odConfigPaths.prefix(10) {
                evidence.append(Evidence(type: "od_path", path: path, detail: "OD/DirectoryService path"))
            }
            for path in identity.ssoPaths.prefix(10) {
                evidence.append(Evidence(type: "sso_path", path: path, detail: "Platform SSO / AppSSO path"))
            }
            for note in identity.notes.prefix(10) {
                evidence.append(Evidence(type: "note", detail: note))
            }
        }

        var techniques = Set<String>()
        if !existingCreds.isEmpty {
            techniques.formUnion(["T1552", "T1552.001", "T1003"])
        }
        if adBound || kerberos {
            techniques.formUnion(["T1087.002", "T1558", "T1078.002"])
        }
        if platformSSO {
            techniques.formUnion(["T1078", "T1550"])
        }
        if techniques.isEmpty {
            techniques.insert("T1078")
        }

        let severity: Severity
        let title: String
        if adBound && !existingCreds.isEmpty {
            severity = .medium
            title = "Auth pivot: credential paths + AD-bound identity surface"
        } else if platformSSO && !existingCreds.isEmpty {
            severity = .medium
            title = "Auth pivot: credential paths + Platform SSO identity"
        } else if adBound || platformSSO {
            severity = .low
            title =
                "Identity pivot: "
                + [adBound ? "AD-bound" : nil, platformSSO ? "Platform SSO" : nil]
                .compactMap { $0 }
                .joined(separator: " + ")
        } else {
            severity = .low
            title = "Credential path pivot surface (\(existingCreds.count) paths present)"
        }

        return [
            Finding(
                id: Self.id,
                title: title,
                severity: severity,
                confidence: .medium,
                category: .auth,
                evidence: evidence,
                attackTechniques: Array(techniques).sorted(),
                remediation: [
                    "Harden private key / cloud credential file permissions (never world-readable)",
                    "Prefer hardware-backed / SSO auth over long-lived key files where possible",
                    "Validate AD/Platform SSO join via MDM inventory; review Kerberos ticket lifetime policy",
                    "OPSEC: Rootstock Red assess never dumps secrets - path metadata only; avoid security dump-keychain",
                ],
                falsePositiveNotes:
                    "Path presence ≠ usable secret; AD path heuristics are not live bind proofs",
                dryRunSafe: true,
                opsecScore: 22,
                esfExpected: ["OPEN"]
            ),
        ]
    }

}
