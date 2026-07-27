import Foundation
import RootstockCore

/// Path-to-impact: missing or weak MDM/PPPC posture when the host still has attack surface.
///
/// Requires supporting remote-access, weak-protection, credential, or browser
/// path signals before reporting a finding.
public struct MDMManagementGapVector: Check {
    public static let id = "rootstock.vector.mdm.management_gap"
    public static let cost: CollectorCost = .low

    public init() {}

    public func evaluate(state: CollectedState, context: EvaluationContext) async throws -> [Finding] {
        guard let mdm = state.mdm else { return [] }

        let enrolled = mdm.enrolled
        let noVendors = mdm.vendorHints.isEmpty
        let noProfiles = (mdm.profileFileCount ?? 0) == 0 && mdm.managedPreferenceNames.isEmpty
        let noPPPC = mdm.pppcPolicyPresent != true
        let unmanaged =
            enrolled == false
            || (enrolled == nil && noVendors && noProfiles)
            || (noVendors && noPPPC && noProfiles)

        guard unmanaged else { return [] }

        // Require supporting path-to-impact so we do not rainbow-dump every home Mac.
        let remote =
            state.network?.remoteLoginSSH == true
            || state.network?.screenSharingARD == true
            || state.network?.fileSharingSMB == true
        let weakProt =
            state.protections?.sipEnabled == false
            || state.protections?.gatekeeperEnabled == false
        let highValue =
            state.credPaths.contains(where: \.exists)
            || state.browserMeta.contains(where: \.exists)
            || state.identity?.adBound == true
        let inject = state.injectabilityHits.contains { !$0.riskFlags.isEmpty }

        guard remote || weakProt || highValue || inject else { return [] }

        var evidence: [Evidence] = [
            Evidence(
                type: "mdm_summary",
                detail:
                    "enrolled=\(enrolled.rootstockDescribe) vendors=\(mdm.vendorHints.count) "
                    + "managedPrefs=\(mdm.managedPreferenceNames.count) "
                    + "profileFiles=\(Self.describeInt(mdm.profileFileCount)) "
                    + "pppcPolicyPresent=\(mdm.pppcPolicyPresent.rootstockDescribe)"
            ),
        ]
        for note in mdm.notes.prefix(12) {
            evidence.append(Evidence(type: "note", detail: note))
        }
        if remote {
            evidence.append(
                Evidence(
                    type: "supporting_remote",
                    detail: "remote access / sharing posture elevated without strong MDM signals"
                )
            )
        }
        if weakProt {
            evidence.append(
                Evidence(
                    type: "supporting_protections",
                    detail: "SIP/Gatekeeper weak while management gap present"
                )
            )
        }
        if highValue {
            evidence.append(
                Evidence(
                    type: "supporting_high_value",
                    detail: "cred/browser/identity high-value surface without PPPC/MDM hardening signal"
                )
            )
        }
        if inject {
            evidence.append(
                Evidence(
                    type: "supporting_inject",
                    detail: "injectability flags present on unmanaged-like host"
                )
            )
        }

        let severity: Severity
        let title: String
        if enrolled == false && (remote || weakProt) {
            severity = .medium
            title = "MDM management gap: not enrolled with elevated host attack surface"
        } else if noPPPC && highValue {
            severity = .medium
            title = "MDM/PPPC gap: no PPPC policy signal with high-value data surface"
        } else {
            severity = .low
            title = "MDM posture thin or absent with supporting path-to-impact signals"
        }

        return [
            Finding(
                id: Self.id,
                title: title,
                severity: severity,
                confidence: enrolled == false ? .medium : .low,
                category: .mdm,
                evidence: evidence,
                attackTechniques: ["T1082", "T1562", "T1078", "T1204"],
                remediation: [
                    "Enroll unmanaged high-value hosts into MDM/ABM where policy requires it",
                    "Deploy PPPC / TCC configuration-profile policy for approved tools only",
                    "Disable unnecessary Remote Login / Screen Sharing when not managed",
                    "OPSEC: path heuristics for MDM are quiet; do not run jamf recon storms from assess",
                ],
                falsePositiveNotes:
                    "Personal Macs legitimately lack MDM. Path/vendor heuristics miss some UEM products; "
                    + "confirm with profiles list / business inventory before treating as critical.",
                dryRunSafe: true,
                opsecScore: 14,
                esfExpected: ["OPEN"]
            ),
        ]
    }


    private static func describeInt(_ value: Int?) -> String {
        value.map(String.init) ?? "unknown"
    }
}
