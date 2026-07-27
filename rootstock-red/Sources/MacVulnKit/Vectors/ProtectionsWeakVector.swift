import Foundation
import RootstockCore

/// Path-to-impact: weakened SIP / Gatekeeper / FileVault, or unknown posture under elevated context.
public struct ProtectionsWeakVector: Check {
    public static let id = "rootstock.vector.privesc.protections_weak"
    public static let cost: CollectorCost = .low

    public init() {}

    public func evaluate(state: CollectedState, context: EvaluationContext) async throws -> [Finding] {
        let p = state.protections
        let sip = p?.sipEnabled
        let gk = p?.gatekeeperEnabled
        let fv = p?.fileVaultOn

        let knownDisabled: [(name: String, technique: String)] = [
            ("SIP", "T1562.001"),
            ("Gatekeeper", "T1553.001"),
            ("FileVault", "T1552"),
        ].compactMap { name, tech in
            let flag: Bool?
            switch name {
            case "SIP": flag = sip
            case "Gatekeeper": flag = gk
            case "FileVault": flag = fv
            default: flag = nil
            }
            return flag == false ? (name, tech) : nil
        }

        let allUnknown = sip == nil && gk == nil && fv == nil
        let isRoot = state.host?.isRoot == true
        let otherMisconfig =
            isRoot
            || state.injectabilityHits.contains { !$0.riskFlags.isEmpty }
            || !state.dylibRiskHits.filter { !$0.weakDylibs.isEmpty }.isEmpty
            || state.network?.remoteLoginSSH == true
            || state.network?.screenSharingARD == true

        // Only emit when weak, or unknown+supporting misconfig path-to-impact.
        guard !knownDisabled.isEmpty || (allUnknown && otherMisconfig) || (p == nil && otherMisconfig) else {
            return []
        }

        var evidence: [Evidence] = []
        if let notes = p?.notes {
            evidence.append(contentsOf: notes.prefix(10).map { Evidence(type: "note", detail: $0) })
        }
        evidence.append(Evidence(type: "sip", detail: "sipEnabled=\(sip.rootstockDescribe)"))
        evidence.append(Evidence(type: "gatekeeper", detail: "gatekeeperEnabled=\(gk.rootstockDescribe)"))
        evidence.append(Evidence(type: "filevault", detail: "fileVaultOn=\(fv.rootstockDescribe)"))
        if isRoot {
            evidence.append(
                Evidence(type: "context", detail: "process isRoot=true - elevated assess context")
            )
        }
        if otherMisconfig && knownDisabled.isEmpty {
            evidence.append(
                Evidence(
                    type: "path_to_impact",
                    detail:
                        "Protections unknown/uncollected while other misconfig signals exist "
                        + "(inject surface, weak dylibs, remote access, or root context)"
                )
            )
        }

        let severity: Severity
        let confidence: Confidence
        let title: String
        var techniques = Set(["T1082", "T1562.001"])

        if knownDisabled.contains(where: { $0.name == "SIP" }) {
            severity = .high
            confidence = .medium
            title = "Privilege-escalation surface: SIP disabled (high impact)"
            techniques.insert("T1548")
        } else if !knownDisabled.isEmpty {
            severity = .medium
            confidence = .medium
            let names = knownDisabled.map(\.name).joined(separator: ", ")
            title = "Protections weak: \(names) disabled"
            for item in knownDisabled {
                techniques.insert(item.technique)
            }
        } else {
            severity = .low
            confidence = .low
            title = "Protections posture unknown with supporting path-to-impact signals"
        }

        return [
            Finding(
                id: Self.id,
                title: title,
                severity: severity,
                confidence: confidence,
                category: .misconfig,
                evidence: evidence,
                attackTechniques: Array(techniques).sorted(),
                remediation: [
                    "Re-enable SIP (csrutil), Gatekeeper (spctl), and FileVault via MDM/compliance",
                    "Treat disabled SIP as high-priority host integrity failure",
                    "OPSEC: assessing protections via csrutil/spctl may itself be logged - prefer MDM inventory",
                ],
                falsePositiveNotes: knownDisabled.isEmpty
                    ? "Unknown is not proof of disabled protections; corroborate with admin tooling"
                    : "Verify disabled flags with privileged host tooling before remediating",
                dryRunSafe: true,
                opsecScore: 18,
                esfExpected: ["OPEN"]
            ),
        ]
    }

}
