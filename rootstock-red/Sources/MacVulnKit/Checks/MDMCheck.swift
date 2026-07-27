/// Cluster/check: MDMCheck - multi-signal posture ranking for assess pipeline.
import Foundation
import RootstockCore

public struct MDMHintsCheck: Check {
    public static let id = "rootstock.check.mdm.vendor_hints"
    public static let cost: CollectorCost = .low

    public init() {}

    public func evaluate(state: CollectedState, context: EvaluationContext) async throws -> [Finding] {
        guard let mdm = state.mdm else { return [] }
        if mdm.vendorHints.isEmpty {
            return [
                Finding(
                    id: "\(Self.id).none",
                    title: "No common MDM vendor paths detected",
                    severity: .low,
                    confidence: .low,
                    category: .mdm,
                    evidence: mdm.notes.prefix(15).map { Evidence(type: "note", detail: $0) },
                    attackTechniques: ["T1082"],
                    remediation: ["Confirm management state via profiles / ABM inventory"],
                    dryRunSafe: true,
                    opsecScore: 5
                ),
            ]
        }
        return [
            Finding(
                id: Self.id,
                title: "MDM / management vendor hints: \(mdm.vendorHints.joined(separator: ", "))",
                severity: .info,
                confidence: .medium,
                category: .mdm,
                evidence: mdm.vendorHints.map { Evidence(type: "vendor", detail: $0) }
                    + mdm.notes.prefix(10).map { Evidence(type: "note", detail: $0) },
                attackTechniques: ["T1082"],
                remediation: ["Correlate vendor agents with configuration profiles and PPPC payloads"],
                dryRunSafe: true,
                opsecScore: 8
            ),
        ]
    }
}

/// Managed preferences + profile-store posture (complements vendor path hints).
public struct MDMProfilesCheck: Check {
    public static let id = "rootstock.check.mdm.profiles"
    public static let cost: CollectorCost = .low

    public init() {}

    public func evaluate(state: CollectedState, context: EvaluationContext) async throws -> [Finding] {
        guard let mdm = state.mdm else { return [] }

        var evidence: [Evidence] = []
        evidence.append(
            Evidence(
                type: "mdm",
                detail:
                    "enrolled=\(mdm.enrolled.rootstockDescribe) "
                    + "profileStoreReadable=\(mdm.profileStoreReadable.rootstockDescribe) "
                    + "profileFileCount=\(mdm.profileFileCount.map(String.init) ?? "unknown") "
                    + "pppcPolicyPresent=\(mdm.pppcPolicyPresent.rootstockDescribe)"
            )
        )
        for name in mdm.managedPreferenceNames.prefix(40) {
            evidence.append(
                Evidence(
                    type: "managed_pref",
                    path: "/Library/Managed Preferences/\(name)",
                    detail: name
                )
            )
        }
        for note in mdm.notes.prefix(20) {
            evidence.append(Evidence(type: "note", detail: note))
        }

        let hasProfiles =
            (mdm.profileFileCount ?? 0) > 0
            || !mdm.managedPreferenceNames.isEmpty
            || mdm.pppcPolicyPresent == true
            || mdm.enrolled == true

        let title: String
        let severity: Severity
        if mdm.pppcPolicyPresent == true {
            severity = .info
            title = "MDM profiles / PPPC policy payloads present"
        } else if hasProfiles {
            severity = .info
            title =
                "MDM profile store / managed preferences inventory "
                + "(\(mdm.managedPreferenceNames.count) managed prefs"
                + (mdm.profileFileCount.map { ", ~\($0) profile files" } ?? "")
                + ")"
        } else {
            severity = .low
            title = "No managed preferences or profile-store files visible"
        }

        return [
            Finding(
                id: Self.id,
                title: title,
                severity: severity,
                confidence: mdm.profileStoreReadable == true || !mdm.managedPreferenceNames.isEmpty
                    ? .medium : .low,
                category: .mdm,
                evidence: evidence,
                attackTechniques: ["T1082", "T1562"],
                remediation: [
                    "Inventory configuration profiles via MDM console / ABM",
                    "Review PPPC payloads for over-broad TCC grants",
                ],
                falsePositiveNotes:
                    "Profile store may be unreadable without root; managed prefs can exist without full MDM enrollment",
                dryRunSafe: true,
                opsecScore: 7,
                esfExpected: []
            ),
        ]
    }

}
