import Foundation
import RootstockCore

/// Path-to-impact: user-writable mobileconfig / configuration profile sideload risk.
///
/// Research basis: MDM profile delivery tradecraft; user-download profile install research.
/// Safety and behavior: typed ConfigProfileSideloadState × unmanaged MDM compound; never installs profiles.
public struct MobileconfigSideloadRiskVector: Check {
    public static let id = "rootstock.vector.profile.mobileconfig_sideload"
    public static let cost: CollectorCost = .low

    public init() {}

    public func evaluate(state: CollectedState, context: EvaluationContext) async throws -> [Finding] {
        let cfg = state.configProfileSideload
        let userProfiles = cfg?.userMobileconfigPaths.count ?? 0
        let downloads = cfg?.downloadsProfileHints.count ?? 0
        let installDb = cfg?.profileInstallDbPresent
        let note =
            state.collectorNotes["collect.config_profile_sideload"] != nil
            || state.collectorNotes["profile.sideload"] != nil

        let hasUserProfiles = userProfiles > 0 || downloads > 0
        let unmanaged = state.mdm?.enrolled == false || state.mdm?.enrolled == nil
        let weakStore =
            state.mdm?.profileStoreReadable == false
            || (state.mdm?.profileFileCount ?? 0) == 0

        // Fire when user-side profiles observed, install-db + unmanaged, or fixture notes.
        let fire =
            hasUserProfiles
            || state.collectorNotes["profile.sideload"] != nil
            || (installDb == true && (unmanaged || weakStore))
            || (note && unmanaged && (installDb == true || weakStore || hasUserProfiles))
            || (installDb == true && unmanaged)
        guard fire else { return [] }

        var evidence: [Evidence] = [
            Evidence(
                type: "profile_summary",
                detail:
                    "userMobileconfigs=\(userProfiles) downloadsHints=\(downloads) "
                    + "profileInstallDb=\(installDb.rootstockDescribe) "
                    + "mdmEnrolled=\((state.mdm?.enrolled).rootstockDescribe)"
            ),
        ]
        if let cfg {
            for path in (cfg.userMobileconfigPaths + cfg.downloadsProfileHints).prefix(10) {
                evidence.append(
                    Evidence(type: "mobileconfig_path", path: path, detail: "user-space profile path")
                )
            }
            for n in cfg.notes.prefix(8) {
                evidence.append(Evidence(type: "profile_note", detail: n))
            }
        }
        if unmanaged {
            evidence.append(Evidence(type: "compound_mdm", detail: "host appears unmanaged or enrollment unknown"))
        }
        evidence.append(
            Evidence(
                type: "honesty",
                detail:
                    "Assess lists paths only - never parses payload secrets or installs profiles. "
                    + "User-owned .mobileconfig files are not proof of malicious install."
            )
        )

        let severity: Severity = (hasUserProfiles && unmanaged) ? .medium : .low

        return [
            Finding(
                id: Self.id,
                title: hasUserProfiles && unmanaged
                    ? "User-space mobileconfig present on unmanaged (or enrollment-unknown) host"
                    : "Configuration profile / mobileconfig sideload surface",
                severity: severity,
                confidence: .low,
                category: .mdm,
                evidence: evidence,
                attackTechniques: ["T1566.001", "T1556", "T1195"],
                remediation: [
                    "Block unsolicited configuration profile installs via MDM / user education",
                    "Remove leftover .mobileconfig files from Downloads/Desktop on managed fleets",
                    "Require supervised enrollment before accepting high-privilege PPPC payloads",
                    "OPSEC: Rootstock Red never installs system configuration profiles",
                ],
                falsePositiveNotes:
                    "IT may leave legitimate profiles in Downloads; confirm before incident response.",
                dryRunSafe: true,
                opsecScore: 16,
                esfExpected: ["OPEN", "WRITE"]
            ),
        ]
    }

}
