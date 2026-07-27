import Foundation
import RootstockCore

/// Lateral / remote access vector from SSH / Screen Sharing posture (path + enable heuristics).
public struct RemoteAccessSurfaceVector: Check {
    public static let id = "rootstock.vector.network.remote_access_surface"
    public static let cost: CollectorCost = .low

    public init() {}

    public func evaluate(state: CollectedState, context: EvaluationContext) async throws -> [Finding] {
        guard let net = state.network else { return [] }

        let sshLikely = net.remoteLoginSSH == true
        let ardLikely = net.screenSharingARD == true
        let sshPlist = net.remoteLoginPlistPresent == true
        let ardPlist = net.screenSharingPlistPresent == true
        let sshdConfig = net.sshdConfigPresent == true
        let remoteMgmt = net.remoteManagementPrefsPresent == true

        let surface =
            sshLikely || ardLikely || sshPlist || ardPlist || sshdConfig || remoteMgmt
        guard surface else { return [] }

        var evidence: [Evidence] = net.notes.prefix(15).map { Evidence(type: "note", detail: $0) }
        evidence.append(
            Evidence(
                type: "ssh",
                detail:
                    "remoteLoginSSH=\(net.remoteLoginSSH.rootstockDescribe) "
                    + "plistPresent=\(net.remoteLoginPlistPresent.rootstockDescribe) "
                    + "sshdConfigPresent=\(net.sshdConfigPresent.rootstockDescribe)"
            )
        )
        evidence.append(
            Evidence(
                type: "screen_sharing",
                detail:
                    "screenSharingARD=\(net.screenSharingARD.rootstockDescribe) "
                    + "plistPresent=\(net.screenSharingPlistPresent.rootstockDescribe) "
                    + "remoteMgmtPrefs=\(net.remoteManagementPrefsPresent.rootstockDescribe)"
            )
        )
        if net.fileSharingSMB == true || net.fileSharingPlistPresent == true {
            evidence.append(
                Evidence(
                    type: "smb",
                    detail:
                        "fileSharingSMB=\(net.fileSharingSMB.rootstockDescribe) "
                        + "plistPresent=\(net.fileSharingPlistPresent.rootstockDescribe)"
                )
            )
        }

        let enabled: [String] = [
            sshLikely ? "SSH/Remote Login" : nil,
            ardLikely ? "Screen Sharing/ARD" : nil,
            net.fileSharingSMB == true ? "SMB File Sharing" : nil,
        ].compactMap { $0 }

        let presentOnly: [String] = [
            (!sshLikely && (sshPlist || sshdConfig)) ? "ssh components" : nil,
            (!ardLikely && (ardPlist || remoteMgmt)) ? "ARD/screen sharing components" : nil,
        ].compactMap { $0 }

        let severity: Severity
        let confidence: Confidence
        let title: String
        if !enabled.isEmpty {
            severity = .medium
            confidence = .medium
            title = "Remote access vector: \(enabled.joined(separator: ", ")) indicated enabled"
        } else {
            severity = .low
            confidence = .low
            title =
                "Remote access surface present (\(presentOnly.joined(separator: ", "))) - enablement uncertain"
        }

        return [
            Finding(
                id: Self.id,
                title: title,
                severity: severity,
                confidence: confidence,
                category: .network,
                evidence: evidence,
                attackTechniques: ["T1021.004", "T1021.001", "T1021.002", "T1133"],
                remediation: [
                    "Disable unused Remote Login, Screen Sharing, and Remote Management",
                    "Require strong auth (keys/certificates) and network controls if SSH must stay on",
                    "Prefer MDM-enforced sharing posture; segment management networks",
                    "OPSEC: path heuristics are quiet; port scanning would be noisier and is out of scope",
                ],
                falsePositiveNotes:
                    "LaunchDaemon plists / sshd_config often exist when services are disabled",
                dryRunSafe: true,
                opsecScore: 16,
                esfExpected: ["OPEN", "CONNECT"]
            ),
        ]
    }

}
