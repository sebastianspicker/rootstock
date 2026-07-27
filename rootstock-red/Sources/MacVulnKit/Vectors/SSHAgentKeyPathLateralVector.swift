import Foundation
import RootstockCore

/// Path-to-impact: SSH-agent / key path lateral posture depth.
///
/// Research basis: SSH lateral checklists; agent socket and authorized_keys awareness.
/// Safety and behavior: path inventory only; never reads private keys or agent material.
public struct SSHAgentKeyPathLateralVector: Check {
    public static let id = "rootstock.vector.lateral.ssh_agent_key_path"
    public static let cost: CollectorCost = .low

    public init() {}

    public func evaluate(state: CollectedState, context: EvaluationContext) async throws -> [Finding] {
        let ssh = state.sshAgentKeyPath
        let agents = ssh?.agentSocketPaths.count ?? 0
        let keys = ssh?.keyPathHits.count ?? 0
        let support = ssh?.sshdSupportPaths.count ?? 0
        let surface = ssh?.lateralPathSurfacePresent == true || agents + keys + support > 0
        let note = state.collectorNotes["collect.ssh_agent_key_path"] != nil

        guard surface || note else { return [] }

        let remoteSSH = state.network?.remoteLoginSSH == true
        let hasPrivateKeyPath = ssh?.keyPathHits.contains {
            $0.contains("id_rsa") || $0.contains("id_ed25519") || $0.contains("id_ecdsa")
        } ?? false
        let hasAuthorizedKeys = ssh?.keyPathHits.contains { $0.contains("authorized_keys") } ?? false

        // Path-to-impact: agent/key/sshd surface with meaningful lateral depth
        guard agents >= 1 || keys >= 1 || support >= 1 else { return [] }

        var evidence: [Evidence] = [
            Evidence(
                type: "ssh_path_summary",
                detail:
                    "agents=\(agents) keyPaths=\(keys) sshdSupport=\(support) "
                    + "remoteSSH=\(remoteSSH) privateKeyPath=\(hasPrivateKeyPath) "
                    + "authorizedKeys=\(hasAuthorizedKeys)"
            ),
        ]
        if let ssh {
            for path in (ssh.agentSocketPaths + ssh.keyPathHits + ssh.sshdSupportPaths).prefix(12) {
                // Never attach key material - path string only
                evidence.append(Evidence(type: "ssh_path", path: path, detail: "SSH path presence (no key material)"))
            }
            for n in ssh.notes.prefix(6) {
                evidence.append(Evidence(type: "ssh_note", detail: n))
            }
        }
        evidence.append(
            Evidence(
                type: "honesty",
                detail:
                    "Assess never reads private keys, never connects to ssh-agent sockets, "
                    + "never extracts authorized_keys material or harvests credentials."
            )
        )

        let severity: Severity
        if remoteSSH && (hasPrivateKeyPath || hasAuthorizedKeys || agents >= 1) {
            severity = .medium
        } else if remoteSSH || hasPrivateKeyPath {
            severity = .low
        } else {
            severity = .info
        }

        return [
            Finding(
                id: Self.id,
                title: remoteSSH
                    ? "SSH-agent/key path lateral depth with remote login enabled"
                    : "SSH-agent / key path lateral posture surface",
                severity: severity,
                confidence: .medium,
                category: .auth,
                evidence: evidence,
                attackTechniques: ["T1021.004", "T1552.004", "T1078"],
                remediation: [
                    "Disable Remote Login (SSH) when not required; use jump hosts and short-lived keys",
                    "Use hardware-backed keys / Touch ID ssh-agent policies; avoid long-lived agent sockets",
                    "Audit authorized_keys on high-value hosts; prefer certificate-based SSH",
                    "OPSEC: Rootstock Red inventories key paths only - never dumps key material",
                ],
                falsePositiveNotes:
                    "OpenSSH tooling and ~/.ssh configs are common on developer hosts. "
                    + "Prioritize Remote Login enabled + private key path compounds.",
                dryRunSafe: true,
                opsecScore: 24,
                esfExpected: ["OPEN"]
            ),
        ]
    }
}
