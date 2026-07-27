import Foundation
import RootstockCore

/// SSH-agent / key path lateral posture depth (Wave-8).
///
/// Research basis: SSH lateral checklists; agent socket and authorized_keys path awareness.
/// Safety and behavior: typed `SSHAgentKeyPathState`; paths only - never reads key material.
public struct SSHAgentKeyPathCollector: Collector {
    public static let id = "collect.ssh_agent_key_path"
    public static let cost: CollectorCost = .low

    public init() {}

    public func collect(context: EvaluationContext) async throws -> CollectedState {
        let fm = FileManager.default
        let home = NSHomeDirectory()
        var notes: [String] = [
            "SSH agent/key path surface: path presence only - never reads private keys or agent material",
        ]

        var agentSockets: [String] = []
        var keyPaths: [String] = []
        var sshdSupport: [String] = []

        // Agent socket from environment (path string only - do not connect)
        if let sock = ProcessInfo.processInfo.environment["SSH_AUTH_SOCK"], !sock.isEmpty {
            agentSockets.append(sock)
            notes.append("SSH_AUTH_SOCK path observed (not connected): \(sock)")
            if fm.fileExists(atPath: sock) {
                notes.append("agent_socket_exists: \(sock)")
            }
        }

        let agentCandidates = [
            home + "/.ssh/agent.sock",
            "/private/tmp/com.apple.launchd." ,
            "/var/run/ssh-agent.sock",
            home + "/Library/Containers/com.openssh.ssh-agent",
            "/System/Library/LaunchAgents/com.openssh.ssh-agent.plist",
            "/System/Library/LaunchDaemons/ssh.plist",
            "/usr/bin/ssh-agent",
            "/usr/bin/ssh-add",
        ]
        for path in agentCandidates {
            if path.hasSuffix("com.apple.launchd.") {
                // Prefix only - do not enumerate /private/tmp broadly; note class
                notes.append("agent_class_hint: launchd tmp socket class (not enumerated)")
                continue
            }
            if fm.fileExists(atPath: path) {
                agentSockets.append(path)
                notes.append("agent_or_tool: \(path)")
            }
        }

        let keyCandidates = [
            home + "/.ssh/authorized_keys",
            home + "/.ssh/authorized_keys2",
            home + "/.ssh/known_hosts",
            home + "/.ssh/config",
            home + "/.ssh/id_rsa",
            home + "/.ssh/id_ed25519",
            home + "/.ssh/id_ecdsa",
            home + "/.ssh/id_dsa",
            "/etc/ssh/sshd_config",
            "/etc/ssh/ssh_config",
            "/private/etc/ssh/sshd_config",
        ]
        for path in keyCandidates where fm.fileExists(atPath: path) {
            // Record path only - never open private key files for content
            keyPaths.append(path)
            let isPrivate = path.contains("id_rsa") || path.contains("id_ed25519")
                || path.contains("id_ecdsa") || path.contains("id_dsa")
            notes.append(isPrivate ? "private_key_path_present: \(path)" : "ssh_path: \(path)")
        }

        // List additional public keys (*.pub) under ~/.ssh without reading material
        let sshDir = home + "/.ssh"
        if fm.fileExists(atPath: sshDir),
           let entries = try? fm.contentsOfDirectory(atPath: sshDir)
        {
            for entry in entries.prefix(40) {
                if entry.hasSuffix(".pub") {
                    let full = (sshDir as NSString).appendingPathComponent(entry)
                    keyPaths.append(full)
                    notes.append("public_key_path: \(full)")
                }
            }
        }

        let sshdCandidates = [
            "/usr/sbin/sshd",
            "/usr/bin/ssh",
            "/usr/libexec/sshd-keygen-wrapper",
            "/System/Library/LaunchDaemons/ssh.plist",
            "/etc/ssh",
            "/private/etc/ssh",
        ]
        for path in sshdCandidates where fm.fileExists(atPath: path) {
            sshdSupport.append(path)
            notes.append("sshd_support: \(path)")
        }

        agentSockets = Array(Set(agentSockets)).sorted()
        keyPaths = Array(Set(keyPaths)).sorted()
        sshdSupport = Array(Set(sshdSupport)).sorted()

        let surface = !agentSockets.isEmpty || !keyPaths.isEmpty || !sshdSupport.isEmpty

        var state = CollectedState()
        state.sshAgentKeyPath = SSHAgentKeyPathState(
            agentSocketPaths: agentSockets,
            keyPathHits: keyPaths,
            sshdSupportPaths: sshdSupport,
            lateralPathSurfacePresent: surface,
            notes: notes
        )
        state.collectorNotes[Self.id] =
            "agent=\(agentSockets.count) keys=\(keyPaths.count) "
            + "sshd=\(sshdSupport.count) surface=\(surface)"
        return state
    }
}
