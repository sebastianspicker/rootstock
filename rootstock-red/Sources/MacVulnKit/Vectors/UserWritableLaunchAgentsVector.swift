import Foundation
import RootstockCore

/// Persistence opportunity: user LaunchAgents directory is writable and agents already exist.
///
/// Honest about modern BTM user notification - not a silent implant claim.
public struct UserWritableLaunchAgentsVector: Check {
    public static let id = "rootstock.vector.persist.user_writable_launchagents"
    public static let cost: CollectorCost = .low

    public init() {}

    public func evaluate(state: CollectedState, context: EvaluationContext) async throws -> [Finding] {
        let agents = state.launchAgents
        guard !agents.isEmpty else { return [] }

        let dirURL = Self.userLaunchAgentsDirectory(from: agents)
        let writable = FileManager.default.isWritableFile(atPath: dirURL.path)
        // User LaunchAgents under home are typically user-writable even if isWritableFile is flaky.
        let likelyWritable =
            writable
            || dirURL.path.contains("/Users/")
            || dirURL.path.hasPrefix(FileManager.default.homeDirectoryForCurrentUser.path)

        guard likelyWritable else { return [] }

        var evidence: [Evidence] = [
            Evidence(
                type: "launchagents_dir",
                path: dirURL.path,
                detail: "writable=\(writable) likelyWritable=\(likelyWritable) agents=\(agents.count)"
            ),
        ]
        for agent in agents.prefix(20) {
            evidence.append(
                Evidence(
                    type: "launchagent",
                    path: agent.path,
                    detail: agent.label ?? "unlabeled"
                )
            )
        }
        if let btm = state.loginItems {
            evidence.append(
                Evidence(
                    type: "btm",
                    path: btm.btmDirectoryPath,
                    detail: "btmStorePresent=\(btm.btmStorePresent) - modern macOS may notify user of new background items"
                )
            )
        } else if state.btmStorePresent != nil {
            evidence.append(
                Evidence(
                    type: "btm",
                    detail: "btmStorePresent=\(state.btmStorePresent ?? false) - BTM may surface new agents to the user"
                )
            )
        } else {
            evidence.append(
                Evidence(
                    type: "btm_honesty",
                    detail:
                        "On modern macOS (Ventura+), Background Task Management may notify the user "
                        + "when new LaunchAgents/login items register - silent persistence is not guaranteed"
                )
            )
        }

        return [
            Finding(
                id: Self.id,
                title: "Persistence vector: user LaunchAgents writable (\(agents.count) agents)",
                severity: .medium,
                confidence: .high,
                category: .persist,
                evidence: evidence,
                attackTechniques: ["T1543.001", "T1547.015"],
                remediation: [
                    "Review unexpected LaunchAgents under ~/Library/LaunchAgents",
                    "Monitor LaunchAgents writes via ESF (OPEN/WRITE/CREATE) and BTM registration",
                    "OPSEC: claiming silent LaunchAgent install is false on modern macOS - BTM/user prompts raise detection risk (high OPSEC cost)",
                    "Prefer signed, user-visible apps over ad-hoc agent drops in authorized labs only",
                ],
                falsePositiveNotes:
                    "User-writable LaunchAgents is normal; vector requires malicious or unexpected agent content",
                dryRunSafe: true,
                // High: silent claim is false; registration is user-visible / BTM-notified on modern macOS.
                opsecScore: 72,
                tccDomains: [],
                esfExpected: ["OPEN", "WRITE", "CREATE", "USER_PROMPT"]
            ),
        ]
    }

    private static func userLaunchAgentsDirectory(from agents: [LaunchAgentEntry]) -> URL {
        if let first = agents.first {
            return URL(fileURLWithPath: first.path).deletingLastPathComponent()
        }
        return FileManager.default.homeDirectoryForCurrentUser
            .appendingPathComponent("Library/LaunchAgents", isDirectory: true)
    }
}
