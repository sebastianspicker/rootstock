import Foundation
import RootstockCore

/// Path-to-impact: browser session/cookie/login DB metadata as a credential pivot surface.
///
/// Reads only path presence, size, and modification time. It never reads
/// database row contents.
public struct BrowserSessionArtifactPivotVector: Check {
    public static let id = "rootstock.vector.browser.session_artifact_pivot"
    public static let cost: CollectorCost = .low

    /// High-value artifact kinds (session / auth adjacent).
    private static let highValueKinds: Set<String> = [
        "cookies", "cookie", "login_data", "logins", "web_data",
        "keychain", "session", "sessions", "preferences",
    ]

    public init() {}

    public func evaluate(state: CollectedState, context: EvaluationContext) async throws -> [Finding] {
        let present = state.browserMeta.filter(\.exists)
        guard !present.isEmpty else { return [] }

        let highValue = present.filter { entry in
            let kind = entry.kind.lowercased()
            return Self.highValueKinds.contains(where: { kind.contains($0) })
                || kind.contains("cookie")
                || kind.contains("login")
        }

        // Prefer high-value kinds; fall back to any present browser DBs with size signal.
        let focus = highValue.isEmpty ? present : highValue
        guard !focus.isEmpty else { return [] }

        var evidence: [Evidence] = [
            Evidence(
                type: "summary",
                detail:
                    "browserMetaPresent=\(present.count) highValueKinds=\(highValue.count) "
                    + "(metadata only - no cookie/password row contents)"
            ),
        ]

        for entry in focus.prefix(30) {
            var detail = "browser=\(entry.browser) kind=\(entry.kind)"
            if let size = entry.sizeBytes {
                detail += " sizeBytes=\(size)"
            }
            if let modified = entry.modifiedAt {
                detail += " mtime=\(ISO8601DateFormatter().string(from: modified))"
            }
            evidence.append(
                Evidence(type: "browser_artifact", path: entry.path, detail: detail)
            )
        }

        // Compound with FDA / cred paths for stronger pivot narrative.
        if state.tcc?.fullDiskAccessLikely == true {
            evidence.append(
                Evidence(
                    type: "compound_fda",
                    detail: "FDA likely - browser DB paths may be readable beyond sandbox defaults"
                )
            )
        }
        let sshOrCloud = state.credPaths.filter {
            $0.exists && ($0.kind == "ssh" || $0.kind == "aws" || $0.kind == "gcp" || $0.kind == "azure")
        }
        if !sshOrCloud.isEmpty {
            evidence.append(
                Evidence(
                    type: "compound_creds",
                    detail: "cloud/ssh cred paths also present (\(sshOrCloud.count)) - multi-artifact pivot"
                )
            )
        }

        let severity: Severity
        let title: String
        if !highValue.isEmpty && state.tcc?.fullDiskAccessLikely == true {
            severity = .medium
            title =
                "Browser session pivot: high-value DBs present with FDA-likely context "
                + "(\(highValue.count))"
        } else if !highValue.isEmpty {
            severity = .medium
            title = "Browser session artifact pivot surface (\(highValue.count) high-value DBs)"
        } else {
            severity = .low
            title = "Browser profile artifact surface (\(present.count) paths present)"
        }

        return [
            Finding(
                id: Self.id,
                title: title,
                severity: severity,
                confidence: .high,
                category: .auth,
                evidence: evidence,
                attackTechniques: ["T1539", "T1555.003", "T1005", "T1083"],
                remediation: [
                    "Lock browser profiles; prefer OS keychain-backed passwords with device auth",
                    "Clear stale session cookies on shared or high-risk hosts",
                    "Do not grant FDA to untrusted tools that can read browser DB paths",
                    "OPSEC: Rootstock Red assess never dumps cookies/passwords - path metadata only",
                ],
                falsePositiveNotes:
                    "Browser cookie/login DB files exist on nearly all user hosts; finding is path-to-impact "
                    + "surface, not proof of theft. App-Bound / sandboxing may still block access without FDA.",
                dryRunSafe: true,
                opsecScore: 24,
                tccDomains: state.tcc?.fullDiskAccessLikely == true ? ["FullDiskAccess"] : [],
                esfExpected: ["OPEN"]
            ),
        ]
    }
}
