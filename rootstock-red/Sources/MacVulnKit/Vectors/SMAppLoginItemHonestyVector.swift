import Foundation
import RootstockCore

/// Path-to-impact: modern login-item / SMAppService / BTM honesty for persistence validation.
///
/// Research basis: PersistentJXA login-item techniques; Apple SMAppService era persistence.
/// Safety and behavior: never claims silent persistence - BTM/user-visible registration is first-class OPSEC;
/// distinct from user LaunchAgents vector by focusing on BTM store + login-item paths.
public struct SMAppLoginItemHonestyVector: Check {
    public static let id = "rootstock.vector.persist.smapp_loginitem_honesty"
    public static let cost: CollectorCost = .low

    public init() {}

    public func evaluate(state: CollectedState, context: EvaluationContext) async throws -> [Finding] {
        let login = state.loginItems
        let btmPresent = login?.btmStorePresent == true || state.btmStorePresent == true
        let loginPaths = !state.loginItemPaths.isEmpty
            ? state.loginItemPaths
            : (login?.loginItemPaths ?? [])
        let legacyPaths = loginPaths.filter {
            $0.localizedCaseInsensitiveContains("loginitem")
                || $0.localizedCaseInsensitiveContains("backgrounditems")
                || $0.localizedCaseInsensitiveContains("ServiceManagement")
                || $0.localizedCaseInsensitiveContains("LoginItems")
        }

        guard btmPresent || !loginPaths.isEmpty || login != nil else { return [] }

        // Path-to-impact: BTM/login surface exists with user agents or high OPSEC cost honesty finding.
        let userAgents = state.launchAgents
        let hasAgents = !userAgents.isEmpty
        let surface =
            btmPresent
            || !legacyPaths.isEmpty
            || (hasAgents && login != nil)
        guard surface else { return [] }

        var evidence: [Evidence] = [
            Evidence(
                type: "btm",
                detail: "btmStorePresent=\(btmPresent) loginItemPaths=\(loginPaths.count)"
            ),
        ]
        if let dir = login?.btmDirectoryPath {
            let size = login?.btmDirectorySizeBytes.map(String.init) ?? "unknown"
            evidence.append(Evidence(type: "btm_dir", path: dir, detail: "sizeBytes=\(size)"))
        }
        if let bg = login?.backgroundItemsBtmPath {
            evidence.append(Evidence(type: "backgrounditems", path: bg, detail: "BackgroundItems path present"))
        }
        for path in loginPaths.prefix(20) {
            evidence.append(Evidence(type: "login_item_path", path: path, detail: "path present"))
        }
        for note in (login?.notes ?? []).prefix(10) {
            evidence.append(Evidence(type: "note", detail: note))
        }
        if hasAgents {
            evidence.append(
                Evidence(
                    type: "compound_launchagents",
                    detail: "userLaunchAgents=\(userAgents.count) - new agents may surface in Login Items UI"
                )
            )
        }
        evidence.append(
            Evidence(
                type: "smapp_honesty",
                detail:
                    "SMAppService / Login Items on Ventura+ are user-visible via BTM; "
                    + "silent persistence claims are false on modern macOS"
            )
        )

        let severity: Severity = hasAgents && btmPresent ? .medium : .low
        let title: String
        if btmPresent && hasAgents {
            title = "Login-item / SMAppService honesty: BTM present with user LaunchAgents (\(userAgents.count))"
        } else if btmPresent {
            title = "Login-item / SMAppService honesty: BTM store evidence present"
        } else {
            title = "Login-item path surface without confirmed BTM store (\(loginPaths.count) paths)"
        }

        return [
            Finding(
                id: Self.id,
                title: title,
                severity: severity,
                confidence: btmPresent ? .high : .low,
                category: .persist,
                evidence: evidence,
                attackTechniques: ["T1547.015", "T1543.001", "T1547"],
                remediation: [
                    "Review System Settings → General → Login Items & Extensions for unexpected items",
                    "Prefer SMAppService-registered apps over ad-hoc LaunchAgent drops in authorized labs",
                    "OPSEC: treat login-item registration as high user-visibility / high OPSEC cost",
                    "Do not claim silent persistence on modern macOS - BTM may notify the user",
                ],
                falsePositiveNotes:
                    "BTM store presence is normal after apps register background tasks. "
                    + "Opaque BTM format is not fully decoded - path/size evidence only.",
                dryRunSafe: true,
                // High: silent claim is false; UI-visible registration.
                opsecScore: 70,
                esfExpected: ["OPEN", "USER_PROMPT"],
                osRange: ">=13.0"
            ),
        ]
    }
}
