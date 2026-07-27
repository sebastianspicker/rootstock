import Foundation
import RootstockCore

/// Path-to-impact: keychain database path presence (login / system / metadata).
///
/// Research basis: PEASS keychain path checks; public macOS credential-store recon themes.
/// Safety and behavior: existence metadata only - never reads keychain contents or runs
/// `security dump-keychain`. OPSEC honesty: assess never dumps secrets.
public struct KeychainPathSurfaceVector: Check {
    public static let id = "rootstock.vector.auth.keychain_path_surface"
    public static let cost: CollectorCost = .low

    public init() {}

    public func evaluate(state: CollectedState, context: EvaluationContext) async throws -> [Finding] {
        let fm = FileManager.default
        let home = fm.homeDirectoryForCurrentUser.path

        let candidates: [(kind: String, path: String)] = [
            ("login_keychain_db", "\(home)/Library/Keychains/login.keychain-db"),
            ("login_keychain_legacy", "\(home)/Library/Keychains/login.keychain"),
            ("metadata_keychain_db", "\(home)/Library/Keychains/metadata.keychain-db"),
            ("system_keychain", "/Library/Keychains/System.keychain"),
            ("filevault_master", "/Library/Keychains/FileVaultMaster.keychain"),
            ("user_keychains_dir", "\(home)/Library/Keychains"),
            ("system_keychains_dir", "/Library/Keychains"),
        ]

        var present: [(kind: String, path: String)] = []
        for item in candidates {
            if fm.fileExists(atPath: item.path) {
                present.append(item)
            }
        }

        // Collector force for tests / deeper collectors (pipe-separated paths).
        var forcedPaths: [String] = []
        if let note = state.collectorNotes["auth.keychain_paths"] {
            for part in note.split(separator: "|") {
                let p = String(part).trimmingCharacters(in: .whitespaces)
                guard !p.isEmpty else { continue }
                forcedPaths.append(p)
                if !present.contains(where: { $0.path == p }) {
                    present.append((kind: "collector_note", path: p))
                }
            }
        }

        let forced = state.collectorNotes["auth.keychain_paths"] != nil
        guard !present.isEmpty || forced else { return [] }

        // High-value DB files (not just the directory shell).
        let dbHits = present.filter {
            $0.path.hasSuffix(".keychain-db")
                || $0.path.hasSuffix(".keychain")
                || $0.kind == "collector_note"
        }

        var evidence: [Evidence] = [
            Evidence(
                type: "summary",
                detail:
                    "keychainPathsPresent=\(present.count) dbLike=\(dbHits.count) forced=\(forced) "
                    + "(path presence only - no secret material, no dump-keychain)"
            ),
        ]
        for item in present.prefix(20) {
            evidence.append(
                Evidence(
                    type: "keychain_path",
                    path: item.path,
                    detail: "kind=\(item.kind) exists=true (metadata only)"
                )
            )
        }
        if !forcedPaths.isEmpty {
            evidence.append(
                Evidence(
                    type: "collector_note",
                    detail: "auth.keychain_paths=\(forcedPaths.prefix(10).joined(separator: "|"))"
                )
            )
        }
        evidence.append(
            Evidence(
                type: "opsec_honesty",
                detail:
                    "Rootstock Red assess never dumps keychain secrets, never runs "
                    + "`security dump-keychain` / find-generic-password extraction in this vector"
            )
        )

        // Compound with other auth pivots for ranking (not required to fire).
        let credCompound = state.credPaths.contains(where: \.exists)
        if credCompound {
            evidence.append(
                Evidence(
                    type: "auth_compound",
                    detail:
                        "cred path surface also present - keychain + file-cred dual store "
                        + "(still metadata-only)"
                )
            )
        }

        let severity: Severity
        let title: String
        if !dbHits.isEmpty && credCompound {
            severity = .medium
            title = "Keychain path surface: DB files + credential-path pivot (\(dbHits.count))"
        } else if !dbHits.isEmpty {
            severity = .low
            title = "Keychain path surface: login/system keychain DB paths present (\(dbHits.count))"
        } else {
            severity = .low
            title = "Keychain directory surface present (path inventory only)"
        }

        return [
            Finding(
                id: Self.id,
                title: title,
                severity: severity,
                confidence: dbHits.isEmpty ? .low : .medium,
                category: .auth,
                evidence: evidence,
                attackTechniques: ["T1555.001", "T1555", "T1003"],
                remediation: [
                    "Protect user sessions; require device unlock for keychain access where policy allows",
                    "Prefer hardware-backed credentials / SSO over long-lived keychain secrets when possible",
                    "Monitor anomalous security(1) dump / find-generic-password process trees via EDR",
                    "OPSEC: assess never dumps secrets - path presence only; do not run dump-keychain in RT assess",
                ],
                falsePositiveNotes:
                    "login.keychain-db and System.keychain exist on nearly every Mac. Finding is "
                    + "path-to-impact ranking for authorized RT, not proof of compromise.",
                dryRunSafe: true,
                opsecScore: 14,
                esfExpected: ["OPEN"]
            ),
        ]
    }
}
