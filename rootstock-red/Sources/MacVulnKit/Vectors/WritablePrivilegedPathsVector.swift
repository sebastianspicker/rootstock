import Foundation
import RootstockCore

/// PEASS-class privilege-escalation vector: user-writable privileged paths.
///
/// Research basis: MacPEAS writable-path breadth (LaunchDaemons, helpers, system agents).
/// Safety and behavior: pure evaluation over CollectedState + FileManager writability (no bash process
/// storms); typed Finding with ATT&CK, SIP honesty, remediation, and FP notes.
public struct WritablePrivilegedPathsVector: Check {
    public static let id = "rootstock.vector.privesc.writable_privileged_paths"
    public static let cost: CollectorCost = .low

    public init() {}

    public func evaluate(state: CollectedState, context: EvaluationContext) async throws -> [Finding] {
        let candidates = Self.candidatePaths(from: state)
        guard !candidates.isEmpty else { return [] }

        var hits: [(path: String, kind: String, writable: Bool, reason: String)] = []
        for item in candidates {
            let pathWritable = FileManager.default.isWritableFile(atPath: item.path)
            let parent = URL(fileURLWithPath: item.path).deletingLastPathComponent().path
            let parentWritable = FileManager.default.isWritableFile(atPath: parent)
            // Also treat explicit privesc probe hits from collector notes / synthetic flags.
            let flagged = item.forceWritable || pathWritable || parentWritable
            guard flagged else { continue }
            let reason: String
            if item.forceWritable {
                reason = "collector_flagged_writable"
            } else if pathWritable {
                reason = "path_writable"
            } else {
                reason = "parent_writable"
            }
            hits.append((item.path, item.kind, true, reason))
        }

        guard !hits.isEmpty else { return [] }

        var evidence: [Evidence] = [
            Evidence(
                type: "summary",
                detail:
                    "privilegedCandidates=\(candidates.count) userWritableHits=\(hits.count) "
                    + "(PEASS-class rule, API-first - no shell storm)"
            ),
        ]
        for hit in hits.prefix(40) {
            evidence.append(
                Evidence(
                    type: "writable_privileged_path",
                    path: hit.path,
                    detail: "kind=\(hit.kind) reason=\(hit.reason)"
                )
            )
        }
        if state.protections?.sipEnabled == true {
            evidence.append(
                Evidence(
                    type: "sip_honesty",
                    detail:
                        "SIP enabled - many /System paths remain immutable even if mis-reported; "
                        + "focus remediations on /Library user-writable locations"
                )
            )
        } else if state.protections?.sipEnabled == false {
            evidence.append(
                Evidence(
                    type: "sip_off",
                    detail: "SIP disabled compounds writable privileged paths into higher impact"
                )
            )
        }

        let highKinds = hits.filter {
            $0.kind.contains("daemon") || $0.kind.contains("helper") || $0.kind.contains("sygext")
        }
        let severity: Severity
        if state.protections?.sipEnabled == false && !highKinds.isEmpty {
            severity = .critical
        } else if !highKinds.isEmpty {
            severity = .high
        } else {
            severity = .medium
        }

        return [
            Finding(
                id: Self.id,
                title:
                    "Privilege-escalation vector: user-writable privileged paths "
                    + "(\(hits.count))",
                severity: severity,
                confidence: .medium,
                category: .misconfig,
                evidence: evidence,
                attackTechniques: ["T1068", "T1222", "T1543.001", "T1543.004", "T1574"],
                remediation: [
                    "Fix ownership/permissions on writable LaunchDaemons, helpers, and system agents",
                    "Ensure privileged paths are root:wheel and not group/world writable",
                    "Re-enable SIP if disabled; validate with csrutil status via MDM inventory",
                    "OPSEC: assess uses FileManager writability checks only - no PEASS shell recursion",
                ],
                falsePositiveNotes:
                    "Lab temp trees may simulate privileged path names. On stock SIP-on hosts, true "
                    + "writable system LaunchDaemons are rare; verify before emergency change control.",
                dryRunSafe: true,
                opsecScore: 28,
                esfExpected: ["OPEN"]
            ),
        ]
    }

    // MARK: - Candidates

    struct Candidate {
        var path: String
        var kind: String
        /// When collector/synthetic state already asserts writability (tests + future collector).
        var forceWritable: Bool
    }

    static func candidatePaths(from state: CollectedState) -> [Candidate] {
        var out: [Candidate] = []

        for agent in state.systemLaunchAgents {
            out.append(Candidate(path: agent.path, kind: "system_launch_agent", forceWritable: false))
        }
        for daemon in state.launchDaemons {
            out.append(Candidate(path: daemon.path, kind: "launch_daemon", forceWritable: false))
        }
        for helper in state.privilegedHelperTools {
            out.append(Candidate(path: helper, kind: "privileged_helper", forceWritable: false))
        }
        for ext in state.systemExtensionPaths {
            out.append(Candidate(path: ext, kind: "system_extension", forceWritable: false))
        }

        // Collector notes convention: privesc.writable_path=/abs/path or privesc.writable_paths=p1|p2
        for (key, value) in state.collectorNotes {
            let lower = key.lowercased()
            guard lower.contains("privesc") && lower.contains("writable") else { continue }
            if value.contains("|") {
                for part in value.split(separator: "|") {
                    let p = String(part).trimmingCharacters(in: .whitespaces)
                    if !p.isEmpty {
                        out.append(Candidate(path: p, kind: "collector_note_writable", forceWritable: true))
                    }
                }
            } else if value.hasPrefix("/") {
                out.append(Candidate(path: value, kind: "collector_note_writable", forceWritable: true))
            }
        }

        // Deduplicate by path.
        var seen = Set<String>()
        return out.filter { seen.insert($0.path).inserted }
    }
}
