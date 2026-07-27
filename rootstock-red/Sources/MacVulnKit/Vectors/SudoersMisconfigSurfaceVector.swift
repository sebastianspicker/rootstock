import Foundation
import RootstockCore

/// Path-to-impact: sudoers / sudoers.d misconfiguration surface (read-only assessment).
///
/// Research basis: PEASS sudo checks; public sudo Host_Alias / NOPASSWD misconfig themes (e.g. CVE-2025-32462 class *requires misconfig*).
/// Safety and behavior: never runs `sudo -l` storms or weaponized exploits; path readability + collector notes;
/// typed Finding with ATT&CK, remediation, FP honesty.
public struct SudoersMisconfigSurfaceVector: Check {
    public static let id = "rootstock.vector.privesc.sudoers_misconfig_surface"
    public static let cost: CollectorCost = .low

    private static let probePaths = [
        "/etc/sudoers",
        "/private/etc/sudoers",
        "/etc/sudoers.d",
        "/private/etc/sudoers.d",
    ]

    public init() {}

    public func evaluate(state: CollectedState, context: EvaluationContext) async throws -> [Finding] {
        let fm = FileManager.default
        var evidence: [Evidence] = []
        var readableFiles: [String] = []
        var writableHits: [String] = []
        var listedDropins: [String] = []

        // Synthetic / collector-driven signals (tests + future collector).
        if let note = state.collectorNotes["privesc.sudoers_signals"] {
            evidence.append(Evidence(type: "collector_note", detail: note))
            for part in note.split(separator: "|") {
                let p = String(part).trimmingCharacters(in: .whitespaces)
                if p.hasPrefix("readable:") {
                    readableFiles.append(String(p.dropFirst("readable:".count)))
                } else if p.hasPrefix("writable:") {
                    writableHits.append(String(p.dropFirst("writable:".count)))
                } else if p.hasPrefix("nopasswd_hint:") {
                    evidence.append(
                        Evidence(type: "nopasswd_hint", detail: String(p.dropFirst("nopasswd_hint:".count)))
                    )
                }
            }
        }

        for path in Self.probePaths {
            var isDir: ObjCBool = false
            guard fm.fileExists(atPath: path, isDirectory: &isDir) else { continue }
            if isDir.boolValue {
                if fm.isReadableFile(atPath: path) {
                    evidence.append(Evidence(type: "sudoers_dir", path: path, detail: "readable=true"))
                    if let kids = try? fm.contentsOfDirectory(atPath: path) {
                        listedDropins.append(contentsOf: kids.prefix(20).map { "\(path)/\($0)" })
                    }
                }
                if fm.isWritableFile(atPath: path) {
                    writableHits.append(path)
                }
            } else {
                if fm.isReadableFile(atPath: path) {
                    readableFiles.append(path)
                }
                if fm.isWritableFile(atPath: path) {
                    writableHits.append(path)
                }
            }
        }

        for path in listedDropins.prefix(15) {
            evidence.append(Evidence(type: "sudoers_dropin", path: path, detail: "drop-in present"))
            if fm.isWritableFile(atPath: path) {
                writableHits.append(path)
            }
        }
        for path in readableFiles.prefix(10) {
            evidence.append(Evidence(type: "sudoers_file", path: path, detail: "readable=true (content not parsed for secrets)"))
        }

        let isRoot = state.host?.isRoot == true
        let hasSignal =
            !readableFiles.isEmpty
            || !writableHits.isEmpty
            || !listedDropins.isEmpty
            || state.collectorNotes["privesc.sudoers_signals"] != nil
        guard hasSignal else { return [] }

        // Path-to-impact: writable is high; readable drop-ins with root/elevated context medium; else low inventory.
        let severity: Severity
        let title: String
        if !writableHits.isEmpty {
            severity = .critical
            title = "Sudoers surface: user-writable sudoers path (\(writableHits.count))"
            for path in writableHits.prefix(10) {
                evidence.append(Evidence(type: "writable_sudoers", path: path, detail: "writable=true"))
            }
        } else if isRoot || state.protections?.sipEnabled == false {
            severity = .medium
            title = "Sudoers surface readable under elevated/weak-SIP context"
        } else if !listedDropins.isEmpty || !readableFiles.isEmpty {
            severity = .low
            title = "Sudoers configuration surface present (readable paths - no content exploit)"
        } else {
            severity = .low
            title = "Sudoers misconfig surface signals present"
        }

        evidence.insert(
            Evidence(
                type: "summary",
                detail:
                    "readableFiles=\(readableFiles.count) dropins=\(listedDropins.count) "
                    + "writable=\(writableHits.count) isRoot=\(isRoot) "
                    + "(assess only - no sudo -l storm, no CVE exploit delivery)"
            ),
            at: 0
        )

        return [
            Finding(
                id: Self.id,
                title: title,
                severity: severity,
                confidence: writableHits.isEmpty ? .low : .medium,
                category: .misconfig,
                evidence: evidence,
                attackTechniques: ["T1548.003", "T1548", "T1068"],
                remediation: [
                    "Ensure /etc/sudoers and /etc/sudoers.d are root:wheel and not user-writable",
                    "Audit NOPASSWD and Host_Alias rules via authorized configuration management",
                    "Prefer least-privilege group policies over broad admin sudo",
                    "OPSEC: Rootstock Red does not execute sudo exploits or dump sudo -l by default",
                ],
                falsePositiveNotes:
                    "Readable sudoers is common on stock macOS; finding is surface + writability ranking, "
                    + "not proof of a live privilege-escalation CVE. Content is not fully parsed.",
                dryRunSafe: true,
                opsecScore: 18,
                esfExpected: ["OPEN"]
            ),
        ]
    }
}
