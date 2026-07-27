import Foundation
import RootstockCore

/// Path-to-impact: periodic / maintenance script directories as root-scheduled privesc surface.
///
/// Research basis: PEASS periodic checks; historical maintenance-script privesc research themes.
/// Safety and behavior: API-first path probes + collector notes; no root script planting; SIP honesty.
public struct PeriodicMaintenanceSurfaceVector: Check {
    public static let id = "rootstock.vector.privesc.periodic_maintenance_surface"
    public static let cost: CollectorCost = .low

    private static let probeDirs = [
        "/etc/periodic",
        "/private/etc/periodic",
        "/usr/local/etc/periodic",
        "/etc/periodic/daily",
        "/etc/periodic/weekly",
        "/etc/periodic/monthly",
        "/usr/local/etc/periodic/daily",
    ]

    public init() {}

    public func evaluate(state: CollectedState, context: EvaluationContext) async throws -> [Finding] {
        let fm = FileManager.default
        var present: [String] = []
        var writable: [String] = []
        var evidence: [Evidence] = []

        if let note = state.collectorNotes["privesc.periodic_paths"] {
            for part in note.split(separator: "|") {
                let p = String(part).trimmingCharacters(in: .whitespaces)
                guard !p.isEmpty else { continue }
                present.append(p)
                if p.hasPrefix("writable:") {
                    writable.append(String(p.dropFirst("writable:".count)))
                } else if fm.isWritableFile(atPath: p) {
                    writable.append(p)
                }
            }
        }

        for path in Self.probeDirs {
            var isDir: ObjCBool = false
            guard fm.fileExists(atPath: path, isDirectory: &isDir) else { continue }
            present.append(path)
            let w = fm.isWritableFile(atPath: path)
            if w { writable.append(path) }
            evidence.append(
                Evidence(type: "periodic_dir", path: path, detail: "dir=\(isDir.boolValue) writable=\(w)")
            )
        }

        // Dedup
        present = Array(Set(present)).sorted()
        writable = Array(Set(writable)).sorted()

        let forced = state.collectorNotes["privesc.periodic_paths"] != nil
        let customTree = present.contains { $0.contains("/usr/local/etc/periodic") }
        // Stock /etc/periodic alone is normal - require writable, custom tree, or collector force.
        guard !writable.isEmpty || customTree || forced else { return [] }

        for path in writable.prefix(15) {
            evidence.append(Evidence(type: "writable_periodic", path: path, detail: "user-writable maintenance path"))
        }
        if state.protections?.sipEnabled == false {
            evidence.append(
                Evidence(type: "sip_compound", detail: "SIP off compounds writable periodic paths")
            )
        }
        evidence.insert(
            Evidence(
                type: "summary",
                detail:
                    "periodicPaths=\(present.count) writable=\(writable.count) customTree=\(customTree) "
                    + "(no scripts executed; no root plant)"
            ),
            at: 0
        )

        let severity: Severity
        let title: String
        if !writable.isEmpty && state.protections?.sipEnabled == false {
            severity = .high
            title = "Periodic maintenance vector: writable paths with SIP off (\(writable.count))"
        } else if !writable.isEmpty {
            severity = .high
            title = "Periodic maintenance vector: user-writable scheduled-script paths (\(writable.count))"
        } else {
            severity = .low
            title = "Periodic / maintenance script surface (custom or forced inventory)"
        }

        return [
            Finding(
                id: Self.id,
                title: title,
                severity: severity,
                confidence: writable.isEmpty ? .low : .medium,
                category: .misconfig,
                evidence: evidence,
                attackTechniques: ["T1053.003", "T1037", "T1068"],
                remediation: [
                    "Ensure periodic directories are root-owned and not user-writable",
                    "Review custom scripts under /usr/local/etc/periodic for unexpected content",
                    "Prefer MDM/launchd over ad-hoc root periodic scripts",
                    "OPSEC: assess lists paths only - planting periodic root scripts is lab-gated",
                ],
                falsePositiveNotes:
                    "Stock /etc/periodic trees are normal. Writable hits under lab/temp trees may be synthetic.",
                dryRunSafe: true,
                opsecScore: 20,
                esfExpected: ["OPEN", "WRITE"]
            ),
        ]
    }
}
