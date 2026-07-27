import Foundation
import RootstockCore

/// Path-to-impact: Calendar server / CalDAV residual surface.
public struct CalendarServerPathVector: Check {
    public static let id = "rootstock.vector.data.calendar_server_path"
    public static let cost: CollectorCost = .low
    public init() {}
    public func evaluate(state: CollectedState, context: EvaluationContext) async throws -> [Finding] {
        let s = state.calendarServerPath
        let a = s?.caldavFrameworkPaths.count ?? 0
        let b = s?.calendarsStorePaths.count ?? 0
        let c = s?.calendarAgentPaths.count ?? 0
        let surface = s?.caldavSurfacePresent == true || a + b + c >= 2
        let note = state.collectorNotes["collect.calendar_server_path"] != nil
        guard surface || note else { return [] }
        guard a >= 1 || b >= 1 else { return [] }
        let remote = state.network?.remoteLoginSSH == true || state.network?.screenSharingARD == true
        let fda = state.tcc?.fullDiskAccessLikely == true
        var evidence: [Evidence] = [
            Evidence(type: "calendar_server_path_summary", detail: "a=\(a) b=\(b) c=\(c) remote=\(remote) fda=\(fda)"),
        ]
        if let s {
            for path in (s.caldavFrameworkPaths + s.calendarsStorePaths + s.calendarAgentPaths).prefix(10) {
                evidence.append(Evidence(type: "calendar_server_path_path", path: path, detail: "Calendar CalDAV residual path"))
            }
            for n in s.notes.prefix(4) { evidence.append(Evidence(type: "calendar_server_path_note", detail: n)) }
        }
        evidence.append(Evidence(type: "honesty", detail: "Assess never reads calendar event bodies or credentials from CalDAV stores."))
        let severity: Severity = (remote && fda && a + b >= 3) ? .high : ((remote || fda || a + b >= 2) ? .medium : .low)
        return [Finding(
            id: Self.id,
            title: remote ? "Calendar CalDAV residual with remote amplifier" : "Calendar server / CalDAV residual surface",
            severity: severity, confidence: .medium, category: .misconfig, evidence: evidence,
            attackTechniques: ["T1213", "T1005", "T1071"],
            remediation: [
                "Inventory and baseline Calendar CalDAV residual paths via MDM/EDR",
                "Correlate unexpected co-presence with delivery timelines",
                "Prioritize hosts with remote/FDA amplifiers",
                "OPSEC: Rootstock Red never reads calendar event bodies or credentials from CalDAV stores",
            ],
            falsePositiveNotes: "Stock paths often exist. Elevate multi-path co-presence with remote/FDA.",
            dryRunSafe: true, opsecScore: 25, esfExpected: ["OPEN", "READ", "EXEC"]
        )]
    }
}
