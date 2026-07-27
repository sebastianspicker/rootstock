import Foundation
import RootstockCore

/// Path-to-impact: Calendar / Reminders automation lateral surface.
public struct CalendarRemindersAutomationVector: Check {
    public static let id = "rootstock.vector.automation.calendar_reminders"
    public static let cost: CollectorCost = .low
    public init() {}
    public func evaluate(state: CollectedState, context: EvaluationContext) async throws -> [Finding] {
        let s = state.calendarRemindersAutomation
        let a = s?.calendarAppPaths.count ?? 0
        let b = s?.remindersPaths.count ?? 0
        let c = s?.eventKitPaths.count ?? 0
        let surface = s?.automationSurfacePresent == true || a + b + c >= 2
        let note = state.collectorNotes["collect.calendar_reminders_automation"] != nil
        guard surface || note else { return [] }
        guard a >= 1 || b >= 1 else { return [] }
        let remote = state.network?.remoteLoginSSH == true || state.network?.screenSharingARD == true
        let fda = state.tcc?.fullDiskAccessLikely == true
        var evidence: [Evidence] = [
            Evidence(type: "calendar_reminders_summary", detail: "a=\(a) b=\(b) c=\(c) remote=\(remote) fda=\(fda)"),
        ]
        if let s {
            for path in (s.calendarAppPaths + s.remindersPaths + s.eventKitPaths).prefix(12) {
                evidence.append(Evidence(type: "calendar_reminders_path", path: path, detail: "Calendar/Reminders automation path"))
            }
            for n in s.notes.prefix(6) { evidence.append(Evidence(type: "calendar_reminders_note", detail: n)) }
        }
        evidence.append(Evidence(type: "honesty", detail: "Assess never reads event contents or creates malicious calendar invites."))
        let severity: Severity = (remote && fda && a + b >= 3) ? .high : ((remote || fda || a + b >= 2) ? .medium : .low)
        return [Finding(
            id: Self.id,
            title: remote ? "Calendar/Reminders automation with remote access amplifier" : "Calendar / Reminders automation lateral surface",
            severity: severity, confidence: .medium, category: .misconfig, evidence: evidence,
            attackTechniques: ["T1059", "T1546", "T1115"],
            remediation: [
                "Inventory and baseline Calendar/Reminders automation paths via MDM/EDR",
                "Correlate unexpected co-presence with delivery timelines",
                "Prioritize hosts with remote/FDA amplifiers",
                "OPSEC: Rootstock Red never reads event contents or creates malicious calendar invites",
            ],
            falsePositiveNotes: "Stock macOS paths often exist. Elevate multi-path co-presence with remote/FDA.",
            dryRunSafe: true, opsecScore: 25, esfExpected: ["OPEN", "READ", "EXEC"]
        )]
    }
}
