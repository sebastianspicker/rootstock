import Foundation
import RootstockCore

/// Lab Calendar/Reminders automation review plan - documentation only.
public struct CalendarRemindersPlanLabAction: LabAction {
    public static let id = "lab.surface.calendar_reminders_plan"
    public static let consent = ConsentPolicy.labDefault
    public static let riskClass = RiskClass.labOnly
    public init() {}
    public func run(request: LabActionRequest, context: EvaluationContext) async throws -> ActionResult {
        try SafetyRails.ensureLabConsent(context: context, policy: Self.consent)
        let labRoot = LabPaths.resolveLabRoot(params: request.parameters)
        let focus = request.parameters["focus"] ?? "Calendar/Reminders automation"
        let markerURL = labRoot.appendingPathComponent("calendar_reminders-plan", isDirectory: true)
            .appendingPathComponent("calendar_reminders-plan.md")
        let body = """
        # rootstock-red-lab Calendar/Reminders automation plan
        focus: \(focus)
        purpose: Calendar / Reminders automation lateral surface posture documentation
        rules:
        - document path/meta inventory only under consent
        - never reads event contents or creates malicious calendar invites
        - purple: validate expected telemetry under ROE only
        ROOTSTOCK_RED_LAB_WAVE13_CALENDAR_REMINDERS=1
        """
        let copy = FileMarkerCopy(
            planMessage: "Dry-run Calendar/Reminders automation plan for focus [\(focus)]: would write plan at \(markerURL.path). never reads event contents or creates malicious calendar invites.",
            planSteps: [
                "Document Calendar/Reminders automation review for: \(focus)",
                "Note path/meta inventory without host mutation beyond lab root",
                "Write markdown plan under lab root only",
                "Purple: validate expected telemetry under ROE only",
            ],
            planCleanup: ["Delete \(markerURL.path)"],
            applyDryRunMessage: "Dry-run: would write Calendar/Reminders automation plan at \(markerURL.path)",
            applySuccessMessage: "Wrote Calendar/Reminders automation plan at \(markerURL.path)",
            applySteps: ["Write Calendar/Reminders automation plan"],
            applyCleanup: ["Delete \(markerURL.path)"],
            presentMessage: "Calendar/Reminders automation plan present",
            absentMessage: "Calendar/Reminders automation plan absent",
            statusPresentCleanup: ["Delete \(markerURL.path)"],
            statusAbsentCleanup: ["No artifact"],
            removeDryRunMessage: { exists in "Dry-run: would delete Calendar/Reminders automation plan (exists=\(exists))" },
            removeSuccessMessage: { exists in "Removed Calendar/Reminders automation plan (wasPresent=\(exists))" },
            removeSteps: ["Delete \(markerURL.path)"],
            removeCleanup: ["No system mutations expected"]
        )
        return try LabMarkerLifecycle.runFileMarker(
            actionId: Self.id, operation: request.operation, markerURL: markerURL,
            body: body, contextDryRun: context.dryRun, copy: copy
        )
    }
    public static func resolveLabRoot(params: [String: String]) -> URL { LabPaths.resolveLabRoot(params: params) }
}
