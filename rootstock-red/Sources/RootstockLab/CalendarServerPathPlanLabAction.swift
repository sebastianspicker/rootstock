import Foundation
import RootstockCore

/// Lab Calendar CalDAV residual review plan - documentation only.
public struct CalendarServerPathPlanLabAction: LabAction {
    public static let id = "lab.surface.calendar_server_path_plan"
    public static let consent = ConsentPolicy.labDefault
    public static let riskClass = RiskClass.labOnly
    public init() {}
    public func run(request: LabActionRequest, context: EvaluationContext) async throws -> ActionResult {
        try SafetyRails.ensureLabConsent(context: context, policy: Self.consent)
        let labRoot = LabPaths.resolveLabRoot(params: request.parameters)
        let focus = request.parameters["focus"] ?? "Calendar CalDAV residual"
        let markerURL = labRoot.appendingPathComponent("calendar_server_path-plan", isDirectory: true)
            .appendingPathComponent("calendar_server_path-plan.md")
        let body = """
        # rootstock-red-lab Calendar CalDAV residual plan
        focus: \(focus)
        purpose: Calendar server / CalDAV residual surface posture documentation
        rules:
        - document path/meta inventory only under consent
        - never reads calendar event bodies or credentials from CalDAV stores
        - purple: validate expected telemetry under ROE only
        ROOTSTOCK_RED_LAB_WAVE16_CALENDAR_SERVER_PATH=1
        """
        let copy = FileMarkerCopy(
            planMessage: "Dry-run Calendar CalDAV residual plan for focus [\(focus)]: would write plan at \(markerURL.path). never reads calendar event bodies or credentials from CalDAV stores.",
            planSteps: [
                "Document Calendar CalDAV residual review for: \(focus)",
                "Note path/meta inventory without host mutation beyond lab root",
                "Write markdown plan under lab root only",
                "Purple: validate expected telemetry under ROE only",
            ],
            planCleanup: ["Delete \(markerURL.path)"],
            applyDryRunMessage: "Dry-run: would write Calendar CalDAV residual plan at \(markerURL.path)",
            applySuccessMessage: "Wrote Calendar CalDAV residual plan at \(markerURL.path)",
            applySteps: ["Write Calendar CalDAV residual plan"], applyCleanup: ["Delete \(markerURL.path)"],
            presentMessage: "Calendar CalDAV residual plan present", absentMessage: "Calendar CalDAV residual plan absent",
            statusPresentCleanup: ["Delete \(markerURL.path)"], statusAbsentCleanup: ["No artifact"],
            removeDryRunMessage: { exists in "Dry-run: would delete Calendar CalDAV residual plan (exists=\(exists))" },
            removeSuccessMessage: { exists in "Removed Calendar CalDAV residual plan (wasPresent=\(exists))" },
            removeSteps: ["Delete \(markerURL.path)"], removeCleanup: ["No system mutations expected"]
        )
        return try LabMarkerLifecycle.runFileMarker(
            actionId: Self.id, operation: request.operation, markerURL: markerURL,
            body: body, contextDryRun: context.dryRun, copy: copy
        )
    }
    public static func resolveLabRoot(params: [String: String]) -> URL { LabPaths.resolveLabRoot(params: params) }
}
