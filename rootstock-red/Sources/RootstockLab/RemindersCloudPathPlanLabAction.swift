import Foundation
import RootstockCore

/// Lab Reminders cloud path review plan - documentation only.
public struct RemindersCloudPathPlanLabAction: LabAction {
    public static let id = "lab.surface.reminders_cloud_path_plan"
    public static let consent = ConsentPolicy.labDefault
    public static let riskClass = RiskClass.labOnly
    public init() {}
    public func run(request: LabActionRequest, context: EvaluationContext) async throws -> ActionResult {
        try SafetyRails.ensureLabConsent(context: context, policy: Self.consent)
        let labRoot = LabPaths.resolveLabRoot(params: request.parameters)
        let focus = request.parameters["focus"] ?? "Reminders cloud path"
        let markerURL = labRoot.appendingPathComponent("reminders_cloud_path-plan", isDirectory: true)
            .appendingPathComponent("reminders_cloud_path-plan.md")
        let body = """
        # rootstock-red-lab Reminders cloud path plan
        focus: \(focus)
        purpose: Reminders cloud path residual plane posture documentation
        rules:
        - document path/meta inventory only under consent
        - never reads reminder titles/bodies or exports Reminders databases
        - purple: validate expected telemetry under ROE only
        ROOTSTOCK_RED_LAB_WAVE16_REMINDERS_CLOUD_PATH=1
        """
        let copy = FileMarkerCopy(
            planMessage: "Dry-run Reminders cloud path plan for focus [\(focus)]: would write plan at \(markerURL.path). never reads reminder titles/bodies or exports Reminders databases.",
            planSteps: [
                "Document Reminders cloud path review for: \(focus)",
                "Note path/meta inventory without host mutation beyond lab root",
                "Write markdown plan under lab root only",
                "Purple: validate expected telemetry under ROE only",
            ],
            planCleanup: ["Delete \(markerURL.path)"],
            applyDryRunMessage: "Dry-run: would write Reminders cloud path plan at \(markerURL.path)",
            applySuccessMessage: "Wrote Reminders cloud path plan at \(markerURL.path)",
            applySteps: ["Write Reminders cloud path plan"], applyCleanup: ["Delete \(markerURL.path)"],
            presentMessage: "Reminders cloud path plan present", absentMessage: "Reminders cloud path plan absent",
            statusPresentCleanup: ["Delete \(markerURL.path)"], statusAbsentCleanup: ["No artifact"],
            removeDryRunMessage: { exists in "Dry-run: would delete Reminders cloud path plan (exists=\(exists))" },
            removeSuccessMessage: { exists in "Removed Reminders cloud path plan (wasPresent=\(exists))" },
            removeSteps: ["Delete \(markerURL.path)"], removeCleanup: ["No system mutations expected"]
        )
        return try LabMarkerLifecycle.runFileMarker(
            actionId: Self.id, operation: request.operation, markerURL: markerURL,
            body: body, contextDryRun: context.dryRun, copy: copy
        )
    }
    public static func resolveLabRoot(params: [String: String]) -> URL { LabPaths.resolveLabRoot(params: params) }
}
