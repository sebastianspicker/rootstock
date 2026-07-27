import Foundation
import RootstockCore

/// Lab Cron/at job depth review plan - documentation only.
public struct CronAtJobDepthPlanLabAction: LabAction {
    public static let id = "lab.surface.cron_at_job_depth_plan"
    public static let consent = ConsentPolicy.labDefault
    public static let riskClass = RiskClass.labOnly
    public init() {}
    public func run(request: LabActionRequest, context: EvaluationContext) async throws -> ActionResult {
        try SafetyRails.ensureLabConsent(context: context, policy: Self.consent)
        let labRoot = LabPaths.resolveLabRoot(params: request.parameters)
        let focus = request.parameters["focus"] ?? "Cron/at job depth"
        let markerURL = labRoot.appendingPathComponent("cron_at_job_depth-plan", isDirectory: true)
            .appendingPathComponent("cron_at_job_depth-plan.md")
        let body = """
        # rootstock-red-lab Cron/at job depth plan
        focus: \(focus)
        purpose: Cron / at job dual-use residual depth posture documentation
        rules:
        - document path/meta inventory only under consent
        - never installs cron or at jobs outside the lab root
        - purple: validate expected telemetry under ROE only
        ROOTSTOCK_RED_LAB_WAVE14_CRON_AT_JOB_DEPTH=1
        """
        let copy = FileMarkerCopy(
            planMessage: "Dry-run Cron/at job depth plan for focus [\(focus)]: would write plan at \(markerURL.path). never installs cron or at jobs outside the lab root.",
            planSteps: [
                "Document Cron/at job depth review for: \(focus)",
                "Note path/meta inventory without host mutation beyond lab root",
                "Write markdown plan under lab root only",
                "Purple: validate expected telemetry under ROE only",
            ],
            planCleanup: ["Delete \(markerURL.path)"],
            applyDryRunMessage: "Dry-run: would write Cron/at job depth plan at \(markerURL.path)",
            applySuccessMessage: "Wrote Cron/at job depth plan at \(markerURL.path)",
            applySteps: ["Write Cron/at job depth plan"], applyCleanup: ["Delete \(markerURL.path)"],
            presentMessage: "Cron/at job depth plan present", absentMessage: "Cron/at job depth plan absent",
            statusPresentCleanup: ["Delete \(markerURL.path)"], statusAbsentCleanup: ["No artifact"],
            removeDryRunMessage: { exists in "Dry-run: would delete Cron/at job depth plan (exists=\(exists))" },
            removeSuccessMessage: { exists in "Removed Cron/at job depth plan (wasPresent=\(exists))" },
            removeSteps: ["Delete \(markerURL.path)"], removeCleanup: ["No system mutations expected"]
        )
        return try LabMarkerLifecycle.runFileMarker(
            actionId: Self.id, operation: request.operation, markerURL: markerURL,
            body: body, contextDryRun: context.dryRun, copy: copy
        )
    }
    public static func resolveLabRoot(params: [String: String]) -> URL { LabPaths.resolveLabRoot(params: params) }
}
