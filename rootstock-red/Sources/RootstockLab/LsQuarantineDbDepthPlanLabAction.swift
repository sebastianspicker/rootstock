import Foundation
import RootstockCore

/// Lab LS QuarantineEvents depth review plan - documentation only.
public struct LsQuarantineDbDepthPlanLabAction: LabAction {
    public static let id = "lab.surface.ls_quarantine_db_depth_plan"
    public static let consent = ConsentPolicy.labDefault
    public static let riskClass = RiskClass.labOnly
    public init() {}
    public func run(request: LabActionRequest, context: EvaluationContext) async throws -> ActionResult {
        try SafetyRails.ensureLabConsent(context: context, policy: Self.consent)
        let labRoot = LabPaths.resolveLabRoot(params: request.parameters)
        let focus = request.parameters["focus"] ?? "LS QuarantineEvents depth"
        let markerURL = labRoot.appendingPathComponent("ls_quarantine_db_depth-plan", isDirectory: true)
            .appendingPathComponent("ls_quarantine_db_depth-plan.md")
        let body = """
        # rootstock-red-lab LS QuarantineEvents depth plan
        focus: \(focus)
        purpose: LaunchServices QuarantineEvents DB residual depth posture documentation
        rules:
        - document path/meta inventory only under consent
        - never deletes QuarantineEvents rows or clears LS quarantine history
        - purple: validate expected telemetry under ROE only
        ROOTSTOCK_RED_LAB_WAVE14_LS_QUARANTINE_DB_DEPTH=1
        """
        let copy = FileMarkerCopy(
            planMessage: "Dry-run LS QuarantineEvents depth plan for focus [\(focus)]: would write plan at \(markerURL.path). never deletes QuarantineEvents rows or clears LS quarantine history.",
            planSteps: [
                "Document LS QuarantineEvents depth review for: \(focus)",
                "Note path/meta inventory without host mutation beyond lab root",
                "Write markdown plan under lab root only",
                "Purple: validate expected telemetry under ROE only",
            ],
            planCleanup: ["Delete \(markerURL.path)"],
            applyDryRunMessage: "Dry-run: would write LS QuarantineEvents depth plan at \(markerURL.path)",
            applySuccessMessage: "Wrote LS QuarantineEvents depth plan at \(markerURL.path)",
            applySteps: ["Write LS QuarantineEvents depth plan"], applyCleanup: ["Delete \(markerURL.path)"],
            presentMessage: "LS QuarantineEvents depth plan present", absentMessage: "LS QuarantineEvents depth plan absent",
            statusPresentCleanup: ["Delete \(markerURL.path)"], statusAbsentCleanup: ["No artifact"],
            removeDryRunMessage: { exists in "Dry-run: would delete LS QuarantineEvents depth plan (exists=\(exists))" },
            removeSuccessMessage: { exists in "Removed LS QuarantineEvents depth plan (wasPresent=\(exists))" },
            removeSteps: ["Delete \(markerURL.path)"], removeCleanup: ["No system mutations expected"]
        )
        return try LabMarkerLifecycle.runFileMarker(
            actionId: Self.id, operation: request.operation, markerURL: markerURL,
            body: body, contextDryRun: context.dryRun, copy: copy
        )
    }
    public static func resolveLabRoot(params: [String: String]) -> URL { LabPaths.resolveLabRoot(params: params) }
}
