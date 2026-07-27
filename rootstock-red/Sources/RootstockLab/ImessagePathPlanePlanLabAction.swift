import Foundation
import RootstockCore

/// Lab iMessage path plane review plan - documentation only.
public struct ImessagePathPlanePlanLabAction: LabAction {
    public static let id = "lab.surface.imessage_path_plane_plan"
    public static let consent = ConsentPolicy.labDefault
    public static let riskClass = RiskClass.labOnly
    public init() {}
    public func run(request: LabActionRequest, context: EvaluationContext) async throws -> ActionResult {
        try SafetyRails.ensureLabConsent(context: context, policy: Self.consent)
        let labRoot = LabPaths.resolveLabRoot(params: request.parameters)
        let focus = request.parameters["focus"] ?? "iMessage path plane"
        let markerURL = labRoot.appendingPathComponent("imessage_path_plane-plan", isDirectory: true)
            .appendingPathComponent("imessage_path_plane-plan.md")
        let body = """
        # rootstock-red-lab iMessage path plane plan
        focus: \(focus)
        purpose: iMessage / Messages path collection plane posture documentation
        rules:
        - document path/meta inventory only under consent
        - never reads Messages database contents or exports chat transcripts
        - purple: validate expected telemetry under ROE only
        ROOTSTOCK_RED_LAB_WAVE16_IMESSAGE_PATH_PLANE=1
        """
        let copy = FileMarkerCopy(
            planMessage: "Dry-run iMessage path plane plan for focus [\(focus)]: would write plan at \(markerURL.path). never reads Messages database contents or exports chat transcripts.",
            planSteps: [
                "Document iMessage path plane review for: \(focus)",
                "Note path/meta inventory without host mutation beyond lab root",
                "Write markdown plan under lab root only",
                "Purple: validate expected telemetry under ROE only",
            ],
            planCleanup: ["Delete \(markerURL.path)"],
            applyDryRunMessage: "Dry-run: would write iMessage path plane plan at \(markerURL.path)",
            applySuccessMessage: "Wrote iMessage path plane plan at \(markerURL.path)",
            applySteps: ["Write iMessage path plane plan"], applyCleanup: ["Delete \(markerURL.path)"],
            presentMessage: "iMessage path plane plan present", absentMessage: "iMessage path plane plan absent",
            statusPresentCleanup: ["Delete \(markerURL.path)"], statusAbsentCleanup: ["No artifact"],
            removeDryRunMessage: { exists in "Dry-run: would delete iMessage path plane plan (exists=\(exists))" },
            removeSuccessMessage: { exists in "Removed iMessage path plane plan (wasPresent=\(exists))" },
            removeSteps: ["Delete \(markerURL.path)"], removeCleanup: ["No system mutations expected"]
        )
        return try LabMarkerLifecycle.runFileMarker(
            actionId: Self.id, operation: request.operation, markerURL: markerURL,
            body: body, contextDryRun: context.dryRun, copy: copy
        )
    }
    public static func resolveLabRoot(params: [String: String]) -> URL { LabPaths.resolveLabRoot(params: params) }
}
