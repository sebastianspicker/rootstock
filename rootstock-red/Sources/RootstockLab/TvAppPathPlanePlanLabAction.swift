import Foundation
import RootstockCore

/// Lab TV.app path plane review plan - documentation only.
public struct TvAppPathPlanePlanLabAction: LabAction {
    public static let id = "lab.surface.tv_app_path_plane_plan"
    public static let consent = ConsentPolicy.labDefault
    public static let riskClass = RiskClass.labOnly
    public init() {}
    public func run(request: LabActionRequest, context: EvaluationContext) async throws -> ActionResult {
        try SafetyRails.ensureLabConsent(context: context, policy: Self.consent)
        let labRoot = LabPaths.resolveLabRoot(params: request.parameters)
        let focus = request.parameters["focus"] ?? "TV.app path plane"
        let markerURL = labRoot.appendingPathComponent("tv_app_path_plane-plan", isDirectory: true)
            .appendingPathComponent("tv_app_path_plane-plan.md")
        let body = """
        # rootstock-red-lab TV.app path plane plan
        focus: \(focus)
        purpose: TV.app residual path plane posture documentation
        rules:
        - document path/meta inventory only under consent
        - never dumps TV.app media caches or account material
        - purple: validate expected telemetry under ROE only
        ROOTSTOCK_RED_LAB_WAVE16_TV_APP_PATH_PLANE=1
        """
        let copy = FileMarkerCopy(
            planMessage: "Dry-run TV.app path plane plan for focus [\(focus)]: would write plan at \(markerURL.path). never dumps TV.app media caches or account material.",
            planSteps: [
                "Document TV.app path plane review for: \(focus)",
                "Note path/meta inventory without host mutation beyond lab root",
                "Write markdown plan under lab root only",
                "Purple: validate expected telemetry under ROE only",
            ],
            planCleanup: ["Delete \(markerURL.path)"],
            applyDryRunMessage: "Dry-run: would write TV.app path plane plan at \(markerURL.path)",
            applySuccessMessage: "Wrote TV.app path plane plan at \(markerURL.path)",
            applySteps: ["Write TV.app path plane plan"], applyCleanup: ["Delete \(markerURL.path)"],
            presentMessage: "TV.app path plane plan present", absentMessage: "TV.app path plane plan absent",
            statusPresentCleanup: ["Delete \(markerURL.path)"], statusAbsentCleanup: ["No artifact"],
            removeDryRunMessage: { exists in "Dry-run: would delete TV.app path plane plan (exists=\(exists))" },
            removeSuccessMessage: { exists in "Removed TV.app path plane plan (wasPresent=\(exists))" },
            removeSteps: ["Delete \(markerURL.path)"], removeCleanup: ["No system mutations expected"]
        )
        return try LabMarkerLifecycle.runFileMarker(
            actionId: Self.id, operation: request.operation, markerURL: markerURL,
            body: body, contextDryRun: context.dryRun, copy: copy
        )
    }
    public static func resolveLabRoot(params: [String: String]) -> URL { LabPaths.resolveLabRoot(params: params) }
}
