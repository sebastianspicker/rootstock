import Foundation
import RootstockCore

/// Lab Podcasts path plane review plan - documentation only.
public struct PodcastsPathPlanePlanLabAction: LabAction {
    public static let id = "lab.surface.podcasts_path_plane_plan"
    public static let consent = ConsentPolicy.labDefault
    public static let riskClass = RiskClass.labOnly
    public init() {}
    public func run(request: LabActionRequest, context: EvaluationContext) async throws -> ActionResult {
        try SafetyRails.ensureLabConsent(context: context, policy: Self.consent)
        let labRoot = LabPaths.resolveLabRoot(params: request.parameters)
        let focus = request.parameters["focus"] ?? "Podcasts path plane"
        let markerURL = labRoot.appendingPathComponent("podcasts_path_plane-plan", isDirectory: true)
            .appendingPathComponent("podcasts_path_plane-plan.md")
        let body = """
        # rootstock-red-lab Podcasts path plane plan
        focus: \(focus)
        purpose: Podcasts library path residual posture documentation
        rules:
        - document path/meta inventory only under consent
        - never dumps podcast episode files or account tokens
        - purple: validate expected telemetry under ROE only
        ROOTSTOCK_RED_LAB_WAVE16_PODCASTS_PATH_PLANE=1
        """
        let copy = FileMarkerCopy(
            planMessage: "Dry-run Podcasts path plane plan for focus [\(focus)]: would write plan at \(markerURL.path). never dumps podcast episode files or account tokens.",
            planSteps: [
                "Document Podcasts path plane review for: \(focus)",
                "Note path/meta inventory without host mutation beyond lab root",
                "Write markdown plan under lab root only",
                "Purple: validate expected telemetry under ROE only",
            ],
            planCleanup: ["Delete \(markerURL.path)"],
            applyDryRunMessage: "Dry-run: would write Podcasts path plane plan at \(markerURL.path)",
            applySuccessMessage: "Wrote Podcasts path plane plan at \(markerURL.path)",
            applySteps: ["Write Podcasts path plane plan"], applyCleanup: ["Delete \(markerURL.path)"],
            presentMessage: "Podcasts path plane plan present", absentMessage: "Podcasts path plane plan absent",
            statusPresentCleanup: ["Delete \(markerURL.path)"], statusAbsentCleanup: ["No artifact"],
            removeDryRunMessage: { exists in "Dry-run: would delete Podcasts path plane plan (exists=\(exists))" },
            removeSuccessMessage: { exists in "Removed Podcasts path plane plan (wasPresent=\(exists))" },
            removeSteps: ["Delete \(markerURL.path)"], removeCleanup: ["No system mutations expected"]
        )
        return try LabMarkerLifecycle.runFileMarker(
            actionId: Self.id, operation: request.operation, markerURL: markerURL,
            body: body, contextDryRun: context.dryRun, copy: copy
        )
    }
    public static func resolveLabRoot(params: [String: String]) -> URL { LabPaths.resolveLabRoot(params: params) }
}
