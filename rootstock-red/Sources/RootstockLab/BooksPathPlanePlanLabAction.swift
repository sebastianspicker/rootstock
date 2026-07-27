import Foundation
import RootstockCore

/// Lab Books path plane review plan - documentation only.
public struct BooksPathPlanePlanLabAction: LabAction {
    public static let id = "lab.surface.books_path_plane_plan"
    public static let consent = ConsentPolicy.labDefault
    public static let riskClass = RiskClass.labOnly
    public init() {}
    public func run(request: LabActionRequest, context: EvaluationContext) async throws -> ActionResult {
        try SafetyRails.ensureLabConsent(context: context, policy: Self.consent)
        let labRoot = LabPaths.resolveLabRoot(params: request.parameters)
        let focus = request.parameters["focus"] ?? "Books path plane"
        let markerURL = labRoot.appendingPathComponent("books_path_plane-plan", isDirectory: true)
            .appendingPathComponent("books_path_plane-plan.md")
        let body = """
        # rootstock-red-lab Books path plane plan
        focus: \(focus)
        purpose: Books / EPUB path residual plane posture documentation
        rules:
        - document path/meta inventory only under consent
        - never extracts EPUB contents or Books annotations as bulk export
        - purple: validate expected telemetry under ROE only
        ROOTSTOCK_RED_LAB_WAVE16_BOOKS_PATH_PLANE=1
        """
        let copy = FileMarkerCopy(
            planMessage: "Dry-run Books path plane plan for focus [\(focus)]: would write plan at \(markerURL.path). never extracts EPUB contents or Books annotations as bulk export.",
            planSteps: [
                "Document Books path plane review for: \(focus)",
                "Note path/meta inventory without host mutation beyond lab root",
                "Write markdown plan under lab root only",
                "Purple: validate expected telemetry under ROE only",
            ],
            planCleanup: ["Delete \(markerURL.path)"],
            applyDryRunMessage: "Dry-run: would write Books path plane plan at \(markerURL.path)",
            applySuccessMessage: "Wrote Books path plane plan at \(markerURL.path)",
            applySteps: ["Write Books path plane plan"], applyCleanup: ["Delete \(markerURL.path)"],
            presentMessage: "Books path plane plan present", absentMessage: "Books path plane plan absent",
            statusPresentCleanup: ["Delete \(markerURL.path)"], statusAbsentCleanup: ["No artifact"],
            removeDryRunMessage: { exists in "Dry-run: would delete Books path plane plan (exists=\(exists))" },
            removeSuccessMessage: { exists in "Removed Books path plane plan (wasPresent=\(exists))" },
            removeSteps: ["Delete \(markerURL.path)"], removeCleanup: ["No system mutations expected"]
        )
        return try LabMarkerLifecycle.runFileMarker(
            actionId: Self.id, operation: request.operation, markerURL: markerURL,
            body: body, contextDryRun: context.dryRun, copy: copy
        )
    }
    public static func resolveLabRoot(params: [String: String]) -> URL { LabPaths.resolveLabRoot(params: params) }
}
