import Foundation
import RootstockCore

/// Lab Photos library path plane review plan - documentation only.
public struct PhotosLibraryPathPlanLabAction: LabAction {
    public static let id = "lab.surface.photos_library_path_plan"
    public static let consent = ConsentPolicy.labDefault
    public static let riskClass = RiskClass.labOnly
    public init() {}
    public func run(request: LabActionRequest, context: EvaluationContext) async throws -> ActionResult {
        try SafetyRails.ensureLabConsent(context: context, policy: Self.consent)
        let labRoot = LabPaths.resolveLabRoot(params: request.parameters)
        let focus = request.parameters["focus"] ?? "Photos library path plane"
        let markerURL = labRoot.appendingPathComponent("photos_library_path-plan", isDirectory: true)
            .appendingPathComponent("photos_library_path-plan.md")
        let body = """
        # rootstock-red-lab Photos library path plane plan
        focus: \(focus)
        purpose: Photos.app library collection path plane posture documentation
        rules:
        - document path/meta inventory only under consent
        - never reads photo contents or exports Photo Library media
        - purple: validate expected telemetry under ROE only
        ROOTSTOCK_RED_LAB_WAVE15_PHOTOS_LIBRARY_PATH=1
        """
        let copy = FileMarkerCopy(
            planMessage: "Dry-run Photos library path plane plan for focus [\(focus)]: would write plan at \(markerURL.path). never reads photo contents or exports Photo Library media.",
            planSteps: [
                "Document Photos library path plane review for: \(focus)",
                "Note path/meta inventory without host mutation beyond lab root",
                "Write markdown plan under lab root only",
                "Purple: validate expected telemetry under ROE only",
            ],
            planCleanup: ["Delete \(markerURL.path)"],
            applyDryRunMessage: "Dry-run: would write Photos library path plane plan at \(markerURL.path)",
            applySuccessMessage: "Wrote Photos library path plane plan at \(markerURL.path)",
            applySteps: ["Write Photos library path plane plan"], applyCleanup: ["Delete \(markerURL.path)"],
            presentMessage: "Photos library path plane plan present", absentMessage: "Photos library path plane plan absent",
            statusPresentCleanup: ["Delete \(markerURL.path)"], statusAbsentCleanup: ["No artifact"],
            removeDryRunMessage: { exists in "Dry-run: would delete Photos library path plane plan (exists=\(exists))" },
            removeSuccessMessage: { exists in "Removed Photos library path plane plan (wasPresent=\(exists))" },
            removeSteps: ["Delete \(markerURL.path)"], removeCleanup: ["No system mutations expected"]
        )
        return try LabMarkerLifecycle.runFileMarker(
            actionId: Self.id, operation: request.operation, markerURL: markerURL,
            body: body, contextDryRun: context.dryRun, copy: copy
        )
    }
    public static func resolveLabRoot(params: [String: String]) -> URL { LabPaths.resolveLabRoot(params: params) }
}
