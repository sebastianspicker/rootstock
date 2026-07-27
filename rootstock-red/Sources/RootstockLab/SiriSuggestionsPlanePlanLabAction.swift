import Foundation
import RootstockCore

/// Lab Siri Suggestions residual review plan - documentation only.
public struct SiriSuggestionsPlanePlanLabAction: LabAction {
    public static let id = "lab.surface.siri_suggestions_plane_plan"
    public static let consent = ConsentPolicy.labDefault
    public static let riskClass = RiskClass.labOnly
    public init() {}
    public func run(request: LabActionRequest, context: EvaluationContext) async throws -> ActionResult {
        try SafetyRails.ensureLabConsent(context: context, policy: Self.consent)
        let labRoot = LabPaths.resolveLabRoot(params: request.parameters)
        let focus = request.parameters["focus"] ?? "Siri Suggestions residual"
        let markerURL = labRoot.appendingPathComponent("siri_suggestions_plane-plan", isDirectory: true)
            .appendingPathComponent("siri_suggestions_plane-plan.md")
        let body = """
        # rootstock-red-lab Siri Suggestions residual plan
        focus: \(focus)
        purpose: Siri / Suggestions data-access residual posture documentation
        rules:
        - document path/meta inventory only under consent
        - never dumps Siri transcripts or Suggestions databases contents
        - purple: validate expected telemetry under ROE only
        ROOTSTOCK_RED_LAB_WAVE16_SIRI_SUGGESTIONS_PLANE=1
        """
        let copy = FileMarkerCopy(
            planMessage: "Dry-run Siri Suggestions residual plan for focus [\(focus)]: would write plan at \(markerURL.path). never dumps Siri transcripts or Suggestions databases contents.",
            planSteps: [
                "Document Siri Suggestions residual review for: \(focus)",
                "Note path/meta inventory without host mutation beyond lab root",
                "Write markdown plan under lab root only",
                "Purple: validate expected telemetry under ROE only",
            ],
            planCleanup: ["Delete \(markerURL.path)"],
            applyDryRunMessage: "Dry-run: would write Siri Suggestions residual plan at \(markerURL.path)",
            applySuccessMessage: "Wrote Siri Suggestions residual plan at \(markerURL.path)",
            applySteps: ["Write Siri Suggestions residual plan"], applyCleanup: ["Delete \(markerURL.path)"],
            presentMessage: "Siri Suggestions residual plan present", absentMessage: "Siri Suggestions residual plan absent",
            statusPresentCleanup: ["Delete \(markerURL.path)"], statusAbsentCleanup: ["No artifact"],
            removeDryRunMessage: { exists in "Dry-run: would delete Siri Suggestions residual plan (exists=\(exists))" },
            removeSuccessMessage: { exists in "Removed Siri Suggestions residual plan (wasPresent=\(exists))" },
            removeSteps: ["Delete \(markerURL.path)"], removeCleanup: ["No system mutations expected"]
        )
        return try LabMarkerLifecycle.runFileMarker(
            actionId: Self.id, operation: request.operation, markerURL: markerURL,
            body: body, contextDryRun: context.dryRun, copy: copy
        )
    }
    public static func resolveLabRoot(params: [String: String]) -> URL { LabPaths.resolveLabRoot(params: params) }
}
