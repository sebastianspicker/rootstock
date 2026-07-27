import Foundation
import RootstockCore

/// Lab Notes metadata plane review plan - documentation only.
public struct NotesMetadataPlanePlanLabAction: LabAction {
    public static let id = "lab.surface.notes_metadata_plane_plan"
    public static let consent = ConsentPolicy.labDefault
    public static let riskClass = RiskClass.labOnly
    public init() {}
    public func run(request: LabActionRequest, context: EvaluationContext) async throws -> ActionResult {
        try SafetyRails.ensureLabConsent(context: context, policy: Self.consent)
        let labRoot = LabPaths.resolveLabRoot(params: request.parameters)
        let focus = request.parameters["focus"] ?? "Notes metadata plane"
        let markerURL = labRoot.appendingPathComponent("notes_metadata_plane-plan", isDirectory: true)
            .appendingPathComponent("notes_metadata_plane-plan.md")
        let body = """
        # rootstock-red-lab Notes metadata plane plan
        focus: \(focus)
        purpose: Notes.app metadata collection path plane posture documentation
        rules:
        - document path/meta inventory only under consent
        - never reads Notes body contents or exports note secrets
        - purple: validate expected telemetry under ROE only
        ROOTSTOCK_RED_LAB_WAVE14_NOTES_METADATA_PLANE=1
        """
        let copy = FileMarkerCopy(
            planMessage: "Dry-run Notes metadata plane plan for focus [\(focus)]: would write plan at \(markerURL.path). never reads Notes body contents or exports note secrets.",
            planSteps: [
                "Document Notes metadata plane review for: \(focus)",
                "Note path/meta inventory without host mutation beyond lab root",
                "Write markdown plan under lab root only",
                "Purple: validate expected telemetry under ROE only",
            ],
            planCleanup: ["Delete \(markerURL.path)"],
            applyDryRunMessage: "Dry-run: would write Notes metadata plane plan at \(markerURL.path)",
            applySuccessMessage: "Wrote Notes metadata plane plan at \(markerURL.path)",
            applySteps: ["Write Notes metadata plane plan"], applyCleanup: ["Delete \(markerURL.path)"],
            presentMessage: "Notes metadata plane plan present", absentMessage: "Notes metadata plane plan absent",
            statusPresentCleanup: ["Delete \(markerURL.path)"], statusAbsentCleanup: ["No artifact"],
            removeDryRunMessage: { exists in "Dry-run: would delete Notes metadata plane plan (exists=\(exists))" },
            removeSuccessMessage: { exists in "Removed Notes metadata plane plan (wasPresent=\(exists))" },
            removeSteps: ["Delete \(markerURL.path)"], removeCleanup: ["No system mutations expected"]
        )
        return try LabMarkerLifecycle.runFileMarker(
            actionId: Self.id, operation: request.operation, markerURL: markerURL,
            body: body, contextDryRun: context.dryRun, copy: copy
        )
    }
    public static func resolveLabRoot(params: [String: String]) -> URL { LabPaths.resolveLabRoot(params: params) }
}
