import Foundation
import RootstockCore

/// Lab FaceTime camera dual-use review plan - documentation only.
public struct FacetimeCameraSurfacePlanLabAction: LabAction {
    public static let id = "lab.surface.facetime_camera_surface_plan"
    public static let consent = ConsentPolicy.labDefault
    public static let riskClass = RiskClass.labOnly
    public init() {}
    public func run(request: LabActionRequest, context: EvaluationContext) async throws -> ActionResult {
        try SafetyRails.ensureLabConsent(context: context, policy: Self.consent)
        let labRoot = LabPaths.resolveLabRoot(params: request.parameters)
        let focus = request.parameters["focus"] ?? "FaceTime camera dual-use"
        let markerURL = labRoot.appendingPathComponent("facetime_camera_surface-plan", isDirectory: true)
            .appendingPathComponent("facetime_camera_surface-plan.md")
        let body = """
        # rootstock-red-lab FaceTime camera dual-use plan
        focus: \(focus)
        purpose: FaceTime / camera pipeline dual-use surface posture documentation
        rules:
        - document path/meta inventory only under consent
        - never activates camera/mic or dumps FaceTime call history contents
        - purple: validate expected telemetry under ROE only
        ROOTSTOCK_RED_LAB_WAVE16_FACETIME_CAMERA_SURFACE=1
        """
        let copy = FileMarkerCopy(
            planMessage: "Dry-run FaceTime camera dual-use plan for focus [\(focus)]: would write plan at \(markerURL.path). never activates camera/mic or dumps FaceTime call history contents.",
            planSteps: [
                "Document FaceTime camera dual-use review for: \(focus)",
                "Note path/meta inventory without host mutation beyond lab root",
                "Write markdown plan under lab root only",
                "Purple: validate expected telemetry under ROE only",
            ],
            planCleanup: ["Delete \(markerURL.path)"],
            applyDryRunMessage: "Dry-run: would write FaceTime camera dual-use plan at \(markerURL.path)",
            applySuccessMessage: "Wrote FaceTime camera dual-use plan at \(markerURL.path)",
            applySteps: ["Write FaceTime camera dual-use plan"], applyCleanup: ["Delete \(markerURL.path)"],
            presentMessage: "FaceTime camera dual-use plan present", absentMessage: "FaceTime camera dual-use plan absent",
            statusPresentCleanup: ["Delete \(markerURL.path)"], statusAbsentCleanup: ["No artifact"],
            removeDryRunMessage: { exists in "Dry-run: would delete FaceTime camera dual-use plan (exists=\(exists))" },
            removeSuccessMessage: { exists in "Removed FaceTime camera dual-use plan (wasPresent=\(exists))" },
            removeSteps: ["Delete \(markerURL.path)"], removeCleanup: ["No system mutations expected"]
        )
        return try LabMarkerLifecycle.runFileMarker(
            actionId: Self.id, operation: request.operation, markerURL: markerURL,
            body: body, contextDryRun: context.dryRun, copy: copy
        )
    }
    public static func resolveLabRoot(params: [String: String]) -> URL { LabPaths.resolveLabRoot(params: params) }
}
