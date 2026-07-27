import Foundation
import RootstockCore

/// Lab Maps location residual review plan - documentation only.
public struct MapsLocationPathPlanLabAction: LabAction {
    public static let id = "lab.surface.maps_location_path_plan"
    public static let consent = ConsentPolicy.labDefault
    public static let riskClass = RiskClass.labOnly
    public init() {}
    public func run(request: LabActionRequest, context: EvaluationContext) async throws -> ActionResult {
        try SafetyRails.ensureLabConsent(context: context, policy: Self.consent)
        let labRoot = LabPaths.resolveLabRoot(params: request.parameters)
        let focus = request.parameters["focus"] ?? "Maps location residual"
        let markerURL = labRoot.appendingPathComponent("maps_location_path-plan", isDirectory: true)
            .appendingPathComponent("maps_location_path-plan.md")
        let body = """
        # rootstock-red-lab Maps location residual plan
        focus: \(focus)
        purpose: Maps / location services residual plane posture documentation
        rules:
        - document path/meta inventory only under consent
        - never dumps location history or spoofs CoreLocation positions
        - purple: validate expected telemetry under ROE only
        ROOTSTOCK_RED_LAB_WAVE16_MAPS_LOCATION_PATH=1
        """
        let copy = FileMarkerCopy(
            planMessage: "Dry-run Maps location residual plan for focus [\(focus)]: would write plan at \(markerURL.path). never dumps location history or spoofs CoreLocation positions.",
            planSteps: [
                "Document Maps location residual review for: \(focus)",
                "Note path/meta inventory without host mutation beyond lab root",
                "Write markdown plan under lab root only",
                "Purple: validate expected telemetry under ROE only",
            ],
            planCleanup: ["Delete \(markerURL.path)"],
            applyDryRunMessage: "Dry-run: would write Maps location residual plan at \(markerURL.path)",
            applySuccessMessage: "Wrote Maps location residual plan at \(markerURL.path)",
            applySteps: ["Write Maps location residual plan"], applyCleanup: ["Delete \(markerURL.path)"],
            presentMessage: "Maps location residual plan present", absentMessage: "Maps location residual plan absent",
            statusPresentCleanup: ["Delete \(markerURL.path)"], statusAbsentCleanup: ["No artifact"],
            removeDryRunMessage: { exists in "Dry-run: would delete Maps location residual plan (exists=\(exists))" },
            removeSuccessMessage: { exists in "Removed Maps location residual plan (wasPresent=\(exists))" },
            removeSteps: ["Delete \(markerURL.path)"], removeCleanup: ["No system mutations expected"]
        )
        return try LabMarkerLifecycle.runFileMarker(
            actionId: Self.id, operation: request.operation, markerURL: markerURL,
            body: body, contextDryRun: context.dryRun, copy: copy
        )
    }
    public static func resolveLabRoot(params: [String: String]) -> URL { LabPaths.resolveLabRoot(params: params) }
}
