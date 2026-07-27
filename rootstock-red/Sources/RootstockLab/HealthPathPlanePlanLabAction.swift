import Foundation
import RootstockCore

/// Lab Health path plane review plan - documentation only.
public struct HealthPathPlanePlanLabAction: LabAction {
    public static let id = "lab.surface.health_path_plane_plan"
    public static let consent = ConsentPolicy.labDefault
    public static let riskClass = RiskClass.labOnly
    public init() {}
    public func run(request: LabActionRequest, context: EvaluationContext) async throws -> ActionResult {
        try SafetyRails.ensureLabConsent(context: context, policy: Self.consent)
        let labRoot = LabPaths.resolveLabRoot(params: request.parameters)
        let focus = request.parameters["focus"] ?? "Health path plane"
        let markerURL = labRoot.appendingPathComponent("health_path_plane-plan", isDirectory: true)
            .appendingPathComponent("health_path_plane-plan.md")
        let body = """
        # rootstock-red-lab Health path plane plan
        focus: \(focus)
        purpose: Health app residual path plane posture documentation
        rules:
        - document path/meta inventory only under consent
        - never exports HealthKit samples or medical records
        - purple: validate expected telemetry under ROE only
        ROOTSTOCK_RED_LAB_WAVE16_HEALTH_PATH_PLANE=1
        """
        let copy = FileMarkerCopy(
            planMessage: "Dry-run Health path plane plan for focus [\(focus)]: would write plan at \(markerURL.path). never exports HealthKit samples or medical records.",
            planSteps: [
                "Document Health path plane review for: \(focus)",
                "Note path/meta inventory without host mutation beyond lab root",
                "Write markdown plan under lab root only",
                "Purple: validate expected telemetry under ROE only",
            ],
            planCleanup: ["Delete \(markerURL.path)"],
            applyDryRunMessage: "Dry-run: would write Health path plane plan at \(markerURL.path)",
            applySuccessMessage: "Wrote Health path plane plan at \(markerURL.path)",
            applySteps: ["Write Health path plane plan"], applyCleanup: ["Delete \(markerURL.path)"],
            presentMessage: "Health path plane plan present", absentMessage: "Health path plane plan absent",
            statusPresentCleanup: ["Delete \(markerURL.path)"], statusAbsentCleanup: ["No artifact"],
            removeDryRunMessage: { exists in "Dry-run: would delete Health path plane plan (exists=\(exists))" },
            removeSuccessMessage: { exists in "Removed Health path plane plan (wasPresent=\(exists))" },
            removeSteps: ["Delete \(markerURL.path)"], removeCleanup: ["No system mutations expected"]
        )
        return try LabMarkerLifecycle.runFileMarker(
            actionId: Self.id, operation: request.operation, markerURL: markerURL,
            body: body, contextDryRun: context.dryRun, copy: copy
        )
    }
    public static func resolveLabRoot(params: [String: String]) -> URL { LabPaths.resolveLabRoot(params: params) }
}
