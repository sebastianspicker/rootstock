import Foundation
import RootstockCore

/// Lab HomeKit path plane review plan - documentation only.
public struct HomekitPathPlanePlanLabAction: LabAction {
    public static let id = "lab.surface.homekit_path_plane_plan"
    public static let consent = ConsentPolicy.labDefault
    public static let riskClass = RiskClass.labOnly
    public init() {}
    public func run(request: LabActionRequest, context: EvaluationContext) async throws -> ActionResult {
        try SafetyRails.ensureLabConsent(context: context, policy: Self.consent)
        let labRoot = LabPaths.resolveLabRoot(params: request.parameters)
        let focus = request.parameters["focus"] ?? "HomeKit path plane"
        let markerURL = labRoot.appendingPathComponent("homekit_path_plane-plan", isDirectory: true)
            .appendingPathComponent("homekit_path_plane-plan.md")
        let body = """
        # rootstock-red-lab HomeKit path plane plan
        focus: \(focus)
        purpose: HomeKit residual path plane posture documentation
        rules:
        - document path/meta inventory only under consent
        - never enumerates HomeKit accessory secrets or pairs devices
        - purple: validate expected telemetry under ROE only
        ROOTSTOCK_RED_LAB_WAVE16_HOMEKIT_PATH_PLANE=1
        """
        let copy = FileMarkerCopy(
            planMessage: "Dry-run HomeKit path plane plan for focus [\(focus)]: would write plan at \(markerURL.path). never enumerates HomeKit accessory secrets or pairs devices.",
            planSteps: [
                "Document HomeKit path plane review for: \(focus)",
                "Note path/meta inventory without host mutation beyond lab root",
                "Write markdown plan under lab root only",
                "Purple: validate expected telemetry under ROE only",
            ],
            planCleanup: ["Delete \(markerURL.path)"],
            applyDryRunMessage: "Dry-run: would write HomeKit path plane plan at \(markerURL.path)",
            applySuccessMessage: "Wrote HomeKit path plane plan at \(markerURL.path)",
            applySteps: ["Write HomeKit path plane plan"], applyCleanup: ["Delete \(markerURL.path)"],
            presentMessage: "HomeKit path plane plan present", absentMessage: "HomeKit path plane plan absent",
            statusPresentCleanup: ["Delete \(markerURL.path)"], statusAbsentCleanup: ["No artifact"],
            removeDryRunMessage: { exists in "Dry-run: would delete HomeKit path plane plan (exists=\(exists))" },
            removeSuccessMessage: { exists in "Removed HomeKit path plane plan (wasPresent=\(exists))" },
            removeSteps: ["Delete \(markerURL.path)"], removeCleanup: ["No system mutations expected"]
        )
        return try LabMarkerLifecycle.runFileMarker(
            actionId: Self.id, operation: request.operation, markerURL: markerURL,
            body: body, contextDryRun: context.dryRun, copy: copy
        )
    }
    public static func resolveLabRoot(params: [String: String]) -> URL { LabPaths.resolveLabRoot(params: params) }
}
