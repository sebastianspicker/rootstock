import Foundation
import RootstockCore

/// Lab Screen Sharing ARD depth review plan - documentation only.
public struct ScreenSharingArdDepthPlanLabAction: LabAction {
    public static let id = "lab.surface.screen_sharing_ard_depth_plan"
    public static let consent = ConsentPolicy.labDefault
    public static let riskClass = RiskClass.labOnly
    public init() {}
    public func run(request: LabActionRequest, context: EvaluationContext) async throws -> ActionResult {
        try SafetyRails.ensureLabConsent(context: context, policy: Self.consent)
        let labRoot = LabPaths.resolveLabRoot(params: request.parameters)
        let focus = request.parameters["focus"] ?? "Screen Sharing ARD depth"
        let markerURL = labRoot.appendingPathComponent("screen_sharing_ard_depth-plan", isDirectory: true)
            .appendingPathComponent("screen_sharing_ard_depth-plan.md")
        let body = """
        # rootstock-red-lab Screen Sharing ARD depth plan
        focus: \(focus)
        purpose: Screen Sharing / ARD residual depth posture documentation
        rules:
        - document path/meta inventory only under consent
        - never enables Screen Sharing or ARD, never connects to remote desktops
        - purple: validate expected telemetry under ROE only
        ROOTSTOCK_RED_LAB_WAVE15_SCREEN_SHARING_ARD_DEPTH=1
        """
        let copy = FileMarkerCopy(
            planMessage: "Dry-run Screen Sharing ARD depth plan for focus [\(focus)]: would write plan at \(markerURL.path). never enables Screen Sharing or ARD, never connects to remote desktops.",
            planSteps: [
                "Document Screen Sharing ARD depth review for: \(focus)",
                "Note path/meta inventory without host mutation beyond lab root",
                "Write markdown plan under lab root only",
                "Purple: validate expected telemetry under ROE only",
            ],
            planCleanup: ["Delete \(markerURL.path)"],
            applyDryRunMessage: "Dry-run: would write Screen Sharing ARD depth plan at \(markerURL.path)",
            applySuccessMessage: "Wrote Screen Sharing ARD depth plan at \(markerURL.path)",
            applySteps: ["Write Screen Sharing ARD depth plan"], applyCleanup: ["Delete \(markerURL.path)"],
            presentMessage: "Screen Sharing ARD depth plan present", absentMessage: "Screen Sharing ARD depth plan absent",
            statusPresentCleanup: ["Delete \(markerURL.path)"], statusAbsentCleanup: ["No artifact"],
            removeDryRunMessage: { exists in "Dry-run: would delete Screen Sharing ARD depth plan (exists=\(exists))" },
            removeSuccessMessage: { exists in "Removed Screen Sharing ARD depth plan (wasPresent=\(exists))" },
            removeSteps: ["Delete \(markerURL.path)"], removeCleanup: ["No system mutations expected"]
        )
        return try LabMarkerLifecycle.runFileMarker(
            actionId: Self.id, operation: request.operation, markerURL: markerURL,
            body: body, contextDryRun: context.dryRun, copy: copy
        )
    }
    public static func resolveLabRoot(params: [String: String]) -> URL { LabPaths.resolveLabRoot(params: params) }
}
