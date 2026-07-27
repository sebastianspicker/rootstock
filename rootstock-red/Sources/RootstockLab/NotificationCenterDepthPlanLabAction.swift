import Foundation
import RootstockCore

/// Lab Notification Center depth review plan - documentation only.
public struct NotificationCenterDepthPlanLabAction: LabAction {
    public static let id = "lab.surface.notification_center_depth_plan"
    public static let consent = ConsentPolicy.labDefault
    public static let riskClass = RiskClass.labOnly
    public init() {}
    public func run(request: LabActionRequest, context: EvaluationContext) async throws -> ActionResult {
        try SafetyRails.ensureLabConsent(context: context, policy: Self.consent)
        let labRoot = LabPaths.resolveLabRoot(params: request.parameters)
        let focus = request.parameters["focus"] ?? "Notification Center depth"
        let markerURL = labRoot.appendingPathComponent("notification_center_depth-plan", isDirectory: true)
            .appendingPathComponent("notification_center_depth-plan.md")
        let body = """
        # rootstock-red-lab Notification Center depth plan
        focus: \(focus)
        purpose: Notification Center residual depth posture documentation
        rules:
        - document path/meta inventory only under consent
        - never dumps notification body contents or forges notification payloads
        - purple: validate expected telemetry under ROE only
        ROOTSTOCK_RED_LAB_WAVE16_NOTIFICATION_CENTER_DEPTH=1
        """
        let copy = FileMarkerCopy(
            planMessage: "Dry-run Notification Center depth plan for focus [\(focus)]: would write plan at \(markerURL.path). never dumps notification body contents or forges notification payloads.",
            planSteps: [
                "Document Notification Center depth review for: \(focus)",
                "Note path/meta inventory without host mutation beyond lab root",
                "Write markdown plan under lab root only",
                "Purple: validate expected telemetry under ROE only",
            ],
            planCleanup: ["Delete \(markerURL.path)"],
            applyDryRunMessage: "Dry-run: would write Notification Center depth plan at \(markerURL.path)",
            applySuccessMessage: "Wrote Notification Center depth plan at \(markerURL.path)",
            applySteps: ["Write Notification Center depth plan"], applyCleanup: ["Delete \(markerURL.path)"],
            presentMessage: "Notification Center depth plan present", absentMessage: "Notification Center depth plan absent",
            statusPresentCleanup: ["Delete \(markerURL.path)"], statusAbsentCleanup: ["No artifact"],
            removeDryRunMessage: { exists in "Dry-run: would delete Notification Center depth plan (exists=\(exists))" },
            removeSuccessMessage: { exists in "Removed Notification Center depth plan (wasPresent=\(exists))" },
            removeSteps: ["Delete \(markerURL.path)"], removeCleanup: ["No system mutations expected"]
        )
        return try LabMarkerLifecycle.runFileMarker(
            actionId: Self.id, operation: request.operation, markerURL: markerURL,
            body: body, contextDryRun: context.dryRun, copy: copy
        )
    }
    public static func resolveLabRoot(params: [String: String]) -> URL { LabPaths.resolveLabRoot(params: params) }
}
