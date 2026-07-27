import Foundation
import RootstockCore

/// Lab Emond legacy depth review plan - documentation only.
public struct EmondLegacyDepthPlanLabAction: LabAction {
    public static let id = "lab.surface.emond_legacy_depth_plan"
    public static let consent = ConsentPolicy.labDefault
    public static let riskClass = RiskClass.labOnly
    public init() {}
    public func run(request: LabActionRequest, context: EvaluationContext) async throws -> ActionResult {
        try SafetyRails.ensureLabConsent(context: context, policy: Self.consent)
        let labRoot = LabPaths.resolveLabRoot(params: request.parameters)
        let focus = request.parameters["focus"] ?? "Emond legacy depth"
        let markerURL = labRoot.appendingPathComponent("emond_legacy_depth-plan", isDirectory: true)
            .appendingPathComponent("emond_legacy_depth-plan.md")
        let body = """
        # rootstock-red-lab Emond legacy depth plan
        focus: \(focus)
        purpose: Emond legacy rules residual depth posture documentation
        rules:
        - document path/meta inventory only under consent
        - never installs emond rules or enables the legacy event monitor daemon
        - purple: validate expected telemetry under ROE only
        ROOTSTOCK_RED_LAB_WAVE15_EMOND_LEGACY_DEPTH=1
        """
        let copy = FileMarkerCopy(
            planMessage: "Dry-run Emond legacy depth plan for focus [\(focus)]: would write plan at \(markerURL.path). never installs emond rules or enables the legacy event monitor daemon.",
            planSteps: [
                "Document Emond legacy depth review for: \(focus)",
                "Note path/meta inventory without host mutation beyond lab root",
                "Write markdown plan under lab root only",
                "Purple: validate expected telemetry under ROE only",
            ],
            planCleanup: ["Delete \(markerURL.path)"],
            applyDryRunMessage: "Dry-run: would write Emond legacy depth plan at \(markerURL.path)",
            applySuccessMessage: "Wrote Emond legacy depth plan at \(markerURL.path)",
            applySteps: ["Write Emond legacy depth plan"], applyCleanup: ["Delete \(markerURL.path)"],
            presentMessage: "Emond legacy depth plan present", absentMessage: "Emond legacy depth plan absent",
            statusPresentCleanup: ["Delete \(markerURL.path)"], statusAbsentCleanup: ["No artifact"],
            removeDryRunMessage: { exists in "Dry-run: would delete Emond legacy depth plan (exists=\(exists))" },
            removeSuccessMessage: { exists in "Removed Emond legacy depth plan (wasPresent=\(exists))" },
            removeSteps: ["Delete \(markerURL.path)"], removeCleanup: ["No system mutations expected"]
        )
        return try LabMarkerLifecycle.runFileMarker(
            actionId: Self.id, operation: request.operation, markerURL: markerURL,
            body: body, contextDryRun: context.dryRun, copy: copy
        )
    }
    public static func resolveLabRoot(params: [String: String]) -> URL { LabPaths.resolveLabRoot(params: params) }
}
