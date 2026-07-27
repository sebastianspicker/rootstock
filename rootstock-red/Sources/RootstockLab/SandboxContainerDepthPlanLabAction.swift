import Foundation
import RootstockCore

/// Lab Sandbox container depth review plan - documentation only.
public struct SandboxContainerDepthPlanLabAction: LabAction {
    public static let id = "lab.surface.sandbox_container_depth_plan"
    public static let consent = ConsentPolicy.labDefault
    public static let riskClass = RiskClass.labOnly
    public init() {}
    public func run(request: LabActionRequest, context: EvaluationContext) async throws -> ActionResult {
        try SafetyRails.ensureLabConsent(context: context, policy: Self.consent)
        let labRoot = LabPaths.resolveLabRoot(params: request.parameters)
        let focus = request.parameters["focus"] ?? "Sandbox container depth"
        let markerURL = labRoot.appendingPathComponent("sandbox_container_depth-plan", isDirectory: true)
            .appendingPathComponent("sandbox_container_depth-plan.md")
        let body = """
        # rootstock-red-lab Sandbox container depth plan
        focus: \(focus)
        purpose: App sandbox container residual depth posture documentation
        rules:
        - document path/meta inventory only under consent
        - never breaks app sandbox or forges container entitlements
        - purple: validate expected telemetry under ROE only
        ROOTSTOCK_RED_LAB_WAVE15_SANDBOX_CONTAINER_DEPTH=1
        """
        let copy = FileMarkerCopy(
            planMessage: "Dry-run Sandbox container depth plan for focus [\(focus)]: would write plan at \(markerURL.path). never breaks app sandbox or forges container entitlements.",
            planSteps: [
                "Document Sandbox container depth review for: \(focus)",
                "Note path/meta inventory without host mutation beyond lab root",
                "Write markdown plan under lab root only",
                "Purple: validate expected telemetry under ROE only",
            ],
            planCleanup: ["Delete \(markerURL.path)"],
            applyDryRunMessage: "Dry-run: would write Sandbox container depth plan at \(markerURL.path)",
            applySuccessMessage: "Wrote Sandbox container depth plan at \(markerURL.path)",
            applySteps: ["Write Sandbox container depth plan"], applyCleanup: ["Delete \(markerURL.path)"],
            presentMessage: "Sandbox container depth plan present", absentMessage: "Sandbox container depth plan absent",
            statusPresentCleanup: ["Delete \(markerURL.path)"], statusAbsentCleanup: ["No artifact"],
            removeDryRunMessage: { exists in "Dry-run: would delete Sandbox container depth plan (exists=\(exists))" },
            removeSuccessMessage: { exists in "Removed Sandbox container depth plan (wasPresent=\(exists))" },
            removeSteps: ["Delete \(markerURL.path)"], removeCleanup: ["No system mutations expected"]
        )
        return try LabMarkerLifecycle.runFileMarker(
            actionId: Self.id, operation: request.operation, markerURL: markerURL,
            body: body, contextDryRun: context.dryRun, copy: copy
        )
    }
    public static func resolveLabRoot(params: [String: String]) -> URL { LabPaths.resolveLabRoot(params: params) }
}
