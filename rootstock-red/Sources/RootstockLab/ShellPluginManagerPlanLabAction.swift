import Foundation
import RootstockCore

/// Lab Shell plugin manager dual-use review plan - documentation only.
public struct ShellPluginManagerPlanLabAction: LabAction {
    public static let id = "lab.surface.shell_plugin_manager_plan"
    public static let consent = ConsentPolicy.labDefault
    public static let riskClass = RiskClass.labOnly
    public init() {}
    public func run(request: LabActionRequest, context: EvaluationContext) async throws -> ActionResult {
        try SafetyRails.ensureLabConsent(context: context, policy: Self.consent)
        let labRoot = LabPaths.resolveLabRoot(params: request.parameters)
        let focus = request.parameters["focus"] ?? "Shell plugin manager dual-use"
        let markerURL = labRoot.appendingPathComponent("shell_plugin_manager-plan", isDirectory: true)
            .appendingPathComponent("shell_plugin_manager-plan.md")
        let body = """
        # rootstock-red-lab Shell plugin manager dual-use plan
        focus: \(focus)
        purpose: Shell plugin manager dual-use residual posture documentation
        rules:
        - document path/meta inventory only under consent
        - never installs oh-my-zsh plugins or rewrites shell init for persistence
        - purple: validate expected telemetry under ROE only
        ROOTSTOCK_RED_LAB_WAVE15_SHELL_PLUGIN_MANAGER=1
        """
        let copy = FileMarkerCopy(
            planMessage: "Dry-run Shell plugin manager dual-use plan for focus [\(focus)]: would write plan at \(markerURL.path). never installs oh-my-zsh plugins or rewrites shell init for persistence.",
            planSteps: [
                "Document Shell plugin manager dual-use review for: \(focus)",
                "Note path/meta inventory without host mutation beyond lab root",
                "Write markdown plan under lab root only",
                "Purple: validate expected telemetry under ROE only",
            ],
            planCleanup: ["Delete \(markerURL.path)"],
            applyDryRunMessage: "Dry-run: would write Shell plugin manager dual-use plan at \(markerURL.path)",
            applySuccessMessage: "Wrote Shell plugin manager dual-use plan at \(markerURL.path)",
            applySteps: ["Write Shell plugin manager dual-use plan"], applyCleanup: ["Delete \(markerURL.path)"],
            presentMessage: "Shell plugin manager dual-use plan present", absentMessage: "Shell plugin manager dual-use plan absent",
            statusPresentCleanup: ["Delete \(markerURL.path)"], statusAbsentCleanup: ["No artifact"],
            removeDryRunMessage: { exists in "Dry-run: would delete Shell plugin manager dual-use plan (exists=\(exists))" },
            removeSuccessMessage: { exists in "Removed Shell plugin manager dual-use plan (wasPresent=\(exists))" },
            removeSteps: ["Delete \(markerURL.path)"], removeCleanup: ["No system mutations expected"]
        )
        return try LabMarkerLifecycle.runFileMarker(
            actionId: Self.id, operation: request.operation, markerURL: markerURL,
            body: body, contextDryRun: context.dryRun, copy: copy
        )
    }
    public static func resolveLabRoot(params: [String: String]) -> URL { LabPaths.resolveLabRoot(params: params) }
}
