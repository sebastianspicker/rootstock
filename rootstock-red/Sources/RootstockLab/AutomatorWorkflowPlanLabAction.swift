import Foundation
import RootstockCore

/// Lab Automator workflow delivery review plan - documentation only.
public struct AutomatorWorkflowPlanLabAction: LabAction {
    public static let id = "lab.surface.automator_workflow_plan"
    public static let consent = ConsentPolicy.labDefault
    public static let riskClass = RiskClass.labOnly
    public init() {}
    public func run(request: LabActionRequest, context: EvaluationContext) async throws -> ActionResult {
        try SafetyRails.ensureLabConsent(context: context, policy: Self.consent)
        let labRoot = LabPaths.resolveLabRoot(params: request.parameters)
        let focus = request.parameters["focus"] ?? "Automator workflow delivery"
        let markerURL = labRoot.appendingPathComponent("automator_workflow-plan", isDirectory: true)
            .appendingPathComponent("automator_workflow-plan.md")
        let body = """
        # rootstock-red-lab Automator workflow delivery plan
        focus: \(focus)
        purpose: Automator workflow delivery residual posture documentation
        rules:
        - document path/meta inventory only under consent
        - never executes Automator workflows or plants malicious .workflow bundles
        - purple: validate expected telemetry under ROE only
        ROOTSTOCK_RED_LAB_WAVE14_AUTOMATOR_WORKFLOW=1
        """
        let copy = FileMarkerCopy(
            planMessage: "Dry-run Automator workflow delivery plan for focus [\(focus)]: would write plan at \(markerURL.path). never executes Automator workflows or plants malicious .workflow bundles.",
            planSteps: [
                "Document Automator workflow delivery review for: \(focus)",
                "Note path/meta inventory without host mutation beyond lab root",
                "Write markdown plan under lab root only",
                "Purple: validate expected telemetry under ROE only",
            ],
            planCleanup: ["Delete \(markerURL.path)"],
            applyDryRunMessage: "Dry-run: would write Automator workflow delivery plan at \(markerURL.path)",
            applySuccessMessage: "Wrote Automator workflow delivery plan at \(markerURL.path)",
            applySteps: ["Write Automator workflow delivery plan"], applyCleanup: ["Delete \(markerURL.path)"],
            presentMessage: "Automator workflow delivery plan present", absentMessage: "Automator workflow delivery plan absent",
            statusPresentCleanup: ["Delete \(markerURL.path)"], statusAbsentCleanup: ["No artifact"],
            removeDryRunMessage: { exists in "Dry-run: would delete Automator workflow delivery plan (exists=\(exists))" },
            removeSuccessMessage: { exists in "Removed Automator workflow delivery plan (wasPresent=\(exists))" },
            removeSteps: ["Delete \(markerURL.path)"], removeCleanup: ["No system mutations expected"]
        )
        return try LabMarkerLifecycle.runFileMarker(
            actionId: Self.id, operation: request.operation, markerURL: markerURL,
            body: body, contextDryRun: context.dryRun, copy: copy
        )
    }
    public static func resolveLabRoot(params: [String: String]) -> URL { LabPaths.resolveLabRoot(params: params) }
}
