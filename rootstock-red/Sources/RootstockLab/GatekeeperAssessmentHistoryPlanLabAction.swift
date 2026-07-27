import Foundation
import RootstockCore

/// Lab Gatekeeper assessment history review plan - documentation only.
public struct GatekeeperAssessmentHistoryPlanLabAction: LabAction {
    public static let id = "lab.surface.gk_assessment_history_plan"
    public static let consent = ConsentPolicy.labDefault
    public static let riskClass = RiskClass.labOnly
    public init() {}
    public func run(request: LabActionRequest, context: EvaluationContext) async throws -> ActionResult {
        try SafetyRails.ensureLabConsent(context: context, policy: Self.consent)
        let labRoot = LabPaths.resolveLabRoot(params: request.parameters)
        let focus = request.parameters["focus"] ?? "Gatekeeper assessment history"
        let markerURL = labRoot.appendingPathComponent("gk_assessment-plan", isDirectory: true)
            .appendingPathComponent("gk_assessment-plan.md")
        let body = """
        # rootstock-red-lab Gatekeeper assessment history plan
        focus: \(focus)
        purpose: Gatekeeper assessment / syspolicyd history depth posture documentation
        rules:
        - document path/meta inventory only under consent
        - never clears Gatekeeper assessments or disables syspolicyd
        - purple: validate expected telemetry under ROE only
        ROOTSTOCK_RED_LAB_WAVE13_GK_ASSESSMENT=1
        """
        let copy = FileMarkerCopy(
            planMessage: "Dry-run Gatekeeper assessment history plan for focus [\(focus)]: would write plan at \(markerURL.path). never clears Gatekeeper assessments or disables syspolicyd.",
            planSteps: [
                "Document Gatekeeper assessment history review for: \(focus)",
                "Note path/meta inventory without host mutation beyond lab root",
                "Write markdown plan under lab root only",
                "Purple: validate expected telemetry under ROE only",
            ],
            planCleanup: ["Delete \(markerURL.path)"],
            applyDryRunMessage: "Dry-run: would write Gatekeeper assessment history plan at \(markerURL.path)",
            applySuccessMessage: "Wrote Gatekeeper assessment history plan at \(markerURL.path)",
            applySteps: ["Write Gatekeeper assessment history plan"],
            applyCleanup: ["Delete \(markerURL.path)"],
            presentMessage: "Gatekeeper assessment history plan present",
            absentMessage: "Gatekeeper assessment history plan absent",
            statusPresentCleanup: ["Delete \(markerURL.path)"],
            statusAbsentCleanup: ["No artifact"],
            removeDryRunMessage: { exists in "Dry-run: would delete Gatekeeper assessment history plan (exists=\(exists))" },
            removeSuccessMessage: { exists in "Removed Gatekeeper assessment history plan (wasPresent=\(exists))" },
            removeSteps: ["Delete \(markerURL.path)"],
            removeCleanup: ["No system mutations expected"]
        )
        return try LabMarkerLifecycle.runFileMarker(
            actionId: Self.id, operation: request.operation, markerURL: markerURL,
            body: body, contextDryRun: context.dryRun, copy: copy
        )
    }
    public static func resolveLabRoot(params: [String: String]) -> URL { LabPaths.resolveLabRoot(params: params) }
}
