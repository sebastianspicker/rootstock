import Foundation
import RootstockCore

/// Lab Python runtime dual-use review plan - documentation only.
public struct PythonRuntimeDualusePlanLabAction: LabAction {
    public static let id = "lab.surface.python_runtime_dualuse_plan"
    public static let consent = ConsentPolicy.labDefault
    public static let riskClass = RiskClass.labOnly
    public init() {}
    public func run(request: LabActionRequest, context: EvaluationContext) async throws -> ActionResult {
        try SafetyRails.ensureLabConsent(context: context, policy: Self.consent)
        let labRoot = LabPaths.resolveLabRoot(params: request.parameters)
        let focus = request.parameters["focus"] ?? "Python runtime dual-use"
        let markerURL = labRoot.appendingPathComponent("python_runtime_dualuse-plan", isDirectory: true)
            .appendingPathComponent("python_runtime_dualuse-plan.md")
        let body = """
        # rootstock-red-lab Python runtime dual-use plan
        focus: \(focus)
        purpose: Python runtime dual-use residual surface posture documentation
        rules:
        - document path/meta inventory only under consent
        - never executes third-party Python payloads or drops malicious site-packages
        - purple: validate expected telemetry under ROE only
        ROOTSTOCK_RED_LAB_WAVE15_PYTHON_RUNTIME_DUALUSE=1
        """
        let copy = FileMarkerCopy(
            planMessage: "Dry-run Python runtime dual-use plan for focus [\(focus)]: would write plan at \(markerURL.path). never executes third-party Python payloads or drops malicious site-packages.",
            planSteps: [
                "Document Python runtime dual-use review for: \(focus)",
                "Note path/meta inventory without host mutation beyond lab root",
                "Write markdown plan under lab root only",
                "Purple: validate expected telemetry under ROE only",
            ],
            planCleanup: ["Delete \(markerURL.path)"],
            applyDryRunMessage: "Dry-run: would write Python runtime dual-use plan at \(markerURL.path)",
            applySuccessMessage: "Wrote Python runtime dual-use plan at \(markerURL.path)",
            applySteps: ["Write Python runtime dual-use plan"], applyCleanup: ["Delete \(markerURL.path)"],
            presentMessage: "Python runtime dual-use plan present", absentMessage: "Python runtime dual-use plan absent",
            statusPresentCleanup: ["Delete \(markerURL.path)"], statusAbsentCleanup: ["No artifact"],
            removeDryRunMessage: { exists in "Dry-run: would delete Python runtime dual-use plan (exists=\(exists))" },
            removeSuccessMessage: { exists in "Removed Python runtime dual-use plan (wasPresent=\(exists))" },
            removeSteps: ["Delete \(markerURL.path)"], removeCleanup: ["No system mutations expected"]
        )
        return try LabMarkerLifecycle.runFileMarker(
            actionId: Self.id, operation: request.operation, markerURL: markerURL,
            body: body, contextDryRun: context.dryRun, copy: copy
        )
    }
    public static func resolveLabRoot(params: [String: String]) -> URL { LabPaths.resolveLabRoot(params: params) }
}
