import Foundation
import RootstockCore

/// Lab Font validation dual-use review plan - documentation only.
public struct FontValidationDualusePlanLabAction: LabAction {
    public static let id = "lab.surface.font_validation_dualuse_plan"
    public static let consent = ConsentPolicy.labDefault
    public static let riskClass = RiskClass.labOnly
    public init() {}
    public func run(request: LabActionRequest, context: EvaluationContext) async throws -> ActionResult {
        try SafetyRails.ensureLabConsent(context: context, policy: Self.consent)
        let labRoot = LabPaths.resolveLabRoot(params: request.parameters)
        let focus = request.parameters["focus"] ?? "Font validation dual-use"
        let markerURL = labRoot.appendingPathComponent("font_validation_dualuse-plan", isDirectory: true)
            .appendingPathComponent("font_validation_dualuse-plan.md")
        let body = """
        # rootstock-red-lab Font validation dual-use plan
        focus: \(focus)
        purpose: Font validation / ATS dual-use surface posture documentation
        rules:
        - document path/meta inventory only under consent
        - never installs malicious fonts or disables font validation
        - purple: validate expected telemetry under ROE only
        ROOTSTOCK_RED_LAB_WAVE14_FONT_VALIDATION_DUALUSE=1
        """
        let copy = FileMarkerCopy(
            planMessage: "Dry-run Font validation dual-use plan for focus [\(focus)]: would write plan at \(markerURL.path). never installs malicious fonts or disables font validation.",
            planSteps: [
                "Document Font validation dual-use review for: \(focus)",
                "Note path/meta inventory without host mutation beyond lab root",
                "Write markdown plan under lab root only",
                "Purple: validate expected telemetry under ROE only",
            ],
            planCleanup: ["Delete \(markerURL.path)"],
            applyDryRunMessage: "Dry-run: would write Font validation dual-use plan at \(markerURL.path)",
            applySuccessMessage: "Wrote Font validation dual-use plan at \(markerURL.path)",
            applySteps: ["Write Font validation dual-use plan"], applyCleanup: ["Delete \(markerURL.path)"],
            presentMessage: "Font validation dual-use plan present", absentMessage: "Font validation dual-use plan absent",
            statusPresentCleanup: ["Delete \(markerURL.path)"], statusAbsentCleanup: ["No artifact"],
            removeDryRunMessage: { exists in "Dry-run: would delete Font validation dual-use plan (exists=\(exists))" },
            removeSuccessMessage: { exists in "Removed Font validation dual-use plan (wasPresent=\(exists))" },
            removeSteps: ["Delete \(markerURL.path)"], removeCleanup: ["No system mutations expected"]
        )
        return try LabMarkerLifecycle.runFileMarker(
            actionId: Self.id, operation: request.operation, markerURL: markerURL,
            body: body, contextDryRun: context.dryRun, copy: copy
        )
    }
    public static func resolveLabRoot(params: [String: String]) -> URL { LabPaths.resolveLabRoot(params: params) }
}
