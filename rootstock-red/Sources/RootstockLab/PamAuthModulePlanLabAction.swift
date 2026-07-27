import Foundation
import RootstockCore

/// Lab PAM auth module surface review plan - documentation only.
public struct PamAuthModulePlanLabAction: LabAction {
    public static let id = "lab.surface.pam_auth_module_plan"
    public static let consent = ConsentPolicy.labDefault
    public static let riskClass = RiskClass.labOnly
    public init() {}
    public func run(request: LabActionRequest, context: EvaluationContext) async throws -> ActionResult {
        try SafetyRails.ensureLabConsent(context: context, policy: Self.consent)
        let labRoot = LabPaths.resolveLabRoot(params: request.parameters)
        let focus = request.parameters["focus"] ?? "PAM auth module surface"
        let markerURL = labRoot.appendingPathComponent("pam_auth_module-plan", isDirectory: true)
            .appendingPathComponent("pam_auth_module-plan.md")
        let body = """
        # rootstock-red-lab PAM auth module surface plan
        focus: \(focus)
        purpose: PAM authentication module residual surface posture documentation
        rules:
        - document path/meta inventory only under consent
        - never installs PAM modules or modifies /etc/pam.d
        - purple: validate expected telemetry under ROE only
        ROOTSTOCK_RED_LAB_WAVE14_PAM_AUTH_MODULE=1
        """
        let copy = FileMarkerCopy(
            planMessage: "Dry-run PAM auth module surface plan for focus [\(focus)]: would write plan at \(markerURL.path). never installs PAM modules or modifies /etc/pam.d.",
            planSteps: [
                "Document PAM auth module surface review for: \(focus)",
                "Note path/meta inventory without host mutation beyond lab root",
                "Write markdown plan under lab root only",
                "Purple: validate expected telemetry under ROE only",
            ],
            planCleanup: ["Delete \(markerURL.path)"],
            applyDryRunMessage: "Dry-run: would write PAM auth module surface plan at \(markerURL.path)",
            applySuccessMessage: "Wrote PAM auth module surface plan at \(markerURL.path)",
            applySteps: ["Write PAM auth module surface plan"], applyCleanup: ["Delete \(markerURL.path)"],
            presentMessage: "PAM auth module surface plan present", absentMessage: "PAM auth module surface plan absent",
            statusPresentCleanup: ["Delete \(markerURL.path)"], statusAbsentCleanup: ["No artifact"],
            removeDryRunMessage: { exists in "Dry-run: would delete PAM auth module surface plan (exists=\(exists))" },
            removeSuccessMessage: { exists in "Removed PAM auth module surface plan (wasPresent=\(exists))" },
            removeSteps: ["Delete \(markerURL.path)"], removeCleanup: ["No system mutations expected"]
        )
        return try LabMarkerLifecycle.runFileMarker(
            actionId: Self.id, operation: request.operation, markerURL: markerURL,
            body: body, contextDryRun: context.dryRun, copy: copy
        )
    }
    public static func resolveLabRoot(params: [String: String]) -> URL { LabPaths.resolveLabRoot(params: params) }
}
