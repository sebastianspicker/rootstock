import Foundation
import RootstockCore

/// Lab Keychain ACL path plane review plan - documentation only.
public struct KeychainAclPathPlanLabAction: LabAction {
    public static let id = "lab.surface.keychain_acl_path_plan"
    public static let consent = ConsentPolicy.labDefault
    public static let riskClass = RiskClass.labOnly
    public init() {}
    public func run(request: LabActionRequest, context: EvaluationContext) async throws -> ActionResult {
        try SafetyRails.ensureLabConsent(context: context, policy: Self.consent)
        let labRoot = LabPaths.resolveLabRoot(params: request.parameters)
        let focus = request.parameters["focus"] ?? "Keychain ACL path plane"
        let markerURL = labRoot.appendingPathComponent("keychain_acl_path-plan", isDirectory: true)
            .appendingPathComponent("keychain_acl_path-plan.md")
        let body = """
        # rootstock-red-lab Keychain ACL path plane plan
        focus: \(focus)
        purpose: Keychain ACL path residual surface posture documentation
        rules:
        - document path/meta inventory only under consent
        - never dumps keychain items, passwords, or private keys
        - purple: validate expected telemetry under ROE only
        ROOTSTOCK_RED_LAB_WAVE15_KEYCHAIN_ACL_PATH=1
        """
        let copy = FileMarkerCopy(
            planMessage: "Dry-run Keychain ACL path plane plan for focus [\(focus)]: would write plan at \(markerURL.path). never dumps keychain items, passwords, or private keys.",
            planSteps: [
                "Document Keychain ACL path plane review for: \(focus)",
                "Note path/meta inventory without host mutation beyond lab root",
                "Write markdown plan under lab root only",
                "Purple: validate expected telemetry under ROE only",
            ],
            planCleanup: ["Delete \(markerURL.path)"],
            applyDryRunMessage: "Dry-run: would write Keychain ACL path plane plan at \(markerURL.path)",
            applySuccessMessage: "Wrote Keychain ACL path plane plan at \(markerURL.path)",
            applySteps: ["Write Keychain ACL path plane plan"], applyCleanup: ["Delete \(markerURL.path)"],
            presentMessage: "Keychain ACL path plane plan present", absentMessage: "Keychain ACL path plane plan absent",
            statusPresentCleanup: ["Delete \(markerURL.path)"], statusAbsentCleanup: ["No artifact"],
            removeDryRunMessage: { exists in "Dry-run: would delete Keychain ACL path plane plan (exists=\(exists))" },
            removeSuccessMessage: { exists in "Removed Keychain ACL path plane plan (wasPresent=\(exists))" },
            removeSteps: ["Delete \(markerURL.path)"], removeCleanup: ["No system mutations expected"]
        )
        return try LabMarkerLifecycle.runFileMarker(
            actionId: Self.id, operation: request.operation, markerURL: markerURL,
            body: body, contextDryRun: context.dryRun, copy: copy
        )
    }
    public static func resolveLabRoot(params: [String: String]) -> URL { LabPaths.resolveLabRoot(params: params) }
}
