import Foundation
import RootstockCore

/// Lab Wallet pass path review plan - documentation only.
public struct WalletPassPathPlanLabAction: LabAction {
    public static let id = "lab.surface.wallet_pass_path_plan"
    public static let consent = ConsentPolicy.labDefault
    public static let riskClass = RiskClass.labOnly
    public init() {}
    public func run(request: LabActionRequest, context: EvaluationContext) async throws -> ActionResult {
        try SafetyRails.ensureLabConsent(context: context, policy: Self.consent)
        let labRoot = LabPaths.resolveLabRoot(params: request.parameters)
        let focus = request.parameters["focus"] ?? "Wallet pass path"
        let markerURL = labRoot.appendingPathComponent("wallet_pass_path-plan", isDirectory: true)
            .appendingPathComponent("wallet_pass_path-plan.md")
        let body = """
        # rootstock-red-lab Wallet pass path plan
        focus: \(focus)
        purpose: Wallet / pass residual path plane posture documentation
        rules:
        - document path/meta inventory only under consent
        - never dumps pass contents, payment tokens, or card data
        - purple: validate expected telemetry under ROE only
        ROOTSTOCK_RED_LAB_WAVE16_WALLET_PASS_PATH=1
        """
        let copy = FileMarkerCopy(
            planMessage: "Dry-run Wallet pass path plan for focus [\(focus)]: would write plan at \(markerURL.path). never dumps pass contents, payment tokens, or card data.",
            planSteps: [
                "Document Wallet pass path review for: \(focus)",
                "Note path/meta inventory without host mutation beyond lab root",
                "Write markdown plan under lab root only",
                "Purple: validate expected telemetry under ROE only",
            ],
            planCleanup: ["Delete \(markerURL.path)"],
            applyDryRunMessage: "Dry-run: would write Wallet pass path plan at \(markerURL.path)",
            applySuccessMessage: "Wrote Wallet pass path plan at \(markerURL.path)",
            applySteps: ["Write Wallet pass path plan"], applyCleanup: ["Delete \(markerURL.path)"],
            presentMessage: "Wallet pass path plan present", absentMessage: "Wallet pass path plan absent",
            statusPresentCleanup: ["Delete \(markerURL.path)"], statusAbsentCleanup: ["No artifact"],
            removeDryRunMessage: { exists in "Dry-run: would delete Wallet pass path plan (exists=\(exists))" },
            removeSuccessMessage: { exists in "Removed Wallet pass path plan (wasPresent=\(exists))" },
            removeSteps: ["Delete \(markerURL.path)"], removeCleanup: ["No system mutations expected"]
        )
        return try LabMarkerLifecycle.runFileMarker(
            actionId: Self.id, operation: request.operation, markerURL: markerURL,
            body: body, contextDryRun: context.dryRun, copy: copy
        )
    }
    public static func resolveLabRoot(params: [String: String]) -> URL { LabPaths.resolveLabRoot(params: params) }
}
