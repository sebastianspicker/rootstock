import Foundation
import RootstockCore

/// Lab Mail rules automation review plan - documentation only.
public struct MailRulesAutomationPlanLabAction: LabAction {
    public static let id = "lab.surface.mail_rules_automation_plan"
    public static let consent = ConsentPolicy.labDefault
    public static let riskClass = RiskClass.labOnly

    public init() {}

    public func run(
        request: LabActionRequest,
        context: EvaluationContext
    ) async throws -> ActionResult {

        try SafetyRails.ensureLabConsent(context: context, policy: Self.consent)
        let labRoot = LabPaths.resolveLabRoot(params: request.parameters)
        let focus = request.parameters["focus"] ?? "Mail rules automation"
        let markerURL = labRoot
            .appendingPathComponent("mail_rules-plan", isDirectory: true)
            .appendingPathComponent("mail_rules-plan.md")
        let body = """
        # rootstock-red-lab Mail rules automation plan
        focus: \(focus)
        purpose: Mail rules / Apple Mail automation persistence posture documentation
        rules:
        - document path/meta inventory only under consent
        - never reads Mail contents or modifies user Mail rules
        - purple: validate expected telemetry under ROE only
        ROOTSTOCK_RED_LAB_WAVE12_MAIL_RULES=1
        """
        let copy = FileMarkerCopy(
            planMessage: """
            Dry-run Mail rules automation plan for focus [\(focus)]: would write plan at             \(markerURL.path). never reads Mail contents or modifies user Mail rules.
            """,
            planSteps: [
                "Document Mail rules automation review for: \(focus)",
                "Note path/meta inventory without host mutation beyond lab root",
                "Write markdown plan under lab root only",
                "Purple: validate expected telemetry under ROE only",
            ],
            planCleanup: ["Delete \(markerURL.path)"],
            applyDryRunMessage: "Dry-run: would write Mail rules automation plan at \(markerURL.path)",
            applySuccessMessage: "Wrote Mail rules automation plan at \(markerURL.path)",
            applySteps: ["Write Mail rules automation plan"],
            applyCleanup: ["Delete \(markerURL.path)"],
            presentMessage: "Mail rules automation plan present",
            absentMessage: "Mail rules automation plan absent",
            statusPresentCleanup: ["Delete \(markerURL.path)"],
            statusAbsentCleanup: ["No artifact"],
            removeDryRunMessage: { exists in "Dry-run: would delete Mail rules automation plan (exists=\(exists))" },
            removeSuccessMessage: { exists in "Removed Mail rules automation plan (wasPresent=\(exists))" },
            removeSteps: ["Delete \(markerURL.path)"],
            removeCleanup: ["No system mutations expected"]
        )
        return try LabMarkerLifecycle.runFileMarker(
            actionId: Self.id,
            operation: request.operation,
            markerURL: markerURL,
            body: body,
            contextDryRun: context.dryRun,
            copy: copy
        )
    }

    public static func resolveLabRoot(params: [String: String]) -> URL {
        LabPaths.resolveLabRoot(params: params)
    }
}
