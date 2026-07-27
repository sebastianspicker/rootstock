import Foundation
import RootstockCore

/// Lab File Provider domain review plan - documentation only.
public struct FileproviderDomainPlanLabAction: LabAction {
    public static let id = "lab.surface.fileprovider_domain_plan"
    public static let consent = ConsentPolicy.labDefault
    public static let riskClass = RiskClass.labOnly
    public init() {}
    public func run(request: LabActionRequest, context: EvaluationContext) async throws -> ActionResult {
        try SafetyRails.ensureLabConsent(context: context, policy: Self.consent)
        let labRoot = LabPaths.resolveLabRoot(params: request.parameters)
        let focus = request.parameters["focus"] ?? "File Provider domain"
        let markerURL = labRoot.appendingPathComponent("fileprovider_domain-plan", isDirectory: true)
            .appendingPathComponent("fileprovider_domain-plan.md")
        let body = """
        # rootstock-red-lab File Provider domain plan
        focus: \(focus)
        purpose: File Provider domain residual surface posture documentation
        rules:
        - document path/meta inventory only under consent
        - never registers malicious File Provider domains or exfiltrates provider caches
        - purple: validate expected telemetry under ROE only
        ROOTSTOCK_RED_LAB_WAVE16_FILEPROVIDER_DOMAIN=1
        """
        let copy = FileMarkerCopy(
            planMessage: "Dry-run File Provider domain plan for focus [\(focus)]: would write plan at \(markerURL.path). never registers malicious File Provider domains or exfiltrates provider caches.",
            planSteps: [
                "Document File Provider domain review for: \(focus)",
                "Note path/meta inventory without host mutation beyond lab root",
                "Write markdown plan under lab root only",
                "Purple: validate expected telemetry under ROE only",
            ],
            planCleanup: ["Delete \(markerURL.path)"],
            applyDryRunMessage: "Dry-run: would write File Provider domain plan at \(markerURL.path)",
            applySuccessMessage: "Wrote File Provider domain plan at \(markerURL.path)",
            applySteps: ["Write File Provider domain plan"], applyCleanup: ["Delete \(markerURL.path)"],
            presentMessage: "File Provider domain plan present", absentMessage: "File Provider domain plan absent",
            statusPresentCleanup: ["Delete \(markerURL.path)"], statusAbsentCleanup: ["No artifact"],
            removeDryRunMessage: { exists in "Dry-run: would delete File Provider domain plan (exists=\(exists))" },
            removeSuccessMessage: { exists in "Removed File Provider domain plan (wasPresent=\(exists))" },
            removeSteps: ["Delete \(markerURL.path)"], removeCleanup: ["No system mutations expected"]
        )
        return try LabMarkerLifecycle.runFileMarker(
            actionId: Self.id, operation: request.operation, markerURL: markerURL,
            body: body, contextDryRun: context.dryRun, copy: copy
        )
    }
    public static func resolveLabRoot(params: [String: String]) -> URL { LabPaths.resolveLabRoot(params: params) }
}
