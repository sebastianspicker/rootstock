import Foundation
import RootstockCore

/// Lab CUPS printer dual-use review plan - documentation only.
public struct CupsPrintPlanLabAction: LabAction {
    public static let id = "lab.surface.cups_print_plan"
    public static let consent = ConsentPolicy.labDefault
    public static let riskClass = RiskClass.labOnly
    public init() {}
    public func run(request: LabActionRequest, context: EvaluationContext) async throws -> ActionResult {
        try SafetyRails.ensureLabConsent(context: context, policy: Self.consent)
        let labRoot = LabPaths.resolveLabRoot(params: request.parameters)
        let focus = request.parameters["focus"] ?? "CUPS printer dual-use"
        let markerURL = labRoot.appendingPathComponent("cups_print-plan", isDirectory: true)
            .appendingPathComponent("cups_print-plan.md")
        let body = """
        # rootstock-red-lab CUPS printer dual-use plan
        focus: \(focus)
        purpose: CUPS / printer dual-use residual surface posture documentation
        rules:
        - document path/meta inventory only under consent
        - never submits print jobs or reconfigures CUPS remotely
        - purple: validate expected telemetry under ROE only
        ROOTSTOCK_RED_LAB_WAVE13_CUPS_PRINT=1
        """
        let copy = FileMarkerCopy(
            planMessage: "Dry-run CUPS printer dual-use plan for focus [\(focus)]: would write plan at \(markerURL.path). never submits print jobs or reconfigures CUPS remotely.",
            planSteps: [
                "Document CUPS printer dual-use review for: \(focus)",
                "Note path/meta inventory without host mutation beyond lab root",
                "Write markdown plan under lab root only",
                "Purple: validate expected telemetry under ROE only",
            ],
            planCleanup: ["Delete \(markerURL.path)"],
            applyDryRunMessage: "Dry-run: would write CUPS printer dual-use plan at \(markerURL.path)",
            applySuccessMessage: "Wrote CUPS printer dual-use plan at \(markerURL.path)",
            applySteps: ["Write CUPS printer dual-use plan"],
            applyCleanup: ["Delete \(markerURL.path)"],
            presentMessage: "CUPS printer dual-use plan present",
            absentMessage: "CUPS printer dual-use plan absent",
            statusPresentCleanup: ["Delete \(markerURL.path)"],
            statusAbsentCleanup: ["No artifact"],
            removeDryRunMessage: { exists in "Dry-run: would delete CUPS printer dual-use plan (exists=\(exists))" },
            removeSuccessMessage: { exists in "Removed CUPS printer dual-use plan (wasPresent=\(exists))" },
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
