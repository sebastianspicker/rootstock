import Foundation
import RootstockCore

/// Lab Software Update catalog review plan - documentation only.
public struct SoftwareupdateCatalogPlanLabAction: LabAction {
    public static let id = "lab.surface.softwareupdate_catalog_plan"
    public static let consent = ConsentPolicy.labDefault
    public static let riskClass = RiskClass.labOnly
    public init() {}
    public func run(request: LabActionRequest, context: EvaluationContext) async throws -> ActionResult {
        try SafetyRails.ensureLabConsent(context: context, policy: Self.consent)
        let labRoot = LabPaths.resolveLabRoot(params: request.parameters)
        let focus = request.parameters["focus"] ?? "Software Update catalog"
        let markerURL = labRoot.appendingPathComponent("softwareupdate_catalog-plan", isDirectory: true)
            .appendingPathComponent("softwareupdate_catalog-plan.md")
        let body = """
        # rootstock-red-lab Software Update catalog plan
        focus: \(focus)
        purpose: Software Update catalog residual surface posture documentation
        rules:
        - document path/meta inventory only under consent
        - never points SUS catalogs at attacker mirrors or tampers with update plists
        - purple: validate expected telemetry under ROE only
        ROOTSTOCK_RED_LAB_WAVE16_SOFTWAREUPDATE_CATALOG=1
        """
        let copy = FileMarkerCopy(
            planMessage: "Dry-run Software Update catalog plan for focus [\(focus)]: would write plan at \(markerURL.path). never points SUS catalogs at attacker mirrors or tampers with update plists.",
            planSteps: [
                "Document Software Update catalog review for: \(focus)",
                "Note path/meta inventory without host mutation beyond lab root",
                "Write markdown plan under lab root only",
                "Purple: validate expected telemetry under ROE only",
            ],
            planCleanup: ["Delete \(markerURL.path)"],
            applyDryRunMessage: "Dry-run: would write Software Update catalog plan at \(markerURL.path)",
            applySuccessMessage: "Wrote Software Update catalog plan at \(markerURL.path)",
            applySteps: ["Write Software Update catalog plan"], applyCleanup: ["Delete \(markerURL.path)"],
            presentMessage: "Software Update catalog plan present", absentMessage: "Software Update catalog plan absent",
            statusPresentCleanup: ["Delete \(markerURL.path)"], statusAbsentCleanup: ["No artifact"],
            removeDryRunMessage: { exists in "Dry-run: would delete Software Update catalog plan (exists=\(exists))" },
            removeSuccessMessage: { exists in "Removed Software Update catalog plan (wasPresent=\(exists))" },
            removeSteps: ["Delete \(markerURL.path)"], removeCleanup: ["No system mutations expected"]
        )
        return try LabMarkerLifecycle.runFileMarker(
            actionId: Self.id, operation: request.operation, markerURL: markerURL,
            body: body, contextDryRun: context.dryRun, copy: copy
        )
    }
    public static func resolveLabRoot(params: [String: String]) -> URL { LabPaths.resolveLabRoot(params: params) }
}
