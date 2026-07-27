import Foundation
import RootstockCore

/// Lab Spotlight importer depth review plan - documentation only.
public struct SpotlightImporterDepthPlanLabAction: LabAction {
    public static let id = "lab.surface.spotlight_importer_depth_plan"
    public static let consent = ConsentPolicy.labDefault
    public static let riskClass = RiskClass.labOnly
    public init() {}
    public func run(request: LabActionRequest, context: EvaluationContext) async throws -> ActionResult {
        try SafetyRails.ensureLabConsent(context: context, policy: Self.consent)
        let labRoot = LabPaths.resolveLabRoot(params: request.parameters)
        let focus = request.parameters["focus"] ?? "Spotlight importer depth"
        let markerURL = labRoot.appendingPathComponent("spotlight_importer_depth-plan", isDirectory: true)
            .appendingPathComponent("spotlight_importer_depth-plan.md")
        let body = """
        # rootstock-red-lab Spotlight importer depth plan
        focus: \(focus)
        purpose: Spotlight importer residual depth posture documentation
        rules:
        - document path/meta inventory only under consent
        - never installs malicious Spotlight importers or dumps mdworker index contents
        - purple: validate expected telemetry under ROE only
        ROOTSTOCK_RED_LAB_WAVE16_SPOTLIGHT_IMPORTER_DEPTH=1
        """
        let copy = FileMarkerCopy(
            planMessage: "Dry-run Spotlight importer depth plan for focus [\(focus)]: would write plan at \(markerURL.path). never installs malicious Spotlight importers or dumps mdworker index contents.",
            planSteps: [
                "Document Spotlight importer depth review for: \(focus)",
                "Note path/meta inventory without host mutation beyond lab root",
                "Write markdown plan under lab root only",
                "Purple: validate expected telemetry under ROE only",
            ],
            planCleanup: ["Delete \(markerURL.path)"],
            applyDryRunMessage: "Dry-run: would write Spotlight importer depth plan at \(markerURL.path)",
            applySuccessMessage: "Wrote Spotlight importer depth plan at \(markerURL.path)",
            applySteps: ["Write Spotlight importer depth plan"], applyCleanup: ["Delete \(markerURL.path)"],
            presentMessage: "Spotlight importer depth plan present", absentMessage: "Spotlight importer depth plan absent",
            statusPresentCleanup: ["Delete \(markerURL.path)"], statusAbsentCleanup: ["No artifact"],
            removeDryRunMessage: { exists in "Dry-run: would delete Spotlight importer depth plan (exists=\(exists))" },
            removeSuccessMessage: { exists in "Removed Spotlight importer depth plan (wasPresent=\(exists))" },
            removeSteps: ["Delete \(markerURL.path)"], removeCleanup: ["No system mutations expected"]
        )
        return try LabMarkerLifecycle.runFileMarker(
            actionId: Self.id, operation: request.operation, markerURL: markerURL,
            body: body, contextDryRun: context.dryRun, copy: copy
        )
    }
    public static func resolveLabRoot(params: [String: String]) -> URL { LabPaths.resolveLabRoot(params: params) }
}
