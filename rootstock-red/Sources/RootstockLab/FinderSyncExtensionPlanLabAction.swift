import Foundation
import RootstockCore

/// Lab Finder Sync dual-use review plan - documentation only.
public struct FinderSyncExtensionPlanLabAction: LabAction {
    public static let id = "lab.surface.finder_sync_extension_plan"
    public static let consent = ConsentPolicy.labDefault
    public static let riskClass = RiskClass.labOnly
    public init() {}
    public func run(request: LabActionRequest, context: EvaluationContext) async throws -> ActionResult {
        try SafetyRails.ensureLabConsent(context: context, policy: Self.consent)
        let labRoot = LabPaths.resolveLabRoot(params: request.parameters)
        let focus = request.parameters["focus"] ?? "Finder Sync dual-use"
        let markerURL = labRoot.appendingPathComponent("finder_sync_extension-plan", isDirectory: true)
            .appendingPathComponent("finder_sync_extension-plan.md")
        let body = """
        # rootstock-red-lab Finder Sync dual-use plan
        focus: \(focus)
        purpose: Finder Sync extension dual-use surface posture documentation
        rules:
        - document path/meta inventory only under consent
        - never installs Finder Sync extensions or rewrites Finder preferences for abuse
        - purple: validate expected telemetry under ROE only
        ROOTSTOCK_RED_LAB_WAVE16_FINDER_SYNC_EXTENSION=1
        """
        let copy = FileMarkerCopy(
            planMessage: "Dry-run Finder Sync dual-use plan for focus [\(focus)]: would write plan at \(markerURL.path). never installs Finder Sync extensions or rewrites Finder preferences for abuse.",
            planSteps: [
                "Document Finder Sync dual-use review for: \(focus)",
                "Note path/meta inventory without host mutation beyond lab root",
                "Write markdown plan under lab root only",
                "Purple: validate expected telemetry under ROE only",
            ],
            planCleanup: ["Delete \(markerURL.path)"],
            applyDryRunMessage: "Dry-run: would write Finder Sync dual-use plan at \(markerURL.path)",
            applySuccessMessage: "Wrote Finder Sync dual-use plan at \(markerURL.path)",
            applySteps: ["Write Finder Sync dual-use plan"], applyCleanup: ["Delete \(markerURL.path)"],
            presentMessage: "Finder Sync dual-use plan present", absentMessage: "Finder Sync dual-use plan absent",
            statusPresentCleanup: ["Delete \(markerURL.path)"], statusAbsentCleanup: ["No artifact"],
            removeDryRunMessage: { exists in "Dry-run: would delete Finder Sync dual-use plan (exists=\(exists))" },
            removeSuccessMessage: { exists in "Removed Finder Sync dual-use plan (wasPresent=\(exists))" },
            removeSteps: ["Delete \(markerURL.path)"], removeCleanup: ["No system mutations expected"]
        )
        return try LabMarkerLifecycle.runFileMarker(
            actionId: Self.id, operation: request.operation, markerURL: markerURL,
            body: body, contextDryRun: context.dryRun, copy: copy
        )
    }
    public static func resolveLabRoot(params: [String: String]) -> URL { LabPaths.resolveLabRoot(params: params) }
}
