import Foundation
import RootstockCore

/// Lab Shortcuts iCloud sync review plan - documentation only.
public struct ShortcutsIcloudSyncPlanLabAction: LabAction {
    public static let id = "lab.surface.shortcuts_icloud_sync_plan"
    public static let consent = ConsentPolicy.labDefault
    public static let riskClass = RiskClass.labOnly
    public init() {}
    public func run(request: LabActionRequest, context: EvaluationContext) async throws -> ActionResult {
        try SafetyRails.ensureLabConsent(context: context, policy: Self.consent)
        let labRoot = LabPaths.resolveLabRoot(params: request.parameters)
        let focus = request.parameters["focus"] ?? "Shortcuts iCloud sync"
        let markerURL = labRoot.appendingPathComponent("shortcuts_icloud_sync-plan", isDirectory: true)
            .appendingPathComponent("shortcuts_icloud_sync-plan.md")
        let body = """
        # rootstock-red-lab Shortcuts iCloud sync plan
        focus: \(focus)
        purpose: Shortcuts iCloud sync residual depth posture documentation
        rules:
        - document path/meta inventory only under consent
        - never executes Shortcuts or dumps iCloud-synced automation databases
        - purple: validate expected telemetry under ROE only
        ROOTSTOCK_RED_LAB_WAVE16_SHORTCUTS_ICLOUD_SYNC=1
        """
        let copy = FileMarkerCopy(
            planMessage: "Dry-run Shortcuts iCloud sync plan for focus [\(focus)]: would write plan at \(markerURL.path). never executes Shortcuts or dumps iCloud-synced automation databases.",
            planSteps: [
                "Document Shortcuts iCloud sync review for: \(focus)",
                "Note path/meta inventory without host mutation beyond lab root",
                "Write markdown plan under lab root only",
                "Purple: validate expected telemetry under ROE only",
            ],
            planCleanup: ["Delete \(markerURL.path)"],
            applyDryRunMessage: "Dry-run: would write Shortcuts iCloud sync plan at \(markerURL.path)",
            applySuccessMessage: "Wrote Shortcuts iCloud sync plan at \(markerURL.path)",
            applySteps: ["Write Shortcuts iCloud sync plan"], applyCleanup: ["Delete \(markerURL.path)"],
            presentMessage: "Shortcuts iCloud sync plan present", absentMessage: "Shortcuts iCloud sync plan absent",
            statusPresentCleanup: ["Delete \(markerURL.path)"], statusAbsentCleanup: ["No artifact"],
            removeDryRunMessage: { exists in "Dry-run: would delete Shortcuts iCloud sync plan (exists=\(exists))" },
            removeSuccessMessage: { exists in "Removed Shortcuts iCloud sync plan (wasPresent=\(exists))" },
            removeSteps: ["Delete \(markerURL.path)"], removeCleanup: ["No system mutations expected"]
        )
        return try LabMarkerLifecycle.runFileMarker(
            actionId: Self.id, operation: request.operation, markerURL: markerURL,
            body: body, contextDryRun: context.dryRun, copy: copy
        )
    }
    public static func resolveLabRoot(params: [String: String]) -> URL { LabPaths.resolveLabRoot(params: params) }
}
