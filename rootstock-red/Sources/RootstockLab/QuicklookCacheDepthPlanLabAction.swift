import Foundation
import RootstockCore

/// Lab QuickLook cache depth review plan - documentation only.
public struct QuicklookCacheDepthPlanLabAction: LabAction {
    public static let id = "lab.surface.quicklook_cache_depth_plan"
    public static let consent = ConsentPolicy.labDefault
    public static let riskClass = RiskClass.labOnly
    public init() {}
    public func run(request: LabActionRequest, context: EvaluationContext) async throws -> ActionResult {
        try SafetyRails.ensureLabConsent(context: context, policy: Self.consent)
        let labRoot = LabPaths.resolveLabRoot(params: request.parameters)
        let focus = request.parameters["focus"] ?? "QuickLook cache depth"
        let markerURL = labRoot.appendingPathComponent("quicklook_cache_depth-plan", isDirectory: true)
            .appendingPathComponent("quicklook_cache_depth-plan.md")
        let body = """
        # rootstock-red-lab QuickLook cache depth plan
        focus: \(focus)
        purpose: QuickLook thumbnail cache residual depth posture documentation
        rules:
        - document path/meta inventory only under consent
        - never dumps QuickLook thumbnail bitmap contents as secret material
        - purple: validate expected telemetry under ROE only
        ROOTSTOCK_RED_LAB_WAVE14_QUICKLOOK_CACHE_DEPTH=1
        """
        let copy = FileMarkerCopy(
            planMessage: "Dry-run QuickLook cache depth plan for focus [\(focus)]: would write plan at \(markerURL.path). never dumps QuickLook thumbnail bitmap contents as secret material.",
            planSteps: [
                "Document QuickLook cache depth review for: \(focus)",
                "Note path/meta inventory without host mutation beyond lab root",
                "Write markdown plan under lab root only",
                "Purple: validate expected telemetry under ROE only",
            ],
            planCleanup: ["Delete \(markerURL.path)"],
            applyDryRunMessage: "Dry-run: would write QuickLook cache depth plan at \(markerURL.path)",
            applySuccessMessage: "Wrote QuickLook cache depth plan at \(markerURL.path)",
            applySteps: ["Write QuickLook cache depth plan"], applyCleanup: ["Delete \(markerURL.path)"],
            presentMessage: "QuickLook cache depth plan present", absentMessage: "QuickLook cache depth plan absent",
            statusPresentCleanup: ["Delete \(markerURL.path)"], statusAbsentCleanup: ["No artifact"],
            removeDryRunMessage: { exists in "Dry-run: would delete QuickLook cache depth plan (exists=\(exists))" },
            removeSuccessMessage: { exists in "Removed QuickLook cache depth plan (wasPresent=\(exists))" },
            removeSteps: ["Delete \(markerURL.path)"], removeCleanup: ["No system mutations expected"]
        )
        return try LabMarkerLifecycle.runFileMarker(
            actionId: Self.id, operation: request.operation, markerURL: markerURL,
            body: body, contextDryRun: context.dryRun, copy: copy
        )
    }
    public static func resolveLabRoot(params: [String: String]) -> URL { LabPaths.resolveLabRoot(params: params) }
}
