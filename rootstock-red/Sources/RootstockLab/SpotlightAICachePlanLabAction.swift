import Foundation
import RootstockCore

/// Lab Spotlight / AI-cache path review plan - documentation only.
public struct SpotlightAICachePlanLabAction: LabAction {
    public static let id = "lab.surface.spotlight_ai_cache_plan"
    public static let consent = ConsentPolicy.labDefault
    public static let riskClass = RiskClass.labOnly

    public init() {}

    public func run(
        request: LabActionRequest,
        context: EvaluationContext
    ) async throws -> ActionResult {

        try SafetyRails.ensureLabConsent(context: context, policy: Self.consent)
        let labRoot = LabPaths.resolveLabRoot(params: request.parameters)
        let focus = request.parameters["focus"] ?? "spotlight,mdworker,ai-cache"
        let markerURL = labRoot
            .appendingPathComponent("spotlight-ai-cache-plan", isDirectory: true)
            .appendingPathComponent("spotlight-plan.md")
        let body = """
        # rootstock-red-lab Spotlight/AI-cache plan
        focus: \(focus)
        purpose: index/cache data-access posture documentation
        rules:
        - document Spotlight/mdworker/AI-cache path inventory only under consent
        - never dump .Spotlight-V100 or AI model/cache contents
        - never weaponize Sploitlight-class index access
        - purple: expect OPEN of mdfind/mdutil if inspected under ROE
        ROOTSTOCK_RED_LAB_SPOTLIGHT_AI_CACHE=1
        """
        let copy = FileMarkerCopy(
            planMessage: """
            Dry-run Spotlight/AI-cache plan for focus [\(focus)]: would write plan at \
            \(markerURL.path). Never dumps index or model contents.
            """,
            planSteps: [
                "Document index/cache data-access review for: \(focus)",
                "Note path presence without reading Spotlight DB or AI caches",
                "Write markdown plan under lab root only",
                "Never weaponize Sploitlight-class index access",
            ],
            planCleanup: ["Delete \(markerURL.path)"],
            applyDryRunMessage: "Dry-run: would write Spotlight/AI-cache plan at \(markerURL.path)",
            applySuccessMessage: "Wrote Spotlight/AI-cache plan at \(markerURL.path)",
            applySteps: ["Write Spotlight/AI-cache plan"],
            applyCleanup: ["Delete \(markerURL.path)"],
            presentMessage: "Spotlight/AI-cache plan present",
            absentMessage: "Spotlight/AI-cache plan absent",
            statusPresentCleanup: ["Delete \(markerURL.path)"],
            statusAbsentCleanup: ["No artifact"],
            removeDryRunMessage: { exists in "Dry-run: would delete Spotlight/AI-cache plan (exists=\(exists))" },
            removeSuccessMessage: { exists in "Removed Spotlight/AI-cache plan (wasPresent=\(exists))" },
            removeSteps: ["Delete \(markerURL.path)"],
            removeCleanup: ["No Spotlight indexes were dumped"]
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
