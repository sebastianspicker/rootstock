import Foundation
import RootstockCore

/// Lab Music library path review plan - documentation only.
public struct MusicLibraryPathPlanLabAction: LabAction {
    public static let id = "lab.surface.music_library_path_plan"
    public static let consent = ConsentPolicy.labDefault
    public static let riskClass = RiskClass.labOnly
    public init() {}
    public func run(request: LabActionRequest, context: EvaluationContext) async throws -> ActionResult {
        try SafetyRails.ensureLabConsent(context: context, policy: Self.consent)
        let labRoot = LabPaths.resolveLabRoot(params: request.parameters)
        let focus = request.parameters["focus"] ?? "Music library path"
        let markerURL = labRoot.appendingPathComponent("music_library_path-plan", isDirectory: true)
            .appendingPathComponent("music_library_path-plan.md")
        let body = """
        # rootstock-red-lab Music library path plan
        focus: \(focus)
        purpose: Music / media library path residual posture documentation
        rules:
        - document path/meta inventory only under consent
        - never exports Music library media or DRM material
        - purple: validate expected telemetry under ROE only
        ROOTSTOCK_RED_LAB_WAVE16_MUSIC_LIBRARY_PATH=1
        """
        let copy = FileMarkerCopy(
            planMessage: "Dry-run Music library path plan for focus [\(focus)]: would write plan at \(markerURL.path). never exports Music library media or DRM material.",
            planSteps: [
                "Document Music library path review for: \(focus)",
                "Note path/meta inventory without host mutation beyond lab root",
                "Write markdown plan under lab root only",
                "Purple: validate expected telemetry under ROE only",
            ],
            planCleanup: ["Delete \(markerURL.path)"],
            applyDryRunMessage: "Dry-run: would write Music library path plan at \(markerURL.path)",
            applySuccessMessage: "Wrote Music library path plan at \(markerURL.path)",
            applySteps: ["Write Music library path plan"], applyCleanup: ["Delete \(markerURL.path)"],
            presentMessage: "Music library path plan present", absentMessage: "Music library path plan absent",
            statusPresentCleanup: ["Delete \(markerURL.path)"], statusAbsentCleanup: ["No artifact"],
            removeDryRunMessage: { exists in "Dry-run: would delete Music library path plan (exists=\(exists))" },
            removeSuccessMessage: { exists in "Removed Music library path plan (wasPresent=\(exists))" },
            removeSteps: ["Delete \(markerURL.path)"], removeCleanup: ["No system mutations expected"]
        )
        return try LabMarkerLifecycle.runFileMarker(
            actionId: Self.id, operation: request.operation, markerURL: markerURL,
            body: body, contextDryRun: context.dryRun, copy: copy
        )
    }
    public static func resolveLabRoot(params: [String: String]) -> URL { LabPaths.resolveLabRoot(params: params) }
}
