import Foundation
import RootstockCore

/// Lab ScreenCapture privacy dual-use review plan - documentation only.
public struct ScreenCapturePrivacyPlanLabAction: LabAction {
    public static let id = "lab.surface.screencapture_privacy_plan"
    public static let consent = ConsentPolicy.labDefault
    public static let riskClass = RiskClass.labOnly
    public init() {}
    public func run(request: LabActionRequest, context: EvaluationContext) async throws -> ActionResult {
        try SafetyRails.ensureLabConsent(context: context, policy: Self.consent)
        let labRoot = LabPaths.resolveLabRoot(params: request.parameters)
        let focus = request.parameters["focus"] ?? "ScreenCapture privacy dual-use"
        let markerURL = labRoot.appendingPathComponent("screencapture-plan", isDirectory: true)
            .appendingPathComponent("screencapture-plan.md")
        let body = """
        # rootstock-red-lab ScreenCapture privacy dual-use plan
        focus: \(focus)
        purpose: ScreenCapture / screenshot privacy dual-use depth posture documentation
        rules:
        - document path/meta inventory only under consent
        - never captures screens or dumps Screen Recording TCC rows
        - purple: validate expected telemetry under ROE only
        ROOTSTOCK_RED_LAB_WAVE13_SCREENCAPTURE=1
        """
        let copy = FileMarkerCopy(
            planMessage: "Dry-run ScreenCapture privacy dual-use plan for focus [\(focus)]: would write plan at \(markerURL.path). never captures screens or dumps Screen Recording TCC rows.",
            planSteps: [
                "Document ScreenCapture privacy dual-use review for: \(focus)",
                "Note path/meta inventory without host mutation beyond lab root",
                "Write markdown plan under lab root only",
                "Purple: validate expected telemetry under ROE only",
            ],
            planCleanup: ["Delete \(markerURL.path)"],
            applyDryRunMessage: "Dry-run: would write ScreenCapture privacy dual-use plan at \(markerURL.path)",
            applySuccessMessage: "Wrote ScreenCapture privacy dual-use plan at \(markerURL.path)",
            applySteps: ["Write ScreenCapture privacy dual-use plan"],
            applyCleanup: ["Delete \(markerURL.path)"],
            presentMessage: "ScreenCapture privacy dual-use plan present",
            absentMessage: "ScreenCapture privacy dual-use plan absent",
            statusPresentCleanup: ["Delete \(markerURL.path)"],
            statusAbsentCleanup: ["No artifact"],
            removeDryRunMessage: { exists in "Dry-run: would delete ScreenCapture privacy dual-use plan (exists=\(exists))" },
            removeSuccessMessage: { exists in "Removed ScreenCapture privacy dual-use plan (wasPresent=\(exists))" },
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
