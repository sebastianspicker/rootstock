import Foundation
import RootstockCore

/// Lab Weather widget residual review plan - documentation only.
public struct WeatherWidgetPathPlanLabAction: LabAction {
    public static let id = "lab.surface.weather_widget_path_plan"
    public static let consent = ConsentPolicy.labDefault
    public static let riskClass = RiskClass.labOnly
    public init() {}
    public func run(request: LabActionRequest, context: EvaluationContext) async throws -> ActionResult {
        try SafetyRails.ensureLabConsent(context: context, policy: Self.consent)
        let labRoot = LabPaths.resolveLabRoot(params: request.parameters)
        let focus = request.parameters["focus"] ?? "Weather widget residual"
        let markerURL = labRoot.appendingPathComponent("weather_widget_path-plan", isDirectory: true)
            .appendingPathComponent("weather_widget_path-plan.md")
        let body = """
        # rootstock-red-lab Weather widget residual plan
        focus: \(focus)
        purpose: Weather / widget data residual plane posture documentation
        rules:
        - document path/meta inventory only under consent
        - never dumps weather personalization data or widget timeline contents
        - purple: validate expected telemetry under ROE only
        ROOTSTOCK_RED_LAB_WAVE16_WEATHER_WIDGET_PATH=1
        """
        let copy = FileMarkerCopy(
            planMessage: "Dry-run Weather widget residual plan for focus [\(focus)]: would write plan at \(markerURL.path). never dumps weather personalization data or widget timeline contents.",
            planSteps: [
                "Document Weather widget residual review for: \(focus)",
                "Note path/meta inventory without host mutation beyond lab root",
                "Write markdown plan under lab root only",
                "Purple: validate expected telemetry under ROE only",
            ],
            planCleanup: ["Delete \(markerURL.path)"],
            applyDryRunMessage: "Dry-run: would write Weather widget residual plan at \(markerURL.path)",
            applySuccessMessage: "Wrote Weather widget residual plan at \(markerURL.path)",
            applySteps: ["Write Weather widget residual plan"], applyCleanup: ["Delete \(markerURL.path)"],
            presentMessage: "Weather widget residual plan present", absentMessage: "Weather widget residual plan absent",
            statusPresentCleanup: ["Delete \(markerURL.path)"], statusAbsentCleanup: ["No artifact"],
            removeDryRunMessage: { exists in "Dry-run: would delete Weather widget residual plan (exists=\(exists))" },
            removeSuccessMessage: { exists in "Removed Weather widget residual plan (wasPresent=\(exists))" },
            removeSteps: ["Delete \(markerURL.path)"], removeCleanup: ["No system mutations expected"]
        )
        return try LabMarkerLifecycle.runFileMarker(
            actionId: Self.id, operation: request.operation, markerURL: markerURL,
            body: body, contextDryRun: context.dryRun, copy: copy
        )
    }
    public static func resolveLabRoot(params: [String: String]) -> URL { LabPaths.resolveLabRoot(params: params) }
}
