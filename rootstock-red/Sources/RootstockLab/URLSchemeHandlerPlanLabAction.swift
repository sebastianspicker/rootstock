import Foundation
import RootstockCore

/// Lab URL scheme / document-handler review plan - documentation only.
public struct URLSchemeHandlerPlanLabAction: LabAction {
    public static let id = "lab.surface.url_scheme_handler_plan"
    public static let consent = ConsentPolicy.labDefault
    public static let riskClass = RiskClass.labOnly

    public init() {}

    public func run(
        request: LabActionRequest,
        context: EvaluationContext
    ) async throws -> ActionResult {

        try SafetyRails.ensureLabConsent(context: context, policy: Self.consent)
        let labRoot = LabPaths.resolveLabRoot(params: request.parameters)
        let focus = request.parameters["focus"] ?? "URL scheme / document-handler"
        let markerURL = labRoot
            .appendingPathComponent("url-scheme-handler-plan", isDirectory: true)
            .appendingPathComponent("url-scheme-plan.md")
        let body = """
        # rootstock-red-lab URL scheme / document-handler plan
        focus: \(focus)
        purpose: URL scheme / document-handler posture documentation
        rules:
        - document path/meta inventory only under consent
        - never registers schemes or rewrites LaunchServices handlers
        - purple: validate expected telemetry under ROE only
        ROOTSTOCK_RED_LAB_URLSCHEME=1
        """
        let copy = FileMarkerCopy(
            planMessage: """
            Dry-run URL scheme / document-handler plan for focus [\(focus)]: would write plan at             \(markerURL.path). never registers schemes or rewrites LaunchServices handlers.
            """,
            planSteps: [
                "Document URL scheme / document-handler review for: \(focus)",
                "Note path/meta inventory without host mutation beyond lab root",
                "Write markdown plan under lab root only",
                "Purple: validate expected telemetry under ROE only",
            ],
            planCleanup: ["Delete \(markerURL.path)"],
            applyDryRunMessage: "Dry-run: would write URL scheme / document-handler plan at \(markerURL.path)",
            applySuccessMessage: "Wrote URL scheme / document-handler plan at \(markerURL.path)",
            applySteps: ["Write URL scheme / document-handler plan"],
            applyCleanup: ["Delete \(markerURL.path)"],
            presentMessage: "URL scheme / document-handler plan present",
            absentMessage: "URL scheme / document-handler plan absent",
            statusPresentCleanup: ["Delete \(markerURL.path)"],
            statusAbsentCleanup: ["No artifact"],
            removeDryRunMessage: { exists in "Dry-run: would delete URL scheme / document-handler plan (exists=\(exists))" },
            removeSuccessMessage: { exists in "Removed URL scheme / document-handler plan (wasPresent=\(exists))" },
            removeSteps: ["Delete \(markerURL.path)"],
            removeCleanup: ["No system mutations expected"]
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
