import Foundation
import RootstockCore

/// Lab Browser extension dual-use review plan - documentation only.
public struct BrowserExtensionDualUsePlanLabAction: LabAction {
    public static let id = "lab.surface.browser_extension_dualuse_plan"
    public static let consent = ConsentPolicy.labDefault
    public static let riskClass = RiskClass.labOnly

    public init() {}

    public func run(
        request: LabActionRequest,
        context: EvaluationContext
    ) async throws -> ActionResult {

        try SafetyRails.ensureLabConsent(context: context, policy: Self.consent)
        let labRoot = LabPaths.resolveLabRoot(params: request.parameters)
        let focus = request.parameters["focus"] ?? "Browser extension dual-use"
        let markerURL = labRoot
            .appendingPathComponent("browser-extension-dualuse-plan", isDirectory: true)
            .appendingPathComponent("browser-extension-plan.md")
        let body = """
        # rootstock-red-lab Browser extension dual-use plan
        focus: \(focus)
        purpose: Browser extension dual-use posture documentation
        rules:
        - document path/meta inventory only under consent
        - never dumps extension secrets or cookies
        - purple: validate expected telemetry under ROE only
        ROOTSTOCK_RED_LAB_BROWSER_EXT=1
        """
        let copy = FileMarkerCopy(
            planMessage: """
            Dry-run Browser extension dual-use plan for focus [\(focus)]: would write plan at             \(markerURL.path). never dumps extension secrets or cookies.
            """,
            planSteps: [
                "Document Browser extension dual-use review for: \(focus)",
                "Note path/meta inventory without host mutation beyond lab root",
                "Write markdown plan under lab root only",
                "Purple: validate expected telemetry under ROE only",
            ],
            planCleanup: ["Delete \(markerURL.path)"],
            applyDryRunMessage: "Dry-run: would write Browser extension dual-use plan at \(markerURL.path)",
            applySuccessMessage: "Wrote Browser extension dual-use plan at \(markerURL.path)",
            applySteps: ["Write Browser extension dual-use plan"],
            applyCleanup: ["Delete \(markerURL.path)"],
            presentMessage: "Browser extension dual-use plan present",
            absentMessage: "Browser extension dual-use plan absent",
            statusPresentCleanup: ["Delete \(markerURL.path)"],
            statusAbsentCleanup: ["No artifact"],
            removeDryRunMessage: { exists in "Dry-run: would delete Browser extension dual-use plan (exists=\(exists))" },
            removeSuccessMessage: { exists in "Removed Browser extension dual-use plan (wasPresent=\(exists))" },
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
