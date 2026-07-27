import Foundation
import RootstockCore

/// Lab Webloc/inetloc delivery review plan - documentation only.
public struct WeblocInetlocPlanLabAction: LabAction {
    public static let id = "lab.surface.webloc_inetloc_plan"
    public static let consent = ConsentPolicy.labDefault
    public static let riskClass = RiskClass.labOnly

    public init() {}

    public func run(
        request: LabActionRequest,
        context: EvaluationContext
    ) async throws -> ActionResult {

        try SafetyRails.ensureLabConsent(context: context, policy: Self.consent)
        let labRoot = LabPaths.resolveLabRoot(params: request.parameters)
        let focus = request.parameters["focus"] ?? "Webloc/inetloc delivery"
        let markerURL = labRoot
            .appendingPathComponent("webloc_inetloc-plan", isDirectory: true)
            .appendingPathComponent("webloc_inetloc-plan.md")
        let body = """
        # rootstock-red-lab Webloc/inetloc delivery plan
        focus: \(focus)
        purpose: Webloc / Internet Location file delivery posture documentation
        rules:
        - document path/meta inventory only under consent
        - never crafts phishing webloc/inetloc payloads or rewrites Internet Location files
        - purple: validate expected telemetry under ROE only
        ROOTSTOCK_RED_LAB_WAVE12_WEBLOC_INETLOC=1
        """
        let copy = FileMarkerCopy(
            planMessage: """
            Dry-run Webloc/inetloc delivery plan for focus [\(focus)]: would write plan at             \(markerURL.path). never crafts phishing webloc/inetloc payloads or rewrites Internet Location files.
            """,
            planSteps: [
                "Document Webloc/inetloc delivery review for: \(focus)",
                "Note path/meta inventory without host mutation beyond lab root",
                "Write markdown plan under lab root only",
                "Purple: validate expected telemetry under ROE only",
            ],
            planCleanup: ["Delete \(markerURL.path)"],
            applyDryRunMessage: "Dry-run: would write Webloc/inetloc delivery plan at \(markerURL.path)",
            applySuccessMessage: "Wrote Webloc/inetloc delivery plan at \(markerURL.path)",
            applySteps: ["Write Webloc/inetloc delivery plan"],
            applyCleanup: ["Delete \(markerURL.path)"],
            presentMessage: "Webloc/inetloc delivery plan present",
            absentMessage: "Webloc/inetloc delivery plan absent",
            statusPresentCleanup: ["Delete \(markerURL.path)"],
            statusAbsentCleanup: ["No artifact"],
            removeDryRunMessage: { exists in "Dry-run: would delete Webloc/inetloc delivery plan (exists=\(exists))" },
            removeSuccessMessage: { exists in "Removed Webloc/inetloc delivery plan (wasPresent=\(exists))" },
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
