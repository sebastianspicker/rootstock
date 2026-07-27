import Foundation
import RootstockCore

/// Lab OSA/scpt delivery review plan - documentation only.
public struct OsascriptScptPlanLabAction: LabAction {
    public static let id = "lab.surface.osascript_scpt_plan"
    public static let consent = ConsentPolicy.labDefault
    public static let riskClass = RiskClass.labOnly

    public init() {}

    public func run(
        request: LabActionRequest,
        context: EvaluationContext
    ) async throws -> ActionResult {

        try SafetyRails.ensureLabConsent(context: context, policy: Self.consent)
        let labRoot = LabPaths.resolveLabRoot(params: request.parameters)
        let focus = request.parameters["focus"] ?? "OSA/scpt delivery"
        let markerURL = labRoot
            .appendingPathComponent("osascript_scpt-plan", isDirectory: true)
            .appendingPathComponent("osascript_scpt-plan.md")
        let body = """
        # rootstock-red-lab OSA/scpt delivery plan
        focus: \(focus)
        purpose: Compiled AppleScript / OSA delivery residual posture documentation
        rules:
        - document path/meta inventory only under consent
        - never compiles malicious .scpt payloads or executes third-party AppleScripts
        - purple: validate expected telemetry under ROE only
        ROOTSTOCK_RED_LAB_WAVE12_OSASCRIPT_SCPT=1
        """
        let copy = FileMarkerCopy(
            planMessage: """
            Dry-run OSA/scpt delivery plan for focus [\(focus)]: would write plan at             \(markerURL.path). never compiles malicious .scpt payloads or executes third-party AppleScripts.
            """,
            planSteps: [
                "Document OSA/scpt delivery review for: \(focus)",
                "Note path/meta inventory without host mutation beyond lab root",
                "Write markdown plan under lab root only",
                "Purple: validate expected telemetry under ROE only",
            ],
            planCleanup: ["Delete \(markerURL.path)"],
            applyDryRunMessage: "Dry-run: would write OSA/scpt delivery plan at \(markerURL.path)",
            applySuccessMessage: "Wrote OSA/scpt delivery plan at \(markerURL.path)",
            applySteps: ["Write OSA/scpt delivery plan"],
            applyCleanup: ["Delete \(markerURL.path)"],
            presentMessage: "OSA/scpt delivery plan present",
            absentMessage: "OSA/scpt delivery plan absent",
            statusPresentCleanup: ["Delete \(markerURL.path)"],
            statusAbsentCleanup: ["No artifact"],
            removeDryRunMessage: { exists in "Dry-run: would delete OSA/scpt delivery plan (exists=\(exists))" },
            removeSuccessMessage: { exists in "Removed OSA/scpt delivery plan (wasPresent=\(exists))" },
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
