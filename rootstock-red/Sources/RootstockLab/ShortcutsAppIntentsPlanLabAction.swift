import Foundation
import RootstockCore

/// Lab Shortcuts / App Intents review plan - documentation only.
public struct ShortcutsAppIntentsPlanLabAction: LabAction {
    public static let id = "lab.surface.shortcuts_app_intents_plan"
    public static let consent = ConsentPolicy.labDefault
    public static let riskClass = RiskClass.labOnly

    public init() {}

    public func run(
        request: LabActionRequest,
        context: EvaluationContext
    ) async throws -> ActionResult {

        try SafetyRails.ensureLabConsent(context: context, policy: Self.consent)
        let labRoot = LabPaths.resolveLabRoot(params: request.parameters)
        let focus = request.parameters["focus"] ?? "Shortcuts / App Intents"
        let markerURL = labRoot
            .appendingPathComponent("shortcuts-app-intents-plan", isDirectory: true)
            .appendingPathComponent("shortcuts-plan.md")
        let body = """
        # rootstock-red-lab Shortcuts / App Intents plan
        focus: \(focus)
        purpose: Shortcuts / App Intents posture documentation
        rules:
        - document path/meta inventory only under consent
        - never runs shortcuts or forges App Intents
        - purple: validate expected telemetry under ROE only
        ROOTSTOCK_RED_LAB_SHORTCUTS=1
        """
        let copy = FileMarkerCopy(
            planMessage: """
            Dry-run Shortcuts / App Intents plan for focus [\(focus)]: would write plan at             \(markerURL.path). never runs shortcuts or forges App Intents.
            """,
            planSteps: [
                "Document Shortcuts / App Intents review for: \(focus)",
                "Note path/meta inventory without host mutation beyond lab root",
                "Write markdown plan under lab root only",
                "Purple: validate expected telemetry under ROE only",
            ],
            planCleanup: ["Delete \(markerURL.path)"],
            applyDryRunMessage: "Dry-run: would write Shortcuts / App Intents plan at \(markerURL.path)",
            applySuccessMessage: "Wrote Shortcuts / App Intents plan at \(markerURL.path)",
            applySteps: ["Write Shortcuts / App Intents plan"],
            applyCleanup: ["Delete \(markerURL.path)"],
            presentMessage: "Shortcuts / App Intents plan present",
            absentMessage: "Shortcuts / App Intents plan absent",
            statusPresentCleanup: ["Delete \(markerURL.path)"],
            statusAbsentCleanup: ["No artifact"],
            removeDryRunMessage: { exists in "Dry-run: would delete Shortcuts / App Intents plan (exists=\(exists))" },
            removeSuccessMessage: { exists in "Removed Shortcuts / App Intents plan (wasPresent=\(exists))" },
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
