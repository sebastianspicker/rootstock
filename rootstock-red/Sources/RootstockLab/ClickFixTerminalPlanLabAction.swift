import Foundation
import RootstockCore

/// Lab ClickFix / paste-run Terminal review plan - documentation only.
public struct ClickFixTerminalPlanLabAction: LabAction {
    public static let id = "lab.surface.clickfix_terminal_plan"
    public static let consent = ConsentPolicy.labDefault
    public static let riskClass = RiskClass.labOnly

    public init() {}

    public func run(
        request: LabActionRequest,
        context: EvaluationContext
    ) async throws -> ActionResult {

        try SafetyRails.ensureLabConsent(context: context, policy: Self.consent)
        let labRoot = LabPaths.resolveLabRoot(params: request.parameters)
        let focus = request.parameters["focus"] ?? "terminal,script-editor,curl,osascript"
        let markerURL = labRoot
            .appendingPathComponent("clickfix-terminal-plan", isDirectory: true)
            .appendingPathComponent("clickfix-plan.md")
        let body = """
        # rootstock-red-lab ClickFix Terminal plan
        focus: \(focus)
        purpose: paste-run delivery posture documentation
        rules:
        - document Terminal/Script Editor/loader inventory only under consent
        - never build ClickFix lures or paste-this-payload recipes
        - never deliver remote loaders or weaponize user-execution
        - purple: expect OPEN/EXEC of shell/curl if paste-run observed under ROE
        ROOTSTOCK_RED_LAB_CLICKFIX_TERMINAL=1
        """
        let copy = FileMarkerCopy(
            planMessage: """
            Dry-run ClickFix Terminal plan for focus [\(focus)]: would write plan at \
            \(markerURL.path). Never builds lures or paste-run payloads.
            """,
            planSteps: [
                "Document paste-run delivery review for: \(focus)",
                "Note Terminal/Script Editor/loader path presence without lure construction",
                "Write markdown plan under lab root only",
                "Purple: expect EXEC of shell/curl if users paste-run under ROE",
            ],
            planCleanup: ["Delete \(markerURL.path)"],
            applyDryRunMessage: "Dry-run: would write ClickFix Terminal plan at \(markerURL.path)",
            applySuccessMessage: "Wrote ClickFix Terminal plan at \(markerURL.path)",
            applySteps: ["Write ClickFix Terminal plan"],
            applyCleanup: ["Delete \(markerURL.path)"],
            presentMessage: "ClickFix Terminal plan present",
            absentMessage: "ClickFix Terminal plan absent",
            statusPresentCleanup: ["Delete \(markerURL.path)"],
            statusAbsentCleanup: ["No artifact"],
            removeDryRunMessage: { exists in "Dry-run: would delete ClickFix Terminal plan (exists=\(exists))" },
            removeSuccessMessage: { exists in "Removed ClickFix Terminal plan (wasPresent=\(exists))" },
            removeSteps: ["Delete \(markerURL.path)"],
            removeCleanup: ["No paste-run payloads were delivered"]
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
