import Foundation
import RootstockCore

/// Lab Unified log observation review plan - documentation only.
public struct UnifiedLogObservationPlanLabAction: LabAction {
    public static let id = "lab.surface.unified_log_observation_plan"
    public static let consent = ConsentPolicy.labDefault
    public static let riskClass = RiskClass.labOnly

    public init() {}

    public func run(
        request: LabActionRequest,
        context: EvaluationContext
    ) async throws -> ActionResult {

        try SafetyRails.ensureLabConsent(context: context, policy: Self.consent)
        let labRoot = LabPaths.resolveLabRoot(params: request.parameters)
        let focus = request.parameters["focus"] ?? "Unified log observation"
        let markerURL = labRoot
            .appendingPathComponent("unified_log-plan", isDirectory: true)
            .appendingPathComponent("unified_log-plan.md")
        let body = """
        # rootstock-red-lab Unified log observation plan
        focus: \(focus)
        purpose: Unified log / logarchive observation depth posture documentation
        rules:
        - document path/meta inventory only under consent
        - never dumps private unified-log message bodies or force-collects other users' logarchives
        - purple: validate expected telemetry under ROE only
        ROOTSTOCK_RED_LAB_WAVE12_UNIFIED_LOG=1
        """
        let copy = FileMarkerCopy(
            planMessage: """
            Dry-run Unified log observation plan for focus [\(focus)]: would write plan at             \(markerURL.path). never dumps private unified-log message bodies or force-collects other users' logarchives.
            """,
            planSteps: [
                "Document Unified log observation review for: \(focus)",
                "Note path/meta inventory without host mutation beyond lab root",
                "Write markdown plan under lab root only",
                "Purple: validate expected telemetry under ROE only",
            ],
            planCleanup: ["Delete \(markerURL.path)"],
            applyDryRunMessage: "Dry-run: would write Unified log observation plan at \(markerURL.path)",
            applySuccessMessage: "Wrote Unified log observation plan at \(markerURL.path)",
            applySteps: ["Write Unified log observation plan"],
            applyCleanup: ["Delete \(markerURL.path)"],
            presentMessage: "Unified log observation plan present",
            absentMessage: "Unified log observation plan absent",
            statusPresentCleanup: ["Delete \(markerURL.path)"],
            statusAbsentCleanup: ["No artifact"],
            removeDryRunMessage: { exists in "Dry-run: would delete Unified log observation plan (exists=\(exists))" },
            removeSuccessMessage: { exists in "Removed Unified log observation plan (wasPresent=\(exists))" },
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
