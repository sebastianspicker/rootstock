import Foundation
import RootstockCore

/// Lab Launchd override depth review plan - documentation only.
public struct LaunchdOverrideDepthPlanLabAction: LabAction {
    public static let id = "lab.surface.launchd_override_depth_plan"
    public static let consent = ConsentPolicy.labDefault
    public static let riskClass = RiskClass.labOnly

    public init() {}

    public func run(
        request: LabActionRequest,
        context: EvaluationContext
    ) async throws -> ActionResult {

        try SafetyRails.ensureLabConsent(context: context, policy: Self.consent)
        let labRoot = LabPaths.resolveLabRoot(params: request.parameters)
        let focus = request.parameters["focus"] ?? "Launchd override depth"
        let markerURL = labRoot
            .appendingPathComponent("launchd-override-depth-plan", isDirectory: true)
            .appendingPathComponent("launchd-override-plan.md")
        let body = """
        # rootstock-red-lab Launchd override depth plan
        focus: \(focus)
        purpose: Launchd override depth posture documentation
        rules:
        - document path/meta inventory only under consent
        - never writes disabled.plist or unloads security products
        - purple: validate expected telemetry under ROE only
        ROOTSTOCK_RED_LAB_LAUNCHD_OVERRIDE=1
        """
        let copy = FileMarkerCopy(
            planMessage: """
            Dry-run Launchd override depth plan for focus [\(focus)]: would write plan at             \(markerURL.path). never writes disabled.plist or unloads security products.
            """,
            planSteps: [
                "Document Launchd override depth review for: \(focus)",
                "Note path/meta inventory without host mutation beyond lab root",
                "Write markdown plan under lab root only",
                "Purple: validate expected telemetry under ROE only",
            ],
            planCleanup: ["Delete \(markerURL.path)"],
            applyDryRunMessage: "Dry-run: would write Launchd override depth plan at \(markerURL.path)",
            applySuccessMessage: "Wrote Launchd override depth plan at \(markerURL.path)",
            applySteps: ["Write Launchd override depth plan"],
            applyCleanup: ["Delete \(markerURL.path)"],
            presentMessage: "Launchd override depth plan present",
            absentMessage: "Launchd override depth plan absent",
            statusPresentCleanup: ["Delete \(markerURL.path)"],
            statusAbsentCleanup: ["No artifact"],
            removeDryRunMessage: { exists in "Dry-run: would delete Launchd override depth plan (exists=\(exists))" },
            removeSuccessMessage: { exists in "Removed Launchd override depth plan (wasPresent=\(exists))" },
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
