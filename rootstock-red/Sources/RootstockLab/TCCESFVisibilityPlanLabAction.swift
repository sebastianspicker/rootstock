import Foundation
import RootstockCore

/// Lab TCC/ESF visibility depth review plan - documentation only.
public struct TCCESFVisibilityPlanLabAction: LabAction {
    public static let id = "lab.surface.tcc_esf_visibility_plan"
    public static let consent = ConsentPolicy.labDefault
    public static let riskClass = RiskClass.labOnly

    public init() {}

    public func run(
        request: LabActionRequest,
        context: EvaluationContext
    ) async throws -> ActionResult {

        try SafetyRails.ensureLabConsent(context: context, policy: Self.consent)
        let labRoot = LabPaths.resolveLabRoot(params: request.parameters)
        let focus = request.parameters["focus"] ?? "TCC.db,eslogger,log,visibility-depth"
        let markerURL = labRoot
            .appendingPathComponent("tcc-esf-visibility-plan", isDirectory: true)
            .appendingPathComponent("tcc-esf-visibility-plan.md")
        let body = """
        # rootstock-red-lab TCC/ESF visibility depth plan
        focus: \(focus)
        purpose: TCC/ESF visibility depth posture documentation
        rules:
        - document TCC.db path readability and eslogger/log tooling inventory only under consent
        - never dump TCC.db rows
        - never live-subscribe Endpoint Security without separate ROE
        - purple: expect OPEN of TCC paths / eslogger if visibility tooling exercised under ROE
        ROOTSTOCK_RED_LAB_TCC_ESF_VISIBILITY=1
        """
        let copy = FileMarkerCopy(
            planMessage: """
            Dry-run TCC/ESF visibility depth plan for focus [\(focus)]: would write plan at \
            \(markerURL.path). Never dumps TCC.db or unloads sensors.
            """,
            planSteps: [
                "Document TCC/ESF visibility depth review for: \(focus)",
                "Note path/meta inventory without host mutation beyond lab root",
                "Write markdown plan under lab root only",
                "Purple: validate expected telemetry under ROE only",
            ],
            planCleanup: ["Delete \(markerURL.path)"],
            applyDryRunMessage: "Dry-run: would write TCC/ESF visibility depth plan at \(markerURL.path)",
            applySuccessMessage: "Wrote TCC/ESF visibility depth plan at \(markerURL.path)",
            applySteps: ["Write TCC/ESF visibility depth plan"],
            applyCleanup: ["Delete \(markerURL.path)"],
            presentMessage: "TCC/ESF visibility depth plan present",
            absentMessage: "TCC/ESF visibility depth plan absent",
            statusPresentCleanup: ["Delete \(markerURL.path)"],
            statusAbsentCleanup: ["No artifact"],
            removeDryRunMessage: { exists in "Dry-run: would delete TCC/ESF visibility depth plan (exists=\(exists))" },
            removeSuccessMessage: { exists in "Removed TCC/ESF visibility depth plan (wasPresent=\(exists))" },
            removeSteps: ["Delete \(markerURL.path)"],
            removeCleanup: ["No TCC dump expected"]
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
