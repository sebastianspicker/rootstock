import Foundation
import RootstockCore

/// Lab AirPlay receiver dual-use review plan - documentation only.
public struct AirplayReceiverSurfacePlanLabAction: LabAction {
    public static let id = "lab.surface.airplay_receiver_surface_plan"
    public static let consent = ConsentPolicy.labDefault
    public static let riskClass = RiskClass.labOnly
    public init() {}
    public func run(request: LabActionRequest, context: EvaluationContext) async throws -> ActionResult {
        try SafetyRails.ensureLabConsent(context: context, policy: Self.consent)
        let labRoot = LabPaths.resolveLabRoot(params: request.parameters)
        let focus = request.parameters["focus"] ?? "AirPlay receiver dual-use"
        let markerURL = labRoot.appendingPathComponent("airplay_receiver_surface-plan", isDirectory: true)
            .appendingPathComponent("airplay_receiver_surface-plan.md")
        let body = """
        # rootstock-red-lab AirPlay receiver dual-use plan
        focus: \(focus)
        purpose: AirPlay receiver dual-use residual posture documentation
        rules:
        - document path/meta inventory only under consent
        - never enables AirPlay Receiver or spoofs AirPlay targets
        - purple: validate expected telemetry under ROE only
        ROOTSTOCK_RED_LAB_WAVE16_AIRPLAY_RECEIVER_SURFACE=1
        """
        let copy = FileMarkerCopy(
            planMessage: "Dry-run AirPlay receiver dual-use plan for focus [\(focus)]: would write plan at \(markerURL.path). never enables AirPlay Receiver or spoofs AirPlay targets.",
            planSteps: [
                "Document AirPlay receiver dual-use review for: \(focus)",
                "Note path/meta inventory without host mutation beyond lab root",
                "Write markdown plan under lab root only",
                "Purple: validate expected telemetry under ROE only",
            ],
            planCleanup: ["Delete \(markerURL.path)"],
            applyDryRunMessage: "Dry-run: would write AirPlay receiver dual-use plan at \(markerURL.path)",
            applySuccessMessage: "Wrote AirPlay receiver dual-use plan at \(markerURL.path)",
            applySteps: ["Write AirPlay receiver dual-use plan"], applyCleanup: ["Delete \(markerURL.path)"],
            presentMessage: "AirPlay receiver dual-use plan present", absentMessage: "AirPlay receiver dual-use plan absent",
            statusPresentCleanup: ["Delete \(markerURL.path)"], statusAbsentCleanup: ["No artifact"],
            removeDryRunMessage: { exists in "Dry-run: would delete AirPlay receiver dual-use plan (exists=\(exists))" },
            removeSuccessMessage: { exists in "Removed AirPlay receiver dual-use plan (wasPresent=\(exists))" },
            removeSteps: ["Delete \(markerURL.path)"], removeCleanup: ["No system mutations expected"]
        )
        return try LabMarkerLifecycle.runFileMarker(
            actionId: Self.id, operation: request.operation, markerURL: markerURL,
            body: body, contextDryRun: context.dryRun, copy: copy
        )
    }
    public static func resolveLabRoot(params: [String: String]) -> URL { LabPaths.resolveLabRoot(params: params) }
}
