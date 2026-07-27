import Foundation
import RootstockCore

/// Lab Bluetooth Continuity depth review plan - documentation only.
public struct BluetoothContinuityDepthPlanLabAction: LabAction {
    public static let id = "lab.surface.bluetooth_continuity_depth_plan"
    public static let consent = ConsentPolicy.labDefault
    public static let riskClass = RiskClass.labOnly
    public init() {}
    public func run(request: LabActionRequest, context: EvaluationContext) async throws -> ActionResult {
        try SafetyRails.ensureLabConsent(context: context, policy: Self.consent)
        let labRoot = LabPaths.resolveLabRoot(params: request.parameters)
        let focus = request.parameters["focus"] ?? "Bluetooth Continuity depth"
        let markerURL = labRoot.appendingPathComponent("bluetooth_continuity_depth-plan", isDirectory: true)
            .appendingPathComponent("bluetooth_continuity_depth-plan.md")
        let body = """
        # rootstock-red-lab Bluetooth Continuity depth plan
        focus: \(focus)
        purpose: Bluetooth / Continuity proximity residual depth posture documentation
        rules:
        - document path/meta inventory only under consent
        - never enables Bluetooth pairing or spoofs Continuity identities
        - purple: validate expected telemetry under ROE only
        ROOTSTOCK_RED_LAB_WAVE14_BLUETOOTH_CONTINUITY_DEPTH=1
        """
        let copy = FileMarkerCopy(
            planMessage: "Dry-run Bluetooth Continuity depth plan for focus [\(focus)]: would write plan at \(markerURL.path). never enables Bluetooth pairing or spoofs Continuity identities.",
            planSteps: [
                "Document Bluetooth Continuity depth review for: \(focus)",
                "Note path/meta inventory without host mutation beyond lab root",
                "Write markdown plan under lab root only",
                "Purple: validate expected telemetry under ROE only",
            ],
            planCleanup: ["Delete \(markerURL.path)"],
            applyDryRunMessage: "Dry-run: would write Bluetooth Continuity depth plan at \(markerURL.path)",
            applySuccessMessage: "Wrote Bluetooth Continuity depth plan at \(markerURL.path)",
            applySteps: ["Write Bluetooth Continuity depth plan"], applyCleanup: ["Delete \(markerURL.path)"],
            presentMessage: "Bluetooth Continuity depth plan present", absentMessage: "Bluetooth Continuity depth plan absent",
            statusPresentCleanup: ["Delete \(markerURL.path)"], statusAbsentCleanup: ["No artifact"],
            removeDryRunMessage: { exists in "Dry-run: would delete Bluetooth Continuity depth plan (exists=\(exists))" },
            removeSuccessMessage: { exists in "Removed Bluetooth Continuity depth plan (wasPresent=\(exists))" },
            removeSteps: ["Delete \(markerURL.path)"], removeCleanup: ["No system mutations expected"]
        )
        return try LabMarkerLifecycle.runFileMarker(
            actionId: Self.id, operation: request.operation, markerURL: markerURL,
            body: body, contextDryRun: context.dryRun, copy: copy
        )
    }
    public static func resolveLabRoot(params: [String: String]) -> URL { LabPaths.resolveLabRoot(params: params) }
}
