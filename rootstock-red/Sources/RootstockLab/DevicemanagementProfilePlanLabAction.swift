import Foundation
import RootstockCore

/// Lab Device management profile review plan - documentation only.
public struct DevicemanagementProfilePlanLabAction: LabAction {
    public static let id = "lab.surface.devicemanagement_profile_plan"
    public static let consent = ConsentPolicy.labDefault
    public static let riskClass = RiskClass.labOnly
    public init() {}
    public func run(request: LabActionRequest, context: EvaluationContext) async throws -> ActionResult {
        try SafetyRails.ensureLabConsent(context: context, policy: Self.consent)
        let labRoot = LabPaths.resolveLabRoot(params: request.parameters)
        let focus = request.parameters["focus"] ?? "Device management profile"
        let markerURL = labRoot.appendingPathComponent("devicemanagement_profile-plan", isDirectory: true)
            .appendingPathComponent("devicemanagement_profile-plan.md")
        let body = """
        # rootstock-red-lab Device management profile plan
        focus: \(focus)
        purpose: Device management profile residual depth posture documentation
        rules:
        - document path/meta inventory only under consent
        - never installs configuration profiles or enrolls hosts in MDM
        - purple: validate expected telemetry under ROE only
        ROOTSTOCK_RED_LAB_WAVE16_DEVICEMANAGEMENT_PROFILE=1
        """
        let copy = FileMarkerCopy(
            planMessage: "Dry-run Device management profile plan for focus [\(focus)]: would write plan at \(markerURL.path). never installs configuration profiles or enrolls hosts in MDM.",
            planSteps: [
                "Document Device management profile review for: \(focus)",
                "Note path/meta inventory without host mutation beyond lab root",
                "Write markdown plan under lab root only",
                "Purple: validate expected telemetry under ROE only",
            ],
            planCleanup: ["Delete \(markerURL.path)"],
            applyDryRunMessage: "Dry-run: would write Device management profile plan at \(markerURL.path)",
            applySuccessMessage: "Wrote Device management profile plan at \(markerURL.path)",
            applySteps: ["Write Device management profile plan"], applyCleanup: ["Delete \(markerURL.path)"],
            presentMessage: "Device management profile plan present", absentMessage: "Device management profile plan absent",
            statusPresentCleanup: ["Delete \(markerURL.path)"], statusAbsentCleanup: ["No artifact"],
            removeDryRunMessage: { exists in "Dry-run: would delete Device management profile plan (exists=\(exists))" },
            removeSuccessMessage: { exists in "Removed Device management profile plan (wasPresent=\(exists))" },
            removeSteps: ["Delete \(markerURL.path)"], removeCleanup: ["No system mutations expected"]
        )
        return try LabMarkerLifecycle.runFileMarker(
            actionId: Self.id, operation: request.operation, markerURL: markerURL,
            body: body, contextDryRun: context.dryRun, copy: copy
        )
    }
    public static func resolveLabRoot(params: [String: String]) -> URL { LabPaths.resolveLabRoot(params: params) }
}
