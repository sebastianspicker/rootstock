import Foundation
import RootstockCore

/// Lab iCloud Drive path plane review plan - documentation only.
public struct IcloudDrivePathPlanLabAction: LabAction {
    public static let id = "lab.surface.icloud_drive_path_plan"
    public static let consent = ConsentPolicy.labDefault
    public static let riskClass = RiskClass.labOnly
    public init() {}
    public func run(request: LabActionRequest, context: EvaluationContext) async throws -> ActionResult {
        try SafetyRails.ensureLabConsent(context: context, policy: Self.consent)
        let labRoot = LabPaths.resolveLabRoot(params: request.parameters)
        let focus = request.parameters["focus"] ?? "iCloud Drive path plane"
        let markerURL = labRoot.appendingPathComponent("icloud_drive_path-plan", isDirectory: true)
            .appendingPathComponent("icloud_drive_path-plan.md")
        let body = """
        # rootstock-red-lab iCloud Drive path plane plan
        focus: \(focus)
        purpose: iCloud Drive / Mobile Documents path plane posture documentation
        rules:
        - document path/meta inventory only under consent
        - never enumerates iCloud file contents or exfiltrates Mobile Documents
        - purple: validate expected telemetry under ROE only
        ROOTSTOCK_RED_LAB_WAVE14_ICLOUD_DRIVE_PATH=1
        """
        let copy = FileMarkerCopy(
            planMessage: "Dry-run iCloud Drive path plane plan for focus [\(focus)]: would write plan at \(markerURL.path). never enumerates iCloud file contents or exfiltrates Mobile Documents.",
            planSteps: [
                "Document iCloud Drive path plane review for: \(focus)",
                "Note path/meta inventory without host mutation beyond lab root",
                "Write markdown plan under lab root only",
                "Purple: validate expected telemetry under ROE only",
            ],
            planCleanup: ["Delete \(markerURL.path)"],
            applyDryRunMessage: "Dry-run: would write iCloud Drive path plane plan at \(markerURL.path)",
            applySuccessMessage: "Wrote iCloud Drive path plane plan at \(markerURL.path)",
            applySteps: ["Write iCloud Drive path plane plan"], applyCleanup: ["Delete \(markerURL.path)"],
            presentMessage: "iCloud Drive path plane plan present", absentMessage: "iCloud Drive path plane plan absent",
            statusPresentCleanup: ["Delete \(markerURL.path)"], statusAbsentCleanup: ["No artifact"],
            removeDryRunMessage: { exists in "Dry-run: would delete iCloud Drive path plane plan (exists=\(exists))" },
            removeSuccessMessage: { exists in "Removed iCloud Drive path plane plan (wasPresent=\(exists))" },
            removeSteps: ["Delete \(markerURL.path)"], removeCleanup: ["No system mutations expected"]
        )
        return try LabMarkerLifecycle.runFileMarker(
            actionId: Self.id, operation: request.operation, markerURL: markerURL,
            body: body, contextDryRun: context.dryRun, copy: copy
        )
    }
    public static func resolveLabRoot(params: [String: String]) -> URL { LabPaths.resolveLabRoot(params: params) }
}
