import Foundation
import RootstockCore

/// Lab Remote Apple Events / EPPC review plan - documentation only.
public struct RemoteAppleEventsPlanLabAction: LabAction {
    public static let id = "lab.surface.remote_apple_events_plan"
    public static let consent = ConsentPolicy.labDefault
    public static let riskClass = RiskClass.labOnly

    public init() {}

    public func run(
        request: LabActionRequest,
        context: EvaluationContext
    ) async throws -> ActionResult {

        try SafetyRails.ensureLabConsent(context: context, policy: Self.consent)
        let labRoot = LabPaths.resolveLabRoot(params: request.parameters)
        let focus = request.parameters["focus"] ?? "remote-ae,eppc,ard"
        let markerURL = labRoot
            .appendingPathComponent("remote-apple-events-plan", isDirectory: true)
            .appendingPathComponent("rae-plan.md")
        let body = """
        # rootstock-red-lab Remote Apple Events plan
        focus: \(focus)
        purpose: RAE/EPPC lateral posture documentation
        rules:
        - document Sharing/Remote Management path inventory only under consent
        - never enable Remote Apple Events
        - never send remote AppleEvents or craft EPPC lateral malware
        - purple: expect OPEN of RemoteManagement prefs if inspected under ROE
        ROOTSTOCK_RED_LAB_REMOTE_APPLE_EVENTS=1
        """
        let copy = FileMarkerCopy(
            planMessage: """
            Dry-run Remote Apple Events plan for focus [\(focus)]: would write plan at \
            \(markerURL.path). Never enables RAE or sends AppleEvents.
            """,
            planSteps: [
                "Document remote automation lateral review for: \(focus)",
                "Note pref/framework path presence without enabling services",
                "Write markdown plan under lab root only",
                "Never send remote AppleEvents or weaponize EPPC",
            ],
            planCleanup: ["Delete \(markerURL.path)"],
            applyDryRunMessage: "Dry-run: would write Remote Apple Events plan at \(markerURL.path)",
            applySuccessMessage: "Wrote Remote Apple Events plan at \(markerURL.path)",
            applySteps: ["Write Remote Apple Events plan"],
            applyCleanup: ["Delete \(markerURL.path)"],
            presentMessage: "Remote Apple Events plan present",
            absentMessage: "Remote Apple Events plan absent",
            statusPresentCleanup: ["Delete \(markerURL.path)"],
            statusAbsentCleanup: ["No artifact"],
            removeDryRunMessage: { exists in "Dry-run: would delete Remote Apple Events plan (exists=\(exists))" },
            removeSuccessMessage: { exists in "Removed Remote Apple Events plan (wasPresent=\(exists))" },
            removeSteps: ["Delete \(markerURL.path)"],
            removeCleanup: ["No remote AppleEvents were sent"]
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
