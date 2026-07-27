import Foundation
import RootstockCore

/// Lab Network share mount review plan - documentation only.
public struct NetworkShareMountPlanLabAction: LabAction {
    public static let id = "lab.surface.network_share_mount_plan"
    public static let consent = ConsentPolicy.labDefault
    public static let riskClass = RiskClass.labOnly

    public init() {}

    public func run(
        request: LabActionRequest,
        context: EvaluationContext
    ) async throws -> ActionResult {

        try SafetyRails.ensureLabConsent(context: context, policy: Self.consent)
        let labRoot = LabPaths.resolveLabRoot(params: request.parameters)
        let focus = request.parameters["focus"] ?? "Network share mount"
        let markerURL = labRoot
            .appendingPathComponent("network_share-plan", isDirectory: true)
            .appendingPathComponent("network_share-plan.md")
        let body = """
        # rootstock-red-lab Network share mount plan
        focus: \(focus)
        purpose: Network share / SMB mount dual-use lateral posture documentation
        rules:
        - document path/meta inventory only under consent
        - never mounts attacker shares or writes credentials to NetAuth
        - purple: validate expected telemetry under ROE only
        ROOTSTOCK_RED_LAB_WAVE12_NETWORK_SHARE=1
        """
        let copy = FileMarkerCopy(
            planMessage: """
            Dry-run Network share mount plan for focus [\(focus)]: would write plan at             \(markerURL.path). never mounts attacker shares or writes credentials to NetAuth.
            """,
            planSteps: [
                "Document Network share mount review for: \(focus)",
                "Note path/meta inventory without host mutation beyond lab root",
                "Write markdown plan under lab root only",
                "Purple: validate expected telemetry under ROE only",
            ],
            planCleanup: ["Delete \(markerURL.path)"],
            applyDryRunMessage: "Dry-run: would write Network share mount plan at \(markerURL.path)",
            applySuccessMessage: "Wrote Network share mount plan at \(markerURL.path)",
            applySteps: ["Write Network share mount plan"],
            applyCleanup: ["Delete \(markerURL.path)"],
            presentMessage: "Network share mount plan present",
            absentMessage: "Network share mount plan absent",
            statusPresentCleanup: ["Delete \(markerURL.path)"],
            statusAbsentCleanup: ["No artifact"],
            removeDryRunMessage: { exists in "Dry-run: would delete Network share mount plan (exists=\(exists))" },
            removeSuccessMessage: { exists in "Removed Network share mount plan (wasPresent=\(exists))" },
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
