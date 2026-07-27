import Foundation
import RootstockCore

/// Lab FileVault / recovery escrow posture plan - documentation only; never key ops.
public struct FileVaultEscrowPlanLabAction: LabAction {
    public static let id = "lab.surface.filevault_escrow_plan"
    public static let consent = ConsentPolicy.labDefault
    public static let riskClass = RiskClass.labOnly

    public init() {}

    public func run(
        request: LabActionRequest,
        context: EvaluationContext
    ) async throws -> ActionResult {

        try SafetyRails.ensureLabConsent(context: context, policy: Self.consent)
        let labRoot = LabPaths.resolveLabRoot(params: request.parameters)
        let focus = request.parameters["focus"] ?? "filevault-status,escrow-paths,mdm-recovery"
        let markerURL = labRoot
            .appendingPathComponent("filevault-escrow-plan", isDirectory: true)
            .appendingPathComponent("fv-escrow-plan.md")
        let body = """
        # rootstock-red-lab FileVault escrow plan
        focus: \(focus)
        purpose: volume encryption / recovery escrow posture documentation
        rules:
        - document status class and escrow paths only under consent
        - NEVER print or extract recovery keys
        - NEVER run fdesetup auth/changerecovery/unlock abuse
        - never open FileVaultMaster.keychain for secret material
        - purple: expect OPEN of escrow preference paths if inspected under ROE
        ROOTSTOCK_RED_LAB_FILEVAULT_ESCROW=1
        """
        let copy = FileMarkerCopy(
            planMessage: """
            Dry-run FileVault/escrow plan for focus [\(focus)]: would write plan at \
            \(markerURL.path). NEVER extracts recovery keys or runs unlock recipes.
            """,
            planSteps: [
                "Document FV/escrow posture review for: \(focus)",
                "Note escrow path presence without opening keychains",
                "Write markdown plan under lab root only",
                "Never run fdesetup auth/recovery extraction",
            ],
            planCleanup: ["Delete \(markerURL.path)"],
            applyDryRunMessage: "Dry-run: would write FileVault escrow plan at \(markerURL.path)",
            applySuccessMessage: "Wrote FileVault escrow plan at \(markerURL.path)",
            applySteps: ["Write FileVault escrow plan"],
            applyCleanup: ["Delete \(markerURL.path)"],
            presentMessage: "FileVault escrow plan present",
            absentMessage: "FileVault escrow plan absent",
            statusPresentCleanup: ["Delete \(markerURL.path)"],
            statusAbsentCleanup: ["No artifact"],
            removeDryRunMessage: { exists in "Dry-run: would delete FileVault escrow plan (exists=\(exists))" },
            removeSuccessMessage: { exists in "Removed FileVault escrow plan (wasPresent=\(exists))" },
            removeSteps: ["Delete \(markerURL.path)"],
            removeCleanup: ["No recovery keys were accessed"]
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
