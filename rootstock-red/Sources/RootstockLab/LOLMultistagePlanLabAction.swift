import Foundation
import RootstockCore

/// Lab multi-stage LOOBin chain plan - documentation only (no chain execution).
public struct LOLMultistagePlanLabAction: LabAction {
    public static let id = "lab.surface.lol_multistage_plan"
    public static let consent = ConsentPolicy.labDefault
    public static let riskClass = RiskClass.labOnly

    public init() {}

    public func run(
        request: LabActionRequest,
        context: EvaluationContext
    ) async throws -> ActionResult {

        try SafetyRails.ensureLabConsent(context: context, policy: Self.consent)
        let labRoot = LabPaths.resolveLabRoot(params: request.parameters)
        let chain = request.parameters["chain"] ?? "mdfind>osascript>launchctl"
        let markerURL = labRoot
            .appendingPathComponent("lol-multistage-plan", isDirectory: true)
            .appendingPathComponent("chain-plan.md")
        let body = """
        # rootstock-red-lab LOOBin multi-stage plan
        chain: \(chain)
        stages: discover → execute → persist
        esfExpected: [OPEN, EXEC]
        execute_chain: false
        ROOTSTOCK_RED_LAB_LOL_MULTISTAGE=1
        """
        let copy = FileMarkerCopy(
            planMessage: """
            Dry-run LOL multi-stage plan for chain=\(chain): would write plan at \
            \(markerURL.path). Does not execute the chain.
            """,
            planSteps: [
                "Document dual-use stages: \(chain)",
                "Prefer quieter discovery bins before osascript",
                "Purple: expect ESF EXEC per stage if ever executed under separate ROE",
                "This action never spawns the chain binaries",
            ],
            planCleanup: ["Delete \(markerURL.path)"],
            applyDryRunMessage: "Dry-run: would write LOL multi-stage plan at \(markerURL.path)",
            applySuccessMessage: "Wrote LOL multi-stage plan at \(markerURL.path)",
            applySteps: ["Write LOL multi-stage plan"],
            applyCleanup: ["Delete \(markerURL.path)"],
            presentMessage: "LOL multi-stage plan present",
            absentMessage: "LOL multi-stage plan absent",
            statusPresentCleanup: ["Delete \(markerURL.path)"],
            statusAbsentCleanup: ["No artifact"],
            removeDryRunMessage: { exists in "Dry-run: would delete LOL multi-stage plan (exists=\(exists))" },
            removeSuccessMessage: { exists in "Removed LOL multi-stage plan (wasPresent=\(exists))" },
            removeSteps: ["Delete \(markerURL.path)"],
            removeCleanup: ["Chain was never executed by this action"]
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
