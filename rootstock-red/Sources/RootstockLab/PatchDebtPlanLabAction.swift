import Foundation
import RootstockCore

/// Lab patch-debt documentation plan - suggester context only (no exploit download).
public struct PatchDebtPlanLabAction: LabAction {
    public static let id = "lab.surface.patch_debt_plan"
    public static let consent = ConsentPolicy.labDefault
    public static let riskClass = RiskClass.labOnly

    public init() {}

    public func run(
        request: LabActionRequest,
        context: EvaluationContext
    ) async throws -> ActionResult {

        try SafetyRails.ensureLabConsent(context: context, policy: Self.consent)
        let labRoot = LabPaths.resolveLabRoot(params: request.parameters)
        let osVersion = request.parameters["osVersion"] ?? "unknown"
        let markerURL = labRoot
            .appendingPathComponent("patch-debt-plan", isDirectory: true)
            .appendingPathComponent("patch-debt-plan.md")
        let body = """
        # rootstock-red-lab patch-debt plan
        osVersion: \(osVersion)
        purpose: CVE class suggester documentation (not exploit pack)
        rules:
        - map ProductBuildVersion to Apple security content
        - confidence stays low until build-matched
        - no exploit download
        ROOTSTOCK_RED_LAB_PATCH_DEBT=1
        """
        let copy = FileMarkerCopy(
            planMessage: """
            Dry-run patch-debt plan for os=\(osVersion): would write documentation at \
            \(markerURL.path). No CVE exploit pack download.
            """,
            planSteps: [
                "Record OS version context: \(osVersion)",
                "Map build to Apple security updates offline",
                "Write suggester notes under lab root only",
                "Never fetch or execute exploit PoCs",
            ],
            planCleanup: ["Delete \(markerURL.path)"],
            applyDryRunMessage: "Dry-run: would write patch-debt plan at \(markerURL.path)",
            applySuccessMessage: "Wrote patch-debt plan at \(markerURL.path)",
            applySteps: ["Write patch-debt plan"],
            applyCleanup: ["Delete \(markerURL.path)"],
            presentMessage: "Patch-debt plan present",
            absentMessage: "Patch-debt plan absent",
            statusPresentCleanup: ["Delete \(markerURL.path)"],
            statusAbsentCleanup: ["No artifact"],
            removeDryRunMessage: { exists in "Dry-run: would delete patch-debt plan (exists=\(exists))" },
            removeSuccessMessage: { exists in "Removed patch-debt plan (wasPresent=\(exists))" },
            removeSteps: ["Delete \(markerURL.path)"],
            removeCleanup: ["No host updates applied by this action"]
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
