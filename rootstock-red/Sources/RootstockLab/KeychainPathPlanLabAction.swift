import Foundation
import RootstockCore

/// Lab keychain path assessment plan - path inventory documentation only; never dumps keychain.
///
/// Research basis: PEASS / red-team keychain path inventory themes.
/// Safety and behavior: lab-root marker only; consent + dry-run; no security dump-keychain / secret reads.
public struct KeychainPathPlanLabAction: LabAction {
    public static let id = "lab.surface.keychain_path_plan"
    public static let consent = ConsentPolicy.labDefault
    public static let riskClass = RiskClass.labOnly

    public static let techniqueNote = """
    Technique documentation (alpha - path assessment only): operators assess presence of \
    login.keychain-db, System.keychain, and related paths as high-value surfaces. Rootstock Red Lab \
    never runs `security dump-keychain`, never exports items, and never reads secret blobs; it only \
    documents path-assessment steps and may plant a lab-root marker for purple file events.
    """

    public init() {}

    public func run(
        request: LabActionRequest,
        context: EvaluationContext
    ) async throws -> ActionResult {

        try SafetyRails.ensureLabConsent(context: context, policy: Self.consent)
        let labRoot = LabPaths.resolveLabRoot(params: request.parameters)
        let markerURL = labRoot
            .appendingPathComponent("keychain-path-plan", isDirectory: true)
            .appendingPathComponent("assessment.marker")
        let body = """
        # rootstock-red-lab keychain path plan marker
        # PATH ASSESSMENT ONLY - not a dump-keychain artifact
        ROOTSTOCK_RED_LAB_KEYCHAIN_PATH_PLAN=1
        NEVER_DUMP_KEYCHAIN=1
        HARMLESS=1
        """
        let copy = FileMarkerCopy(
            planMessage: """
            Dry-run keychain path plan: document path-existence assessment only; optional marker \
            at \(markerURL.path). Never dump-keychain or export items.
            """,
            planSteps: [
                "Inventory common keychain paths (existence / metadata only)",
                "Do not run security dump-keychain, find-generic-password, or item export",
                "Optional lab marker: \(markerURL.path)",
                Self.techniqueNote,
            ],
            planCleanup: [
                "Delete \(markerURL.path) if planted",
                "Confirm no keychain DB files were read for secrets",
            ],
            applyDryRunMessage: "Dry-run: would write keychain path plan marker at \(markerURL.path)",
            applySuccessMessage: "Wrote keychain path plan marker at \(markerURL.path) (no keychain dump)",
            applySteps: [
            "Write keychain path-assessment marker under lab root only",
            "Refuse dump-keychain / secret extraction",
        ],
            applyCleanup: ["Delete \(markerURL.path)"],
            presentMessage: "Keychain path plan marker present",
            absentMessage: "Keychain path plan marker absent",
            statusPresentCleanup: ["Delete \(markerURL.path)"],
            statusAbsentCleanup: ["No artifact"],
            removeDryRunMessage: { exists in "Dry-run: would delete keychain path plan marker (exists=\(exists))" },
            removeSuccessMessage: { exists in "Removed keychain path plan marker (wasPresent=\(exists))" },
            removeSteps: ["Delete \(markerURL.path)"],
            removeCleanup: ["Keychain DBs never dumped by this action"]
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
