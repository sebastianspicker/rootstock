import Foundation
import RootstockCore

/// Lab notarization / stapling review plan - documentation + reversible marker only.
public struct NotarizationPlanLabAction: LabAction {
    public static let id = "lab.surface.notarization_plan"
    public static let consent = ConsentPolicy.labDefault
    public static let riskClass = RiskClass.labOnly

    public init() {}

    public func run(
        request: LabActionRequest,
        context: EvaluationContext
    ) async throws -> ActionResult {

        try SafetyRails.ensureLabConsent(context: context, policy: Self.consent)
        let labRoot = LabPaths.resolveLabRoot(params: request.parameters)
        let focus = request.parameters["focus"] ?? "stapler,spctl,delivery-artifacts"
        let markerURL = labRoot
            .appendingPathComponent("notarization-plan", isDirectory: true)
            .appendingPathComponent("notarization-plan.md")
        let body = """
        # rootstock-red-lab notarization plan
        focus: \(focus)
        purpose: delivery-trust / stapling posture documentation
        rules:
        - document spctl/stapler tooling and delivery artifacts only under consent
        - never forge notarization tickets
        - never provide Gatekeeper bypass recipes
        - purple: expect OPEN of Downloads/DMG paths if inspected under ROE
        ROOTSTOCK_RED_LAB_NOTARIZATION=1
        """
        let copy = FileMarkerCopy(
            planMessage: """
            Dry-run notarization plan for focus [\(focus)]: would write plan at \
            \(markerURL.path). Never forges tickets or bypasses Gatekeeper.
            """,
            planSteps: [
                "Document notarization/stapling review for: \(focus)",
                "Note delivery artifacts without ticket forgery",
                "Write markdown plan under lab root only",
                "Never run Gatekeeper bypass or stapler abuse sequences",
            ],
            planCleanup: ["Delete \(markerURL.path)"],
            applyDryRunMessage: "Dry-run: would write notarization plan at \(markerURL.path)",
            applySuccessMessage: "Wrote notarization plan at \(markerURL.path)",
            applySteps: ["Write notarization plan"],
            applyCleanup: ["Delete \(markerURL.path)"],
            presentMessage: "Notarization plan present",
            absentMessage: "Notarization plan absent",
            statusPresentCleanup: ["Delete \(markerURL.path)"],
            statusAbsentCleanup: ["No artifact"],
            removeDryRunMessage: { exists in "Dry-run: would delete notarization plan (exists=\(exists))" },
            removeSuccessMessage: { exists in "Removed notarization plan (wasPresent=\(exists))" },
            removeSteps: ["Delete \(markerURL.path)"],
            removeCleanup: ["No notarization tickets were modified"]
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
