import Foundation
import RootstockCore

/// Lab Info-stealer path plane review plan - documentation only.
public struct InfoStealerPathPlanLabAction: LabAction {
    public static let id = "lab.surface.infostealer_path_plan"
    public static let consent = ConsentPolicy.labDefault
    public static let riskClass = RiskClass.labOnly

    public init() {}

    public func run(
        request: LabActionRequest,
        context: EvaluationContext
    ) async throws -> ActionResult {

        try SafetyRails.ensureLabConsent(context: context, policy: Self.consent)
        let labRoot = LabPaths.resolveLabRoot(params: request.parameters)
        let focus = request.parameters["focus"] ?? "browser,mail,messages,vaults,wallets"
        let markerURL = labRoot
            .appendingPathComponent("infostealer-path-plan", isDirectory: true)
            .appendingPathComponent("infostealer-path-plan.md")
        let body = """
        # rootstock-red-lab Info-stealer path plane plan
        focus: \(focus)
        purpose: Info-stealer path plane posture documentation
        rules:
        - document multi-app collection path inventory only under consent
        - never dump cookies, passwords, keychain items, or wallet material
        - never harvest Messages/Mail contents
        - purple: expect OPEN/READ of high-value app data stores if inspected under ROE
        ROOTSTOCK_RED_LAB_INFOSTEALER_PATH=1
        """
        let copy = FileMarkerCopy(
            planMessage: """
            Dry-run Info-stealer path plane plan for focus [\(focus)]: would write plan at \
            \(markerURL.path). Never dumps secrets or stealer payloads.
            """,
            planSteps: [
                "Document Info-stealer path plane review for: \(focus)",
                "Note path/meta inventory without host mutation beyond lab root",
                "Write markdown plan under lab root only",
                "Purple: validate expected telemetry under ROE only",
            ],
            planCleanup: ["Delete \(markerURL.path)"],
            applyDryRunMessage: "Dry-run: would write Info-stealer path plane plan at \(markerURL.path)",
            applySuccessMessage: "Wrote Info-stealer path plane plan at \(markerURL.path)",
            applySteps: ["Write Info-stealer path plane plan"],
            applyCleanup: ["Delete \(markerURL.path)"],
            presentMessage: "Info-stealer path plane plan present",
            absentMessage: "Info-stealer path plane plan absent",
            statusPresentCleanup: ["Delete \(markerURL.path)"],
            statusAbsentCleanup: ["No artifact"],
            removeDryRunMessage: { exists in "Dry-run: would delete Info-stealer path plane plan (exists=\(exists))" },
            removeSuccessMessage: { exists in "Removed Info-stealer path plane plan (wasPresent=\(exists))" },
            removeSteps: ["Delete \(markerURL.path)"],
            removeCleanup: ["No secret harvest expected"]
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
