import Foundation
import RootstockCore

/// Lab security management-plane observation plan - documentation only.
public struct SecurityMgmtPlanePlanLabAction: LabAction {
    public static let id = "lab.surface.security_mgmt_plane_plan"
    public static let consent = ConsentPolicy.labDefault
    public static let riskClass = RiskClass.labOnly

    public init() {}

    public func run(
        request: LabActionRequest,
        context: EvaluationContext
    ) async throws -> ActionResult {

        try SafetyRails.ensureLabConsent(context: context, policy: Self.consent)
        let labRoot = LabPaths.resolveLabRoot(params: request.parameters)
        let focus = request.parameters["focus"] ?? "systemextensionsctl,helpers,unload-class"
        let markerURL = labRoot
            .appendingPathComponent("security-mgmt-plane-plan", isDirectory: true)
            .appendingPathComponent("mgmt-plane-plan.md")
        let body = """
        # rootstock-red-lab security management-plane plan
        focus: \(focus)
        purpose: security-product management-plane / unload-class posture documentation
        rules:
        - document management CLI/helper path inventory only under consent
        - never unload system extensions or stop EDR agents
        - never send stop/unload XPC to security products
        - purple: expect EXEC of systemextensionsctl only if operator explicitly inspects under ROE
        ROOTSTOCK_RED_LAB_SECURITY_MGMT_PLANE=1
        """
        let copy = FileMarkerCopy(
            planMessage: """
            Dry-run security management-plane plan for focus [\(focus)]: would write plan at \
            \(markerURL.path). Never unloads sensors or system extensions.
            """,
            planSteps: [
                "Document management-plane unload-class review for: \(focus)",
                "Note CLI/helper path presence without calling unload",
                "Write markdown plan under lab root only",
                "Never stop EDR agents or weaponize management XPC",
            ],
            planCleanup: ["Delete \(markerURL.path)"],
            applyDryRunMessage: "Dry-run: would write security management-plane plan at \(markerURL.path)",
            applySuccessMessage: "Wrote security management-plane plan at \(markerURL.path)",
            applySteps: ["Write security management-plane plan"],
            applyCleanup: ["Delete \(markerURL.path)"],
            presentMessage: "Security mgmt-plane plan present",
            absentMessage: "Security mgmt-plane plan absent",
            statusPresentCleanup: ["Delete \(markerURL.path)"],
            statusAbsentCleanup: ["No artifact"],
            removeDryRunMessage: { exists in "Dry-run: would delete security mgmt-plane plan (exists=\(exists))" },
            removeSuccessMessage: { exists in "Removed security mgmt-plane plan (wasPresent=\(exists))" },
            removeSteps: ["Delete \(markerURL.path)"],
            removeCleanup: ["No sensors were unloaded"]
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
