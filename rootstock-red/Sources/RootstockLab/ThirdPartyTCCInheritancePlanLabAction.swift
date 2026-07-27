import Foundation
import RootstockCore

/// Lab third-party TCC inheritance review plan - documentation only.
public struct ThirdPartyTCCInheritancePlanLabAction: LabAction {
    public static let id = "lab.surface.third_party_tcc_inheritance_plan"
    public static let consent = ConsentPolicy.labDefault
    public static let riskClass = RiskClass.labOnly

    public init() {}

    public func run(
        request: LabActionRequest,
        context: EvaluationContext
    ) async throws -> ActionResult {

        try SafetyRails.ensureLabConsent(context: context, policy: Self.consent)
        let labRoot = LabPaths.resolveLabRoot(params: request.parameters)
        let focus = request.parameters["focus"] ?? "electron,thick-client,interpreters"
        let markerURL = labRoot
            .appendingPathComponent("third-party-tcc-inheritance-plan", isDirectory: true)
            .appendingPathComponent("tcc-inheritance-plan.md")
        let body = """
        # rootstock-red-lab third-party TCC inheritance plan
        focus: \(focus)
        purpose: thick-client / embedded-interpreter TCC inheritance posture documentation
        rules:
        - document app/interpreter path inventory only under consent
        - never forge TCC grants or modify TCC databases
        - never strip entitlements or weaponize Electron inheritance
        - purple: expect OPEN of app bundle paths if inspected under ROE
        ROOTSTOCK_RED_LAB_THIRD_PARTY_TCC_INHERITANCE=1
        """
        let copy = FileMarkerCopy(
            planMessage: """
            Dry-run third-party TCC inheritance plan for focus [\(focus)]: would write plan at \
            \(markerURL.path). Never forges TCC grants.
            """,
            planSteps: [
                "Document TCC inheritance review for: \(focus)",
                "Note thick-client/interpreter path presence without grant mutation",
                "Write markdown plan under lab root only",
                "Never forge TCC grants or strip entitlements",
            ],
            planCleanup: ["Delete \(markerURL.path)"],
            applyDryRunMessage: "Dry-run: would write TCC inheritance plan at \(markerURL.path)",
            applySuccessMessage: "Wrote TCC inheritance plan at \(markerURL.path)",
            applySteps: ["Write TCC inheritance plan"],
            applyCleanup: ["Delete \(markerURL.path)"],
            presentMessage: "TCC inheritance plan present",
            absentMessage: "TCC inheritance plan absent",
            statusPresentCleanup: ["Delete \(markerURL.path)"],
            statusAbsentCleanup: ["No artifact"],
            removeDryRunMessage: { exists in "Dry-run: would delete TCC inheritance plan (exists=\(exists))" },
            removeSuccessMessage: { exists in "Removed TCC inheritance plan (wasPresent=\(exists))" },
            removeSteps: ["Delete \(markerURL.path)"],
            removeCleanup: ["No TCC grants were forged"]
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
