import Foundation
import RootstockCore

/// Lab authorized-rights review plan - documentation + reversible marker only.
///
/// Research basis: auth.db rights inventory themes.
/// Safety and behavior: never edits /var/db/auth.db; lab-root marker only.
public struct AuthRightsPlanLabAction: LabAction {
    public static let id = "lab.surface.auth_rights_plan"
    public static let consent = ConsentPolicy.labDefault
    public static let riskClass = RiskClass.labOnly

    public init() {}

    public func run(
        request: LabActionRequest,
        context: EvaluationContext
    ) async throws -> ActionResult {

        try SafetyRails.ensureLabConsent(context: context, policy: Self.consent)
        let labRoot = LabPaths.resolveLabRoot(params: request.parameters)
        let rights = request.parameters["rights"] ?? "system.preferences,system.install.software"
        let markerURL = labRoot
            .appendingPathComponent("auth-rights-plan", isDirectory: true)
            .appendingPathComponent("auth-plan.md")
        let body = """
        # rootstock-red-lab authorized rights plan
        rights: \(rights)
        purpose: documentation for auth rights review (not mutation)
        rules:
        - inventory and document only
        - never edit /var/db/auth.db
        - never run security authorizationdb write/remove
        - purple: expect OPEN of auth artifacts if read under separate ROE
        ROOTSTOCK_RED_LAB_AUTH_RIGHTS=1
        """
        let copy = FileMarkerCopy(
            planMessage: """
            Dry-run authorized-rights plan for rights [\(rights)]: would write plan at \
            \(markerURL.path). Never edits /var/db/auth.db.
            """,
            planSteps: [
                "Document review procedure for rights: \(rights)",
                "Prefer offline / export-based inventory over live authdb mutation",
                "Write markdown plan under lab root only",
                "Never edit /var/db/auth.db or security authorizationdb write",
            ],
            planCleanup: [
                "Delete \(markerURL.path)",
                "Confirm auth.db was never modified",
            ],
            applyDryRunMessage: "Dry-run: would write auth rights plan at \(markerURL.path)",
            applySuccessMessage: "Wrote auth rights plan at \(markerURL.path)",
            applySteps: ["Write auth rights plan"],
            applyCleanup: ["Delete \(markerURL.path)"],
            presentMessage: "Auth rights plan present",
            absentMessage: "Auth rights plan absent",
            statusPresentCleanup: ["Delete \(markerURL.path)"],
            statusAbsentCleanup: ["No artifact"],
            removeDryRunMessage: { exists in "Dry-run: would delete auth rights plan (exists=\(exists))" },
            removeSuccessMessage: { exists in "Removed auth rights plan (wasPresent=\(exists))" },
            removeSteps: ["Delete \(markerURL.path)"],
            removeCleanup: ["/var/db/auth.db was never edited by this action"]
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
