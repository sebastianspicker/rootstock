import Foundation
import RootstockCore

/// Lab MDM profile parse depth review plan - documentation only.
public struct MDMProfileParsePlanLabAction: LabAction {
    public static let id = "lab.surface.mdm_profile_parse_plan"
    public static let consent = ConsentPolicy.labDefault
    public static let riskClass = RiskClass.labOnly

    public init() {}

    public func run(
        request: LabActionRequest,
        context: EvaluationContext
    ) async throws -> ActionResult {

        try SafetyRails.ensureLabConsent(context: context, policy: Self.consent)
        let labRoot = LabPaths.resolveLabRoot(params: request.parameters)
        let focus = request.parameters["focus"] ?? "mobileconfig,PayloadType,sideload"
        let markerURL = labRoot
            .appendingPathComponent("mdm-profile-parse-plan", isDirectory: true)
            .appendingPathComponent("mdm-profile-parse-plan.md")
        let body = """
        # rootstock-red-lab MDM profile parse depth plan
        focus: \(focus)
        purpose: MDM profile parse depth posture documentation
        rules:
        - document shallow PayloadType inventory only under consent
        - never dump passwords, certificates, or shared secrets from profiles
        - never install or forge configuration profiles
        - purple: expect OPEN/READ of .mobileconfig if parse observed under ROE
        ROOTSTOCK_RED_LAB_MDM_PROFILE_PARSE=1
        """
        let copy = FileMarkerCopy(
            planMessage: """
            Dry-run MDM profile parse depth plan for focus [\(focus)]: would write plan at \
            \(markerURL.path). Never installs profiles or dumps secret payload values.
            """,
            planSteps: [
                "Document MDM profile parse depth review for: \(focus)",
                "Note path/meta inventory without host mutation beyond lab root",
                "Write markdown plan under lab root only",
                "Purple: validate expected telemetry under ROE only",
            ],
            planCleanup: ["Delete \(markerURL.path)"],
            applyDryRunMessage: "Dry-run: would write MDM profile parse depth plan at \(markerURL.path)",
            applySuccessMessage: "Wrote MDM profile parse depth plan at \(markerURL.path)",
            applySteps: ["Write MDM profile parse depth plan"],
            applyCleanup: ["Delete \(markerURL.path)"],
            presentMessage: "MDM profile parse depth plan present",
            absentMessage: "MDM profile parse depth plan absent",
            statusPresentCleanup: ["Delete \(markerURL.path)"],
            statusAbsentCleanup: ["No artifact"],
            removeDryRunMessage: { exists in "Dry-run: would delete MDM profile parse depth plan (exists=\(exists))" },
            removeSuccessMessage: { exists in "Removed MDM profile parse depth plan (wasPresent=\(exists))" },
            removeSteps: ["Delete \(markerURL.path)"],
            removeCleanup: ["No profile install expected"]
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
