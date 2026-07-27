import Foundation
import RootstockCore

/// Lab DNS resolver dual-use review plan - documentation only.
public struct DnsResolverDualusePlanLabAction: LabAction {
    public static let id = "lab.surface.dns_resolver_dualuse_plan"
    public static let consent = ConsentPolicy.labDefault
    public static let riskClass = RiskClass.labOnly
    public init() {}
    public func run(request: LabActionRequest, context: EvaluationContext) async throws -> ActionResult {
        try SafetyRails.ensureLabConsent(context: context, policy: Self.consent)
        let labRoot = LabPaths.resolveLabRoot(params: request.parameters)
        let focus = request.parameters["focus"] ?? "DNS resolver dual-use"
        let markerURL = labRoot.appendingPathComponent("dns_resolver_dualuse-plan", isDirectory: true)
            .appendingPathComponent("dns_resolver_dualuse-plan.md")
        let body = """
        # rootstock-red-lab DNS resolver dual-use plan
        focus: \(focus)
        purpose: DNS resolver / mDNSResponder dual-use surface posture documentation
        rules:
        - document path/meta inventory only under consent
        - never rewrites resolver config or poisons DNS caches
        - purple: validate expected telemetry under ROE only
        ROOTSTOCK_RED_LAB_WAVE14_DNS_RESOLVER_DUALUSE=1
        """
        let copy = FileMarkerCopy(
            planMessage: "Dry-run DNS resolver dual-use plan for focus [\(focus)]: would write plan at \(markerURL.path). never rewrites resolver config or poisons DNS caches.",
            planSteps: [
                "Document DNS resolver dual-use review for: \(focus)",
                "Note path/meta inventory without host mutation beyond lab root",
                "Write markdown plan under lab root only",
                "Purple: validate expected telemetry under ROE only",
            ],
            planCleanup: ["Delete \(markerURL.path)"],
            applyDryRunMessage: "Dry-run: would write DNS resolver dual-use plan at \(markerURL.path)",
            applySuccessMessage: "Wrote DNS resolver dual-use plan at \(markerURL.path)",
            applySteps: ["Write DNS resolver dual-use plan"], applyCleanup: ["Delete \(markerURL.path)"],
            presentMessage: "DNS resolver dual-use plan present", absentMessage: "DNS resolver dual-use plan absent",
            statusPresentCleanup: ["Delete \(markerURL.path)"], statusAbsentCleanup: ["No artifact"],
            removeDryRunMessage: { exists in "Dry-run: would delete DNS resolver dual-use plan (exists=\(exists))" },
            removeSuccessMessage: { exists in "Removed DNS resolver dual-use plan (wasPresent=\(exists))" },
            removeSteps: ["Delete \(markerURL.path)"], removeCleanup: ["No system mutations expected"]
        )
        return try LabMarkerLifecycle.runFileMarker(
            actionId: Self.id, operation: request.operation, markerURL: markerURL,
            body: body, contextDryRun: context.dryRun, copy: copy
        )
    }
    public static func resolveLabRoot(params: [String: String]) -> URL { LabPaths.resolveLabRoot(params: params) }
}
