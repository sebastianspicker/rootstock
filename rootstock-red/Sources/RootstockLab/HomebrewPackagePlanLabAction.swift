import Foundation
import RootstockCore

/// Lab Homebrew package dual-use review plan - documentation only.
public struct HomebrewPackagePlanLabAction: LabAction {
    public static let id = "lab.surface.homebrew_package_plan"
    public static let consent = ConsentPolicy.labDefault
    public static let riskClass = RiskClass.labOnly
    public init() {}
    public func run(request: LabActionRequest, context: EvaluationContext) async throws -> ActionResult {
        try SafetyRails.ensureLabConsent(context: context, policy: Self.consent)
        let labRoot = LabPaths.resolveLabRoot(params: request.parameters)
        let focus = request.parameters["focus"] ?? "Homebrew package dual-use"
        let markerURL = labRoot.appendingPathComponent("homebrew_pkg-plan", isDirectory: true)
            .appendingPathComponent("homebrew_pkg-plan.md")
        let body = """
        # rootstock-red-lab Homebrew package dual-use plan
        focus: \(focus)
        purpose: Homebrew / third-party package manager dual-use posture documentation
        rules:
        - document path/meta inventory only under consent
        - never installs packages or modifies Homebrew formulae
        - purple: validate expected telemetry under ROE only
        ROOTSTOCK_RED_LAB_WAVE13_HOMEBREW_PKG=1
        """
        let copy = FileMarkerCopy(
            planMessage: "Dry-run Homebrew package dual-use plan for focus [\(focus)]: would write plan at \(markerURL.path). never installs packages or modifies Homebrew formulae.",
            planSteps: [
                "Document Homebrew package dual-use review for: \(focus)",
                "Note path/meta inventory without host mutation beyond lab root",
                "Write markdown plan under lab root only",
                "Purple: validate expected telemetry under ROE only",
            ],
            planCleanup: ["Delete \(markerURL.path)"],
            applyDryRunMessage: "Dry-run: would write Homebrew package dual-use plan at \(markerURL.path)",
            applySuccessMessage: "Wrote Homebrew package dual-use plan at \(markerURL.path)",
            applySteps: ["Write Homebrew package dual-use plan"],
            applyCleanup: ["Delete \(markerURL.path)"],
            presentMessage: "Homebrew package dual-use plan present",
            absentMessage: "Homebrew package dual-use plan absent",
            statusPresentCleanup: ["Delete \(markerURL.path)"],
            statusAbsentCleanup: ["No artifact"],
            removeDryRunMessage: { exists in "Dry-run: would delete Homebrew package dual-use plan (exists=\(exists))" },
            removeSuccessMessage: { exists in "Removed Homebrew package dual-use plan (wasPresent=\(exists))" },
            removeSteps: ["Delete \(markerURL.path)"],
            removeCleanup: ["No system mutations expected"]
        )
        return try LabMarkerLifecycle.runFileMarker(
            actionId: Self.id, operation: request.operation, markerURL: markerURL,
            body: body, contextDryRun: context.dryRun, copy: copy
        )
    }
    public static func resolveLabRoot(params: [String: String]) -> URL { LabPaths.resolveLabRoot(params: params) }
}
