import Foundation
import RootstockCore

/// Lab PackageKit installer design review plan - documentation only.
public struct PackageKitInstallerPlanLabAction: LabAction {
    public static let id = "lab.surface.packagekit_installer_plan"
    public static let consent = ConsentPolicy.labDefault
    public static let riskClass = RiskClass.labOnly

    public init() {}

    public func run(
        request: LabActionRequest,
        context: EvaluationContext
    ) async throws -> ActionResult {

        try SafetyRails.ensureLabConsent(context: context, policy: Self.consent)
        let labRoot = LabPaths.resolveLabRoot(params: request.parameters)
        let focus = request.parameters["focus"] ?? "package_script_service,installd,receipts,InstallerSandboxes"
        let markerURL = labRoot
            .appendingPathComponent("packagekit-installer-plan", isDirectory: true)
            .appendingPathComponent("packagekit-plan.md")
        let body = """
        # rootstock-red-lab PackageKit installer design plan
        focus: \(focus)
        purpose: PackageKit installer design posture documentation
        rules:
        - document package_script_service / installd / receipt path inventory only under consent
        - never build malicious packages or invoke installd
        - never weaponize InstallerSandboxes or preinstall/postinstall scripts
        - purple: expect EXEC/WRITE of package services if install observed under ROE
        ROOTSTOCK_RED_LAB_PACKAGEKIT_INSTALLER=1
        """
        let copy = FileMarkerCopy(
            planMessage: """
            Dry-run PackageKit installer design plan for focus [\(focus)]: would write plan at \
            \(markerURL.path). Never builds pkgs or invokes installd.
            """,
            planSteps: [
                "Document PackageKit installer design review for: \(focus)",
                "Note path/meta inventory without host mutation beyond lab root",
                "Write markdown plan under lab root only",
                "Purple: validate expected telemetry under ROE only",
            ],
            planCleanup: ["Delete \(markerURL.path)"],
            applyDryRunMessage: "Dry-run: would write PackageKit installer design plan at \(markerURL.path)",
            applySuccessMessage: "Wrote PackageKit installer design plan at \(markerURL.path)",
            applySteps: ["Write PackageKit installer design plan"],
            applyCleanup: ["Delete \(markerURL.path)"],
            presentMessage: "PackageKit installer design plan present",
            absentMessage: "PackageKit installer design plan absent",
            statusPresentCleanup: ["Delete \(markerURL.path)"],
            statusAbsentCleanup: ["No artifact"],
            removeDryRunMessage: { exists in "Dry-run: would delete PackageKit installer design plan (exists=\(exists))" },
            removeSuccessMessage: { exists in "Removed PackageKit installer design plan (wasPresent=\(exists))" },
            removeSteps: ["Delete \(markerURL.path)"],
            removeCleanup: ["No package installs expected"]
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
