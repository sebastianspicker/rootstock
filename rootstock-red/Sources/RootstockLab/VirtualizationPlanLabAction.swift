import Foundation
import RootstockCore

/// Lab virtualization / container dual-use observation plan - documentation only.
public struct VirtualizationPlanLabAction: LabAction {
    public static let id = "lab.surface.virtualization_plan"
    public static let consent = ConsentPolicy.labDefault
    public static let riskClass = RiskClass.labOnly

    public init() {}

    public func run(
        request: LabActionRequest,
        context: EvaluationContext
    ) async throws -> ActionResult {

        try SafetyRails.ensureLabConsent(context: context, policy: Self.consent)
        let labRoot = LabPaths.resolveLabRoot(params: request.parameters)
        let focus = request.parameters["focus"] ?? "docker,colima,utm,virtualization.framework"
        let markerURL = labRoot
            .appendingPathComponent("virtualization-plan", isDirectory: true)
            .appendingPathComponent("virt-plan.md")
        let body = """
        # rootstock-red-lab virtualization plan
        focus: \(focus)
        purpose: dual-use virt/container posture documentation
        rules:
        - document path inventory only under consent
        - never start/stop Docker/VMs from this lab action
        - never harvest image secrets or deploy nested C2
        - purple: expect EXEC/OPEN of docker/utm helpers if exercised under separate ROE
        ROOTSTOCK_RED_LAB_VIRTUALIZATION=1
        """
        let copy = FileMarkerCopy(
            planMessage: """
            Dry-run virtualization plan for focus [\(focus)]: would write plan at \
            \(markerURL.path). Never starts containers/VMs or harvests image secrets.
            """,
            planSteps: [
                "Document virt/container dual-use observation for: \(focus)",
                "Note helper daemons and app paths without starting VMs",
                "Write markdown plan under lab root only",
                "Never deploy container C2 or hypervisor escape packs",
            ],
            planCleanup: ["Delete \(markerURL.path)"],
            applyDryRunMessage: "Dry-run: would write virtualization plan at \(markerURL.path)",
            applySuccessMessage: "Wrote virtualization plan at \(markerURL.path)",
            applySteps: ["Write virtualization plan"],
            applyCleanup: ["Delete \(markerURL.path)"],
            presentMessage: "Virtualization plan present",
            absentMessage: "Virtualization plan absent",
            statusPresentCleanup: ["Delete \(markerURL.path)"],
            statusAbsentCleanup: ["No artifact"],
            removeDryRunMessage: { exists in "Dry-run: would delete virtualization plan (exists=\(exists))" },
            removeSuccessMessage: { exists in "Removed virtualization plan (wasPresent=\(exists))" },
            removeSteps: ["Delete \(markerURL.path)"],
            removeCleanup: ["No containers or VMs were started"]
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
