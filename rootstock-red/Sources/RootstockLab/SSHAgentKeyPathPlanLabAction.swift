import Foundation
import RootstockCore

/// Lab SSH-agent / key path review plan - documentation only.
public struct SSHAgentKeyPathPlanLabAction: LabAction {
    public static let id = "lab.surface.ssh_agent_key_path_plan"
    public static let consent = ConsentPolicy.labDefault
    public static let riskClass = RiskClass.labOnly

    public init() {}

    public func run(
        request: LabActionRequest,
        context: EvaluationContext
    ) async throws -> ActionResult {

        try SafetyRails.ensureLabConsent(context: context, policy: Self.consent)
        let labRoot = LabPaths.resolveLabRoot(params: request.parameters)
        let focus = request.parameters["focus"] ?? "ssh-agent,authorized_keys,sshd"
        let markerURL = labRoot
            .appendingPathComponent("ssh-agent-key-path-plan", isDirectory: true)
            .appendingPathComponent("ssh-path-plan.md")
        let body = """
        # rootstock-red-lab SSH agent/key path plan
        focus: \(focus)
        purpose: SSH-agent and key path lateral posture documentation
        rules:
        - document agent socket / authorized_keys / sshd path inventory only under consent
        - never read private key material
        - never connect to ssh-agent sockets or harvest credentials
        - purple: expect OPEN of ~/.ssh paths if inspected under ROE
        ROOTSTOCK_RED_LAB_SSH_AGENT_KEY_PATH=1
        """
        let copy = FileMarkerCopy(
            planMessage: """
            Dry-run SSH agent/key path plan for focus [\(focus)]: would write plan at \
            \(markerURL.path). Never reads private keys or agent material.
            """,
            planSteps: [
                "Document SSH agent/key path lateral review for: \(focus)",
                "Note path presence without reading key material",
                "Write markdown plan under lab root only",
                "Never extract private keys or connect to agent sockets",
            ],
            planCleanup: ["Delete \(markerURL.path)"],
            applyDryRunMessage: "Dry-run: would write SSH agent/key path plan at \(markerURL.path)",
            applySuccessMessage: "Wrote SSH agent/key path plan at \(markerURL.path)",
            applySteps: ["Write SSH agent/key path plan"],
            applyCleanup: ["Delete \(markerURL.path)"],
            presentMessage: "SSH agent/key path plan present",
            absentMessage: "SSH agent/key path plan absent",
            statusPresentCleanup: ["Delete \(markerURL.path)"],
            statusAbsentCleanup: ["No artifact"],
            removeDryRunMessage: { exists in "Dry-run: would delete SSH agent/key path plan (exists=\(exists))" },
            removeSuccessMessage: { exists in "Removed SSH agent/key path plan (wasPresent=\(exists))" },
            removeSteps: ["Delete \(markerURL.path)"],
            removeCleanup: ["No private keys were read"]
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
