import Foundation
import RootstockCore

/// Lab Time Machine data-access surface plan - documentation + reversible marker only.
///
/// Research basis: backup volume / tmutil observation themes.
/// Safety and behavior: never mounts or restores foreign backups silently; lab-root marker only.
public struct TimeMachinePlanLabAction: LabAction {
    public static let id = "lab.surface.time_machine_plan"
    public static let consent = ConsentPolicy.labDefault
    public static let riskClass = RiskClass.labOnly

    public init() {}

    public func run(
        request: LabActionRequest,
        context: EvaluationContext
    ) async throws -> ActionResult {

        try SafetyRails.ensureLabConsent(context: context, policy: Self.consent)
        let labRoot = LabPaths.resolveLabRoot(params: request.parameters)
        let focus = request.parameters["focus"] ?? "destination-info,latestbackup,mount-points"
        let markerURL = labRoot
            .appendingPathComponent("time-machine-plan", isDirectory: true)
            .appendingPathComponent("tm-plan.md")
        let body = """
        # rootstock-red-lab Time Machine plan
        focus: \(focus)
        purpose: data-access surface documentation (not backup abuse)
        rules:
        - document destinations and visibility only under consent
        - never silently mount foreign Time Machine volumes
        - never restore from backups without explicit written ROE
        - purple: expect OPEN of backup roots if FDA exercised under separate ROE
        ROOTSTOCK_RED_LAB_TIME_MACHINE=1
        """
        let copy = FileMarkerCopy(
            planMessage: """
            Dry-run Time Machine plan for focus [\(focus)]: would write plan at \
            \(markerURL.path). Never mounts or restores foreign backups silently.
            """,
            planSteps: [
                "Document data-access surface review for: \(focus)",
                "Note FDA / backup volume visibility without silent restore",
                "Write markdown plan under lab root only",
                "Never mount foreign backups or run tmutil restore without explicit ROE",
            ],
            planCleanup: [
                "Delete \(markerURL.path)",
                "Confirm no TM mount/restore was performed",
            ],
            applyDryRunMessage: "Dry-run: would write Time Machine plan at \(markerURL.path)",
            applySuccessMessage: "Wrote Time Machine plan at \(markerURL.path)",
            applySteps: ["Write Time Machine plan"],
            applyCleanup: ["Delete \(markerURL.path)"],
            presentMessage: "Time Machine plan present",
            absentMessage: "Time Machine plan absent",
            statusPresentCleanup: ["Delete \(markerURL.path)"],
            statusAbsentCleanup: ["No artifact"],
            removeDryRunMessage: { exists in "Dry-run: would delete Time Machine plan (exists=\(exists))" },
            removeSuccessMessage: { exists in "Removed Time Machine plan (wasPresent=\(exists))" },
            removeSteps: ["Delete \(markerURL.path)"],
            removeCleanup: ["No foreign backup was mounted or restored"]
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
