import Foundation
import RootstockCore

/// Lab Archive/quarantine extractor review plan - documentation only.
public struct ArchiveQuarantinePlanLabAction: LabAction {
    public static let id = "lab.surface.archive_quarantine_plan"
    public static let consent = ConsentPolicy.labDefault
    public static let riskClass = RiskClass.labOnly

    public init() {}

    public func run(
        request: LabActionRequest,
        context: EvaluationContext
    ) async throws -> ActionResult {

        try SafetyRails.ensureLabConsent(context: context, policy: Self.consent)
        let labRoot = LabPaths.resolveLabRoot(params: request.parameters)
        let focus = request.parameters["focus"] ?? "extractors,quarantine,Gatekeeper"
        let markerURL = labRoot
            .appendingPathComponent("archive-quarantine-plan", isDirectory: true)
            .appendingPathComponent("archive-quarantine-plan.md")
        let body = """
        # rootstock-red-lab Archive/quarantine extractor plan
        focus: \(focus)
        purpose: Archive/quarantine extractor posture documentation
        rules:
        - document third-party and stock extractor path inventory only under consent
        - never strip com.apple.quarantine xattrs
        - never craft Gatekeeper bypass archives
        - purple: expect OPEN/WRITE of Downloads archives if unpack observed under ROE
        ROOTSTOCK_RED_LAB_ARCHIVE_QUARANTINE=1
        """
        let copy = FileMarkerCopy(
            planMessage: """
            Dry-run Archive/quarantine extractor plan for focus [\(focus)]: would write plan at \
            \(markerURL.path). Never strips quarantine or crafts bypass archives.
            """,
            planSteps: [
                "Document Archive/quarantine extractor review for: \(focus)",
                "Note path/meta inventory without host mutation beyond lab root",
                "Write markdown plan under lab root only",
                "Purple: validate expected telemetry under ROE only",
            ],
            planCleanup: ["Delete \(markerURL.path)"],
            applyDryRunMessage: "Dry-run: would write Archive/quarantine extractor plan at \(markerURL.path)",
            applySuccessMessage: "Wrote Archive/quarantine extractor plan at \(markerURL.path)",
            applySteps: ["Write Archive/quarantine extractor plan"],
            applyCleanup: ["Delete \(markerURL.path)"],
            presentMessage: "Archive/quarantine extractor plan present",
            absentMessage: "Archive/quarantine extractor plan absent",
            statusPresentCleanup: ["Delete \(markerURL.path)"],
            statusAbsentCleanup: ["No artifact"],
            removeDryRunMessage: { exists in "Dry-run: would delete Archive/quarantine extractor plan (exists=\(exists))" },
            removeSuccessMessage: { exists in "Removed Archive/quarantine extractor plan (wasPresent=\(exists))" },
            removeSteps: ["Delete \(markerURL.path)"],
            removeCleanup: ["No xattr mutation expected"]
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
