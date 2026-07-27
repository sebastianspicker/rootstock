import Foundation
import RootstockCore

/// Purple xattr / quarantine detection-pair stub - technique + expected ESF OPEN/WRITE events.
///
/// Research basis: Atomic Red Team dual-use detection companions; quarantine/xattr monitoring themes.
/// Safety and behavior: reversible JSON under lab root; no process execution; consent + dry-run.
public struct XattrDetectPairLabAction: LabAction {
    public static let id = "lab.purple.xattr_detect_pair"
    public static let consent = ConsentPolicy.labDefault
    public static let riskClass = RiskClass.labOnly

    public static let markerName = "xattr-detect-pair.json"
    public static let defaultTechnique = "T1553.001"
    public static let defaultEvents = "OPEN,WRITE"

    public init() {}

    public func run(
        request: LabActionRequest,
        context: EvaluationContext
    ) async throws -> ActionResult {

        try SafetyRails.ensureLabConsent(context: context, policy: Self.consent)
        let labRoot = LabPaths.resolveLabRoot(params: request.parameters)
        let technique = request.parameters["technique"] ?? Self.defaultTechnique
        let events = request.parameters["esfEvents"] ?? Self.defaultEvents
        let eventList = LabPaths.jsonStringList(fromCSV: events)
        let markerURL = labRoot
            .appendingPathComponent("purple-xattr", isDirectory: true)
            .appendingPathComponent(Self.markerName)
        let body = """
        {
          "id": "com.rootstock.red.lab.xattr_detect_pair",
          "technique": "\(technique)",
          "esfExpected": [\(eventList)],
          "focus": "xattr/quarantine monitoring",
          "purpose": "purple-team detection pair stub",
          "harmless": true
        }
        """
        let copy = FileMarkerCopy(
            planMessage: """
            Dry-run xattr detect-pair plan: would write purple stub for \(technique) expecting \
            [\(events)] (xattr/quarantine monitoring) at \(markerURL.path).
            """,
            planSteps: [
                "Technique tag: \(technique)",
                "Expected ESF-style events for xattr/quarantine monitoring: \(events)",
                "Write purple detection-pair JSON: \(markerURL.path)",
                "No xattr mutations; pair with local ESF/osquery rules offline",
            ],
            planCleanup: [
                "Delete \(markerURL.path)",
                "Disable temporary detection rules if they keyed only on this lab path",
            ],
            applyDryRunMessage: "Dry-run: would write xattr detect-pair stub at \(markerURL.path)",
            applySuccessMessage: "Wrote xattr detect-pair stub at \(markerURL.path) (technique=\(technique))",
            applySteps: [
            "Create purple-xattr directory",
            "Write xattr/quarantine detection-pair JSON for \(technique)",
        ],
            applyCleanup: ["Delete \(markerURL.path)"],
            presentMessage: "Xattr detect-pair stub present",
            absentMessage: "Xattr detect-pair stub absent",
            statusPresentCleanup: ["Delete \(markerURL.path)"],
            statusAbsentCleanup: ["No artifact"],
            removeDryRunMessage: { exists in "Dry-run: would delete xattr detect-pair stub (exists=\(exists))" },
            removeSuccessMessage: { exists in "Removed xattr detect-pair stub (wasPresent=\(exists))" },
            removeSteps: ["Delete \(markerURL.path)"],
            removeCleanup: ["No host ESF consumer modified"]
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
