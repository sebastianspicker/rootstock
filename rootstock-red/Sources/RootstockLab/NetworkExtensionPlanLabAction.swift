import Foundation
import RootstockCore

/// Lab Network Extension / VPN / content-filter observation plan - documentation only.
///
/// Research basis: purple expectations for NE surfaces.
/// Safety and behavior: never modifies system NetworkExtension configuration; lab-root marker only.
public struct NetworkExtensionPlanLabAction: LabAction {
    public static let id = "lab.surface.network_extension_plan"
    public static let consent = ConsentPolicy.labDefault
    public static let riskClass = RiskClass.labOnly

    public init() {}

    public func run(
        request: LabActionRequest,
        context: EvaluationContext
    ) async throws -> ActionResult {

        try SafetyRails.ensureLabConsent(context: context, policy: Self.consent)
        let labRoot = LabPaths.resolveLabRoot(params: request.parameters)
        let surfaces = request.parameters["surfaces"] ?? "VPN,content-filter,packet-tunnel"
        let surfaceList = LabPaths.jsonStringList(fromCSV: surfaces)
        let markerURL = labRoot
            .appendingPathComponent("network-extension-plan", isDirectory: true)
            .appendingPathComponent("ne-plan.json")
        let body = """
        {
          "id": "com.rootstock.red.lab.network_extension_plan",
          "surfaces": [\(surfaceList)],
          "purpose": "purple-team NE/VPN/content-filter observation plan",
          "harmless": true,
          "neverModifySystemNEConfig": true,
          "esfExpected": ["OPEN", "EXEC", "NETWORK"]
        }
        """
        let copy = FileMarkerCopy(
            planMessage: """
            Dry-run Network Extension plan for surfaces [\(surfaces)]: would write plan at \
            \(markerURL.path). Never modifies system NetworkExtension configuration.
            """,
            planSteps: [
                "Document purple observation expectations for: \(surfaces)",
                "Note NE/VPN/content-filter process and preference artifacts (read-only)",
                "Write NE plan JSON under lab root only",
                "Never modify system NetworkExtension config, preferences, or entitlements",
            ],
            planCleanup: [
                "Delete \(markerURL.path)",
                "Confirm no system NE/VPN configuration was modified",
            ],
            applyDryRunMessage: "Dry-run: would write Network Extension plan at \(markerURL.path)",
            applySuccessMessage: "Wrote Network Extension plan at \(markerURL.path)",
            applySteps: [
            "Create network-extension-plan directory",
            "Write NE observation plan JSON for \(surfaces)",
        ],
            applyCleanup: ["Delete \(markerURL.path)"],
            presentMessage: "Network Extension plan present",
            absentMessage: "Network Extension plan absent",
            statusPresentCleanup: ["Delete \(markerURL.path)"],
            statusAbsentCleanup: ["No artifact"],
            removeDryRunMessage: { exists in "Dry-run: would delete Network Extension plan (exists=\(exists))" },
            removeSuccessMessage: { exists in "Removed Network Extension plan (wasPresent=\(exists))" },
            removeSteps: ["Delete \(markerURL.path)"],
            removeCleanup: ["No system NetworkExtension configuration was modified"]
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
