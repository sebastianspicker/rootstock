import Foundation
import RootstockCore

/// Lab mobileconfig / configuration-profile sideload risk plan - documentation only.
///
/// Research basis: profile payload risk inventory themes.
/// Safety and behavior: never installs real configuration profiles to the system.
public struct MobileconfigSideloadPlanLabAction: LabAction {
    public static let id = "lab.surface.mobileconfig_sideload_plan"
    public static let consent = ConsentPolicy.labDefault
    public static let riskClass = RiskClass.labOnly

    public init() {}

    public func run(
        request: LabActionRequest,
        context: EvaluationContext
    ) async throws -> ActionResult {

        try SafetyRails.ensureLabConsent(context: context, policy: Self.consent)
        let labRoot = LabPaths.resolveLabRoot(params: request.parameters)
        let payloads = request.parameters["payloads"] ?? "com.apple.vpn.managed,com.apple.webcontent-filter"
        let payloadList = LabPaths.jsonStringList(fromCSV: payloads)
        let markerURL = labRoot
            .appendingPathComponent("mobileconfig-sideload-plan", isDirectory: true)
            .appendingPathComponent("profile-plan.json")
        let body = """
        {
          "id": "com.rootstock.red.lab.mobileconfig_sideload_plan",
          "payloadTypes": [\(payloadList)],
          "purpose": "configuration profile sideload risk plan",
          "harmless": true,
          "installProfiles": false,
          "neverInstallToSystem": true,
          "esfExpected": ["OPEN", "WRITE"]
        }
        """
        let copy = FileMarkerCopy(
            planMessage: """
            Dry-run mobileconfig sideload plan for payloads [\(payloads)]: would write plan at \
            \(markerURL.path). Never installs real configuration profiles to the system.
            """,
            planSteps: [
                "Document sideload risk review for payloads: \(payloads)",
                "Catalog detection opportunities for .mobileconfig delivery without install",
                "Write profile plan JSON under lab root only",
                "Never install configuration profiles via profiles(1) or System Settings",
            ],
            planCleanup: [
                "Delete \(markerURL.path)",
                "Confirm no system configuration profile was installed",
            ],
            applyDryRunMessage: "Dry-run: would write mobileconfig sideload plan at \(markerURL.path)",
            applySuccessMessage: "Wrote mobileconfig sideload plan at \(markerURL.path)",
            applySteps: [
            "Create mobileconfig-sideload-plan directory",
            "Write profile sideload risk plan JSON for \(payloads)",
        ],
            applyCleanup: ["Delete \(markerURL.path)"],
            presentMessage: "Mobileconfig sideload plan present",
            absentMessage: "Mobileconfig sideload plan absent",
            statusPresentCleanup: ["Delete \(markerURL.path)"],
            statusAbsentCleanup: ["No artifact"],
            removeDryRunMessage: { exists in "Dry-run: would delete mobileconfig sideload plan (exists=\(exists))" },
            removeSuccessMessage: { exists in "Removed mobileconfig sideload plan (wasPresent=\(exists))" },
            removeSteps: ["Delete \(markerURL.path)"],
            removeCleanup: ["No real configuration profile was installed to the system"]
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
