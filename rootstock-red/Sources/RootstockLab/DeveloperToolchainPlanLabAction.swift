import Foundation
import RootstockCore

/// Lab dual-use developer toolchain validation plan - documentation only.
///
/// Research basis: codesign/xcodebuild/clang dual-use surface themes.
/// Safety and behavior: no codesign of malware; never invokes toolchain for payload build.
public struct DeveloperToolchainPlanLabAction: LabAction {
    public static let id = "lab.surface.developer_toolchain_plan"
    public static let consent = ConsentPolicy.labDefault
    public static let riskClass = RiskClass.labOnly

    public init() {}

    public func run(
        request: LabActionRequest,
        context: EvaluationContext
    ) async throws -> ActionResult {

        try SafetyRails.ensureLabConsent(context: context, policy: Self.consent)
        let labRoot = LabPaths.resolveLabRoot(params: request.parameters)
        let tools = request.parameters["tools"] ?? "codesign,xcodebuild,clang,ld"
        let toolList = LabPaths.jsonStringList(fromCSV: tools)
        let markerURL = labRoot
            .appendingPathComponent("developer-toolchain-plan", isDirectory: true)
            .appendingPathComponent("toolchain-plan.json")
        let body = """
        {
          "id": "com.rootstock.red.lab.developer_toolchain_plan",
          "tools": [\(toolList)],
          "purpose": "dual-use developer toolchain validation plan",
          "harmless": true,
          "codesignMalware": false,
          "buildPayloads": false,
          "esfExpected": ["EXEC", "OPEN"]
        }
        """
        let copy = FileMarkerCopy(
            planMessage: """
            Dry-run developer toolchain plan for tools [\(tools)]: would write plan at \
            \(markerURL.path). No codesign of malware; no payload builds.
            """,
            planSteps: [
                "Document dual-use validation steps for: \(tools)",
                "Map expected purple signals (EXEC of toolchain binaries) if exercised under separate ROE",
                "Write toolchain plan JSON under lab root only",
                "Never codesign malware, ad-hoc sign implants, or build weaponized payloads",
            ],
            planCleanup: [
                "Delete \(markerURL.path)",
                "Confirm no codesign/xcodebuild payload operations occurred",
            ],
            applyDryRunMessage: "Dry-run: would write developer toolchain plan at \(markerURL.path)",
            applySuccessMessage: "Wrote developer toolchain plan at \(markerURL.path)",
            applySteps: [
            "Create developer-toolchain-plan directory",
            "Write toolchain validation plan JSON for \(tools)",
        ],
            applyCleanup: ["Delete \(markerURL.path)"],
            presentMessage: "Developer toolchain plan present",
            absentMessage: "Developer toolchain plan absent",
            statusPresentCleanup: ["Delete \(markerURL.path)"],
            statusAbsentCleanup: ["No artifact"],
            removeDryRunMessage: { exists in "Dry-run: would delete developer toolchain plan (exists=\(exists))" },
            removeSuccessMessage: { exists in "Removed developer toolchain plan (wasPresent=\(exists))" },
            removeSteps: ["Delete \(markerURL.path)"],
            removeCleanup: ["No codesign of malware was performed"]
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
