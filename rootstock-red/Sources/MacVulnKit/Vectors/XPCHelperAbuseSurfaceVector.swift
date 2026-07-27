import Foundation
import RootstockCore

/// Path-to-impact: XPC / Privileged Helper Tools surface as abuse and persistence plane.
///
/// Research basis: PEASS helper listings, Empire OSX helper ideas, Objective-See XPC research themes.
/// Safety and behavior: typed vector with ATT&CK, SIP honesty, compound inject/helper signals,
/// not a rainbow dump of every helper filename.
public struct XPCHelperAbuseSurfaceVector: Check {
    public static let id = "rootstock.vector.xpc.helper_abuse_surface"
    public static let cost: CollectorCost = .low

    public init() {}

    public func evaluate(state: CollectedState, context: EvaluationContext) async throws -> [Finding] {
        let helpers = state.privilegedHelperTools
        let extensions = state.systemExtensionPaths
        let xpcNote = state.collectorNotes["collect.xpc_helpers"]
            ?? state.collectorNotes.first(where: { $0.key.contains("xpc") })?.value

        guard !helpers.isEmpty || !extensions.isEmpty || xpcNote != nil else { return [] }

        // Path-to-impact: helpers alone are inventory; require scale, writability, or inject compound.
        var writable: [String] = []
        for h in helpers {
            let path = h.hasPrefix("/") ? h : "/Library/PrivilegedHelperTools/\(h)"
            if FileManager.default.isWritableFile(atPath: path)
                || FileManager.default.isWritableFile(
                    atPath: URL(fileURLWithPath: path).deletingLastPathComponent().path
                )
            {
                writable.append(path)
            }
        }
        let injectCompound = state.injectabilityHits.contains {
            $0.disableLibraryValidation == true
                || $0.getTaskAllow == true
                || $0.hardenedRuntime == false
                || !$0.riskFlags.isEmpty
        }
        let scale = helpers.count + extensions.count >= 2
        let flaggedNote = xpcNote?.localizedCaseInsensitiveContains("denied") == true
            || state.collectorNotes["privesc.xpc_risk"] != nil

        // Path-to-impact: require writability, inject compound, scale, or collector risk flag.
        guard !writable.isEmpty || injectCompound || scale || flaggedNote else { return [] }
        guard !helpers.isEmpty || !extensions.isEmpty else { return [] }

        var evidence: [Evidence] = [
            Evidence(
                type: "summary",
                detail:
                    "privilegedHelpers=\(helpers.count) systemExtensions=\(extensions.count) "
                    + "writableHelpers=\(writable.count) injectCompound=\(injectCompound)"
            ),
        ]
        if let xpcNote {
            evidence.append(Evidence(type: "xpc_collector", detail: xpcNote))
        }
        for h in helpers.prefix(25) {
            let path = h.hasPrefix("/") ? h : "/Library/PrivilegedHelperTools/\(h)"
            evidence.append(
                Evidence(
                    type: "xpc_helper",
                    path: path,
                    detail: "name=\(h) (filename/path inventory; no binary reverse)"
                )
            )
        }
        for ext in extensions.prefix(15) {
            evidence.append(Evidence(type: "system_extension", path: ext, detail: "sygext path present"))
        }
        if injectCompound {
            evidence.append(
                Evidence(
                    type: "compound_inject",
                    detail: "injectability risk flags present - helper install + weak HR is higher impact"
                )
            )
        }
        if state.protections?.sipEnabled == true {
            evidence.append(
                Evidence(
                    type: "sip_honesty",
                    detail: "SIP on - system helper install still needs root; abuse is usually existing weak helpers"
                )
            )
        }

        let severity: Severity
        let title: String
        if !writable.isEmpty {
            severity = .high
            title = "XPC/helper abuse surface: user-writable privileged helpers (\(writable.count))"
        } else if injectCompound && helpers.count >= 1 {
            severity = .medium
            title = "XPC/helper surface with injectability compound (\(helpers.count) helpers)"
        } else {
            severity = .low
            title = "XPC/privileged-helper attack surface (\(helpers.count + extensions.count) paths)"
        }

        return [
            Finding(
                id: Self.id,
                title: title,
                severity: severity,
                confidence: .medium,
                category: .xpc,
                evidence: evidence,
                attackTechniques: ["T1543.001", "T1543.004", "T1559", "T1068"],
                remediation: [
                    "Inventory PrivilegedHelperTools; remove unexpected vendor helpers",
                    "Ensure helpers are root-owned, signed, and not user-writable",
                    "Correlate with System Settings → Login Items / Background Items for residual services",
                    "OPSEC: filename listing is quiet; installing fake helpers is high-risk and lab-only",
                ],
                falsePositiveNotes:
                    "Security and MDM products legitimately install helpers. Filenames-only inventory "
                    + "is not proof of vulnerable XPC interfaces - no private API reverse engineering performed.",
                dryRunSafe: true,
                opsecScore: writable.isEmpty ? 22 : 50,
                esfExpected: ["OPEN", "WRITE"]
            ),
        ]
    }
}
