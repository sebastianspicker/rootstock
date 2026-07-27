import Foundation
import RootstockCore

/// Path-to-impact: thick-client sandbox / dangerous entitlement surface.
///
/// Research basis: entitlement inventories; Electron/thick-client research.
/// Safety and behavior: typed compound with inject/TCC; never strips entitlements.
public struct SandboxEntitlementThickClientVector: Check {
    public static let id = "rootstock.vector.sandbox.entitlement_thick_client"
    public static let cost: CollectorCost = .low

    public init() {}

    public func evaluate(state: CollectedState, context: EvaluationContext) async throws -> [Finding] {
        let sb = state.appSandboxEntitlements
        let apps = sb?.appSamples.count ?? 0
        let riskPaths = sb?.unsandboxedRiskPaths.count ?? 0
        let dangerous = sb?.dangerousEntitlementHints.count ?? 0
        let note = state.collectorNotes["collect.app_sandbox_entitlements"] != nil

        let injectRisk = state.injectabilityHits.contains { !$0.riskFlags.isEmpty }
            || state.codesignSamples.contains {
                $0.getTaskAllow == true
                    || $0.disableLibraryValidation == true
                    || $0.hardenedRuntime == false
            }
        let surface = apps > 0 || riskPaths > 0 || note
        guard surface else { return [] }
        // Path-to-impact: thick clients + (inject/codesign risk OR dangerous tools OR scale)
        guard riskPaths > 0 || injectRisk || dangerous > 0 || apps >= 3 else { return [] }

        var evidence: [Evidence] = [
            Evidence(
                type: "sandbox_summary",
                detail:
                    "appSamples=\(apps) unsandboxedRisk=\(riskPaths) "
                    + "dangerousHints=\(dangerous) injectOrWeakCodesign=\(injectRisk)"
            ),
        ]
        if let sb {
            for path in (sb.appSamples + sb.unsandboxedRiskPaths).prefix(12) {
                evidence.append(Evidence(type: "app_sample", path: path, detail: "thick-client sample"))
            }
            for n in sb.notes.prefix(8) {
                evidence.append(Evidence(type: "sandbox_note", detail: n))
            }
        }
        for hit in state.injectabilityHits.prefix(5) where !hit.riskFlags.isEmpty {
            evidence.append(
                Evidence(
                    type: "inject_compound",
                    path: hit.path,
                    detail: "riskFlags=\(hit.riskFlags.joined(separator: ","))"
                )
            )
        }
        evidence.append(
            Evidence(
                type: "honesty",
                detail:
                    "Assess never strips entitlements, disables sandbox, or injects processes. "
                    + "Thick-client risk is posture ranking only."
            )
        )

        let severity: Severity =
            (riskPaths >= 2 && injectRisk) ? .medium : .low

        return [
            Finding(
                id: Self.id,
                title: injectRisk
                    ? "Thick-client sandbox/entitlement surface with inject/codesign risk compound"
                    : "Thick-client app sandbox / entitlement surface",
                severity: severity,
                confidence: .low,
                category: .sandbox,
                evidence: evidence,
                attackTechniques: ["T1553", "T1055", "T1548"],
                remediation: [
                    "Prefer sandboxed distribution for high-value clients; strip get-task-allow from production builds",
                    "Enable Hardened Runtime and library validation on shipping binaries",
                    "Inventory Electron/thick clients for unexpected debug entitlements",
                    "OPSEC: Rootstock Red does not provide inject or entitlement-strip tooling",
                ],
                falsePositiveNotes:
                    "Engineering workstations often run unsandboxed IDEs. Prioritize production-shaped hosts "
                    + "and inject compounds.",
                dryRunSafe: true,
                opsecScore: 18,
                esfExpected: ["OPEN"]
            ),
        ]
    }
}
