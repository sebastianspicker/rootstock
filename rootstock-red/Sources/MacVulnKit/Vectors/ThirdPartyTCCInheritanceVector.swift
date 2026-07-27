import Foundation
import RootstockCore

/// Path-to-impact: third-party TCC-inheritance / embedded-interpreter class.
///
/// Research basis: Electron/TCC inheritance discussions; thick-client dual-use execution.
/// Safety and behavior: path samples + TCC domain compound; never forges grants.
public struct ThirdPartyTCCInheritanceVector: Check {
    public static let id = "rootstock.vector.tcc.third_party_inheritance"
    public static let cost: CollectorCost = .low

    public init() {}

    public func evaluate(state: CollectedState, context: EvaluationContext) async throws -> [Finding] {
        let tpi = state.thirdPartyTCCInheritance
        let thick = tpi?.thickClientAppPaths.count ?? 0
        let interpreters = tpi?.embeddedInterpreterPaths.count ?? 0
        let electron = tpi?.electronHelperPaths.count ?? 0
        let surface = tpi?.inheritanceSurfacePresent == true || (thick > 0 && interpreters > 0)
        let note = state.collectorNotes["collect.third_party_tcc_inheritance"] != nil

        guard surface || note else { return [] }
        guard thick >= 1 else { return [] }

        let fda = state.tcc?.fullDiskAccessLikely == true
        let axSignals = state.tcc?.domainSignals.contains {
            $0.lowercased().contains("screen") || $0.lowercased().contains("accessib")
                || $0.lowercased().contains("automation")
        } ?? false
        let sensitive =
            state.browserMeta.contains(where: \.exists)
            || state.credPaths.contains(where: \.exists)

        // Path-to-impact: thick client + interpreter, or thick + sensitive TCC domains,
        // or multiple thick clients (lighter inventory signal).
        let inheritanceSignal = interpreters >= 1 || electron >= 1 || fda || axSignals || thick >= 2
        guard inheritanceSignal else { return [] }

        var evidence: [Evidence] = [
            Evidence(
                type: "tcc_inheritance_summary",
                detail:
                    "thick=\(thick) interpreters=\(interpreters) electron=\(electron) "
                    + "fda=\(fda) axSignals=\(axSignals) sensitive=\(sensitive)"
            ),
        ]
        if let tpi {
            for path in (tpi.thickClientAppPaths + tpi.embeddedInterpreterPaths).prefix(12) {
                evidence.append(Evidence(type: "inheritance_path", path: path, detail: "TCC inheritance class path"))
            }
            for n in tpi.notes.prefix(6) {
                evidence.append(Evidence(type: "inheritance_note", detail: n))
            }
        }
        evidence.append(
            Evidence(
                type: "honesty",
                detail:
                    "Assess never forges TCC grants, never strips entitlements, "
                    + "never weaponizes Electron/interpreter inheritance bypasses."
            )
        )

        let severity: Severity
        if (fda || axSignals) && (interpreters >= 1 || electron >= 1) {
            severity = .medium
        } else {
            severity = .low
        }

        return [
            Finding(
                id: Self.id,
                title: electron > 0
                    ? "Third-party TCC inheritance surface with Electron/embedded helpers"
                    : "Third-party TCC inheritance / embedded-interpreter surface",
                severity: severity,
                confidence: .low,
                category: .tcc,
                evidence: evidence,
                attackTechniques: ["T1059", "T1559", "T1548"],
                remediation: [
                    "Review TCC grants for high-value thick clients (Screen, Accessibility, FDA)",
                    "Prefer sandboxed / Hardened Runtime builds; limit embedded debug interpreters",
                    "Monitor child process trees from Electron shells and IDE helpers",
                    "OPSEC: Rootstock Red does not forge TCC grants or deliver inheritance exploits",
                ],
                falsePositiveNotes:
                    "Electron apps and host interpreters are common on developer workstations. "
                    + "Prioritize production hosts with broad TCC grants on thick clients.",
                dryRunSafe: true,
                opsecScore: 22,
                tccDomains: fda ? ["FullDiskAccess"] : (axSignals ? ["Accessibility"] : []),
                esfExpected: ["OPEN", "EXEC"]
            ),
        ]
    }
}
