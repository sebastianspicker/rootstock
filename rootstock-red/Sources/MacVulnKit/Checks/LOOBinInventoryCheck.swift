import Foundation
import RootstockCore

/// Inventory of present LOOBins with ATT&CK-oriented tactics from the catalog.
public struct LOOBinInventoryCheck: Check {
    public static let id = "rootstock.check.lool.inventory"
    public static let cost: CollectorCost = .low

    public init() {}

    public func evaluate(state: CollectedState, context: EvaluationContext) async throws -> [Finding] {
        let present = state.loobins.filter(\.present)
        guard !present.isEmpty else {
            // Still emit if inventory was collected but nothing present (unusual on macOS).
            guard !state.loobins.isEmpty else { return [] }
            return [
                Finding(
                    id: "\(Self.id).none",
                    title: "LOOBin inventory empty (no catalog entries present on disk)",
                    severity: .info,
                    confidence: .medium,
                    category: .lool,
                    evidence: [
                        Evidence(
                            type: "note",
                            detail: "Catalog scanned \(state.loobins.count) entries; none executable at expected paths"
                        ),
                    ],
                    attackTechniques: ["T1218"],
                    remediation: ["Verify LOOBin catalog paths for this OS version"],
                    dryRunSafe: true,
                    opsecScore: 5
                ),
            ]
        }

        var techniques = Set(present.flatMap(\.tactics))
        // Map loose tactics to common ATT&CK IDs when catalog only has names.
        let mapped = Self.mapTacticsToTechniques(Array(techniques))
        techniques.formUnion(mapped)
        if techniques.isEmpty {
            techniques.insert("T1218")
        }

        return [
            Finding(
                id: Self.id,
                title: "LOOBin inventory: \(present.count) present",
                severity: .info,
                confidence: .high,
                category: .lool,
                evidence: present.prefix(40).map {
                    let tactics = $0.tactics.isEmpty ? "unspecified" : $0.tactics.joined(separator: ",")
                    return Evidence(
                        type: "loobin",
                        path: $0.path,
                        detail: "\($0.name) present tactics=\(tactics)"
                    )
                },
                attackTechniques: Array(techniques).sorted(),
                remediation: [
                    "Informational living-off-the-land surface for purple-team planning",
                    "Monitor abuse of dual-use binaries via ESF / EDR",
                ],
                falsePositiveNotes: "Presence of stock Apple binaries is expected on every Mac",
                dryRunSafe: true,
                opsecScore: 8,
                esfExpected: ["OPEN"]
            ),
        ]
    }

    private static func mapTacticsToTechniques(_ tactics: [String]) -> [String] {
        var ids: [String] = []
        for t in tactics {
            let lower = t.lowercased()
            if lower.contains("execution") { ids.append("T1059") }
            if lower.contains("persist") { ids.append("T1543.001") }
            if lower.contains("credential") { ids.append("T1555") }
            if lower.contains("discovery") { ids.append("T1082") }
            if lower.contains("defense") || lower.contains("evasion") { ids.append("T1562") }
            if lower.contains("lateral") { ids.append("T1021") }
            if lower.contains("collection") { ids.append("T1005") }
            if lower.contains("command") || lower.contains("c2") { ids.append("T1071") }
        }
        return Array(Set(ids))
    }
}
