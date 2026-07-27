import Foundation
import RootstockCore

/// Vector-class injectability finding (not inventory): HR off / get-task-allow / weak dylibs.
public struct InjectSurfaceVector: Check {
    public static let id = "rootstock.vector.inject.surface"
    public static let cost: CollectorCost = .low

    private static let highFlags: Set<String> = [
        "get-task-allow",
        "allow-unsigned-executable-memory",
        "disable-library-validation",
    ]

    public init() {}

    public func evaluate(state: CollectedState, context: EvaluationContext) async throws -> [Finding] {
        let riskyHits = state.injectabilityHits.filter { !$0.riskFlags.isEmpty }
        let weakDylibs = state.dylibRiskHits.filter {
            !$0.weakDylibs.isEmpty || !$0.notes.isEmpty
        }

        guard !riskyHits.isEmpty || !weakDylibs.isEmpty else { return [] }

        let highRisk = riskyHits.filter { hit in
            hit.riskFlags.contains(where: { Self.highFlags.contains($0) })
                || hit.getTaskAllow == true
                || hit.hardenedRuntime == false
                || hit.disableLibraryValidation == true
        }

        var evidence: [Evidence] = [
            Evidence(
                type: "summary",
                detail:
                    "injectHitsWithFlags=\(riskyHits.count) highRisk=\(highRisk.count) "
                    + "dylibRiskHits=\(weakDylibs.count)"
            ),
        ]

        for hit in (highRisk.isEmpty ? riskyHits : highRisk).prefix(25) {
            let hr = hit.hardenedRuntime.map { $0 ? "on" : "off" } ?? "unknown"
            evidence.append(
                Evidence(
                    type: "inject_vector",
                    path: hit.path,
                    detail:
                        "HR=\(hr) get-task-allow=\(hit.getTaskAllow.rootstockDescribe) "
                        + "flags=\(hit.riskFlags.joined(separator: ","))"
                )
            )
        }

        for dylib in weakDylibs.prefix(15) {
            evidence.append(
                Evidence(
                    type: "weak_dylib_vector",
                    path: dylib.path,
                    detail: dylib.weakDylibs.isEmpty
                        ? dylib.notes.joined(separator: "; ")
                        : "weak=\(dylib.weakDylibs.joined(separator: ","))"
                )
            )
        }

        let severity: Severity
        let title: String
        if !highRisk.isEmpty {
            severity = .high
            title =
                "Injection vector surface: get-task-allow / HR-off / weak library validation "
                + "(\(highRisk.count))"
        } else if !weakDylibs.isEmpty && riskyHits.isEmpty {
            severity = .medium
            title = "Injection vector: weak dylib load surface (\(weakDylibs.count))"
        } else {
            severity = .medium
            title = "Injection vector surface (\(riskyHits.count) flagged samples)"
        }

        return [
            Finding(
                id: Self.id,
                title: title,
                severity: severity,
                confidence: .medium,
                category: .codesign,
                evidence: evidence,
                attackTechniques: ["T1055", "T1574.006", "T1574.001"],
                remediation: [
                    "Ship production builds with Hardened Runtime; strip get-task-allow",
                    "Avoid disable-library-validation and allow-dyld-environment-variables unless required",
                    "Harden rpath / weak dylib load paths; prefer absolute, signed library deps",
                    "OPSEC: probing codesign/entitlements is read-only but may open many app bundles (noisy OPEN)",
                ],
                falsePositiveNotes:
                    "Debug-signed local builds commonly include get-task-allow on engineering workstations",
                dryRunSafe: true,
                opsecScore: 28,
                esfExpected: ["OPEN", "MMAP", "GET_TASK"]
            ),
        ]
    }

}
