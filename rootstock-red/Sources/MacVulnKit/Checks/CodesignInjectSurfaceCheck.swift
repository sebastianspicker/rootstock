import Foundation
import RootstockCore

/// Injectability / codesign surface: HR off or dangerous entitlements → medium/high.
public struct CodesignInjectSurfaceCheck: Check {
    public static let id = "rootstock.check.codesign.inject_surface"
    public static let cost: CollectorCost = .low

    public init() {}

    public func evaluate(state: CollectedState, context: EvaluationContext) async throws -> [Finding] {
        let hits = state.injectabilityHits
        let samples = state.codesignSamples
        guard !hits.isEmpty || !samples.isEmpty else { return [] }

        let risky = hits.filter { !$0.riskFlags.isEmpty }
        let highRisk = risky.filter {
            $0.riskFlags.contains("get-task-allow")
                || $0.riskFlags.contains("allow-unsigned-executable-memory")
                || $0.riskFlags.contains("disable-library-validation")
        }

        var evidence: [Evidence] = []
        if risky.isEmpty {
            for sample in (samples.isEmpty ? hits.map(\.path) : samples.map(\.path)).prefix(15) {
                evidence.append(
                    Evidence(type: "codesign_sample", path: sample, detail: "no elevated inject flags")
                )
            }
            for hit in hits.prefix(10) {
                let hr = hit.hardenedRuntime.map { $0 ? "on" : "off" } ?? "unknown"
                evidence.append(
                    Evidence(
                        type: "injectability",
                        path: hit.path,
                        detail: "HR=\(hr) flags=none"
                    )
                )
            }
        } else {
            for hit in risky.prefix(25) {
                evidence.append(
                    Evidence(
                        type: "inject_risk",
                        path: hit.path,
                        detail: "flags=\(hit.riskFlags.joined(separator: ","))"
                    )
                )
            }
        }

        // Also surface weak dylib notes if any.
        for dylib in state.dylibRiskHits.prefix(10) {
            evidence.append(
                Evidence(
                    type: "dylib_risk",
                    path: dylib.path,
                    detail: dylib.weakDylibs.isEmpty
                        ? dylib.notes.joined(separator: "; ")
                        : "weak=\(dylib.weakDylibs.joined(separator: ","))"
                )
            )
        }

        let severity: Severity
        let title: String
        let confidence: Confidence
        if !highRisk.isEmpty {
            severity = .high
            confidence = .medium
            title = "Dangerous inject surface entitlements (\(highRisk.count) samples)"
        } else if !risky.isEmpty {
            severity = .medium
            confidence = .medium
            title = "Inject surface risks (\(risky.count) samples)"
        } else {
            severity = .info
            confidence = .medium
            title = "Codesign / inject surface samples (\(max(hits.count, samples.count)))"
        }

        return [
            Finding(
                id: Self.id,
                title: title,
                severity: severity,
                confidence: confidence,
                category: .codesign,
                evidence: evidence,
                attackTechniques: ["T1055", "T1574.006"],
                remediation: [
                    "Prefer Hardened Runtime without get-task-allow on production builds",
                    "Avoid disable-library-validation and allow-dyld-environment-variables unless required",
                    "Developer builds with get-task-allow are expected on engineering workstations",
                ],
                falsePositiveNotes: "Debug-signed local builds commonly include get-task-allow",
                dryRunSafe: true,
                opsecScore: 15,
                esfExpected: ["OPEN"]
            ),
        ]
    }
}
