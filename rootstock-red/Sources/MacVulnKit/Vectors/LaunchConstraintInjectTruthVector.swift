import Foundation
import RootstockCore

/// Path-to-impact: launch-constraint honesty × injectability entitlement truth.
///
/// Research basis: InjectCheck HR/LV flags; Apple launch-constraint documentation.
/// Safety and behavior: constrained vs unconstrained-risk sets; never claims successful injection.
public struct LaunchConstraintInjectTruthVector: Check {
    public static let id = "rootstock.vector.inject.launch_constraint_truth"
    public static let cost: CollectorCost = .low

    public init() {}

    public func evaluate(state: CollectedState, context: EvaluationContext) async throws -> [Finding] {
        let lc = state.launchConstraints
        let inject = state.injectabilityHits
        let dylib = state.dylibRiskHits

        let unconstrained = lc?.unconstrainedRiskPaths ?? []
        let constrained = lc?.constrainedPaths ?? []
        let riskyInject = inject.filter {
            !$0.riskFlags.isEmpty
                || $0.getTaskAllow == true
                || $0.disableLibraryValidation == true
                || $0.hardenedRuntime == false
        }

        guard !unconstrained.isEmpty || !riskyInject.isEmpty || !dylib.isEmpty || lc != nil else {
            return []
        }
        // Need actual risk signal.
        guard !unconstrained.isEmpty || !riskyInject.isEmpty || !dylib.isEmpty else { return [] }

        var evidence: [Evidence] = [
            Evidence(
                type: "summary",
                detail:
                    "unconstrainedRisk=\(unconstrained.count) constrainedArtifacts=\(constrained.count) "
                    + "injectHits=\(riskyInject.count) dylibRisk=\(dylib.count)"
            ),
            Evidence(
                type: "honesty",
                detail:
                    "Launch constraints and library validation reduce (not eliminate) load/inject "
                    + "classes. This finding is surface truth, not a working exploit."
            ),
        ]
        for path in unconstrained.prefix(12) {
            evidence.append(
                Evidence(
                    type: "unconstrained_risk",
                    path: path,
                    detail: "risk flags without observed constraint artifact"
                )
            )
        }
        for path in constrained.prefix(8) {
            evidence.append(
                Evidence(type: "constraint_artifact", path: path, detail: "constraint-ish path present")
            )
        }
        for hit in riskyInject.prefix(12) {
            evidence.append(
                Evidence(
                    type: "inject_flags",
                    path: hit.path,
                    detail:
                        "HR=\(hit.hardenedRuntime.rootstockDescribe) "
                        + "get-task-allow=\(hit.getTaskAllow.rootstockDescribe) "
                        + "disable-LV=\(hit.disableLibraryValidation.rootstockDescribe) "
                        + "flags=\(hit.riskFlags.joined(separator: ","))"
                )
            )
        }
        for d in dylib.prefix(8) {
            evidence.append(
                Evidence(
                    type: "dylib_risk",
                    path: d.path,
                    detail: "weakDylibs=\(d.weakDylibs.prefix(4).joined(separator: ","))"
                )
            )
        }
        if let lc {
            for note in lc.notes.prefix(8) {
                evidence.append(Evidence(type: "lc_note", detail: note))
            }
        }

        let severity: Severity
        let title: String
        if riskyInject.contains(where: { $0.getTaskAllow == true && $0.hardenedRuntime == false })
            || unconstrained.count >= 2
        {
            severity = .high
            title = "Inject truth: weak HR/get-task-allow without launch-constraint cover"
        } else if !riskyInject.isEmpty || !unconstrained.isEmpty {
            severity = .medium
            title = "Inject truth: library-validation / constraint surface risk"
        } else {
            severity = .low
            title = "Inject truth: dylib load-command risk surface"
        }

        return [
            Finding(
                id: Self.id,
                title: title,
                severity: severity,
                confidence: .medium,
                category: .codesign,
                evidence: evidence,
                attackTechniques: ["T1574.006", "T1055", "T1548"],
                remediation: [
                    "Enable Hardened Runtime; remove get-task-allow from production builds",
                    "Avoid disable-library-validation except for narrowly justified plugins",
                    "Prefer apps that ship launch constraints for privileged spawn relationships",
                    "OPSEC: codesign probes are medium noise under ESF - sample, don't mass-scan",
                ],
                falsePositiveNotes:
                    "Developer and Electron apps often ship with weaker entitlements by design. "
                    + "Constraint artifacts may exist only inside signature blobs not listed as files.",
                dryRunSafe: true,
                opsecScore: 40,
                esfExpected: ["OPEN", "EXEC"]
            ),
        ]
    }

}
