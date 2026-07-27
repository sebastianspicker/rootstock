import Foundation
import RootstockCore

/// Path-to-impact: XPC / privileged-helper *client validation* trust surface.
///
/// Research basis: Objective-See XPC research; PEASS helper listings; CDHash+NIB helper themes.
/// Safety and behavior: compound helper inventory with inject/codesign weakness and SIP honesty;
/// distinct from filename-only abuse surface - emphasizes trust-validation gap narrative.
public struct XPCClientValidationSurfaceVector: Check {
    public static let id = "rootstock.vector.xpc.client_validation_surface"
    public static let cost: CollectorCost = .low

    public init() {}

    public func evaluate(state: CollectedState, context: EvaluationContext) async throws -> [Finding] {
        let helpers = state.privilegedHelperTools
        let extensions = state.systemExtensionPaths
        guard !helpers.isEmpty || !extensions.isEmpty else { return [] }

        // Require trust-relevant compound: inject flags, weak codesign samples near helpers,
        // collector risk note, or scale with missing EDR.
        let injectWeak = state.injectabilityHits.contains {
            $0.disableLibraryValidation == true
                || $0.getTaskAllow == true
                || $0.hardenedRuntime == false
                || $0.riskFlags.contains("disable-library-validation")
        }
        let unsignedish = state.codesignSamples.contains { $0.signed == false || $0.hardenedRuntime == false }
        let riskNote =
            state.collectorNotes["privesc.xpc_risk"] != nil
            || state.collectorNotes["xpc.client_validation"] != nil
        let scale = helpers.count + extensions.count >= 2
        let noEDR = !state.securityProducts.contains(where: \.present)

        let shouldFire =
            injectWeak
            || unsignedish
            || riskNote
            || (scale && (injectWeak || noEDR || riskNote))
            || helpers.count >= 3
        guard shouldFire else { return [] }

        var evidence: [Evidence] = [
            Evidence(
                type: "summary",
                detail:
                    "helpers=\(helpers.count) sysext=\(extensions.count) "
                    + "injectWeak=\(injectWeak) unsignedish=\(unsignedish) noEDR=\(noEDR)"
            ),
            Evidence(
                type: "trust_narrative",
                detail:
                    "Public XPC abuse classes often involve helpers that under-validate client "
                    + "code signature / team ID / audit token. Assess does not reverse private "
                    + "XPC protocols - this finding flags surface for manual authorized review."
            ),
        ]
        for h in helpers.prefix(20) {
            let path = h.hasPrefix("/") ? h : "/Library/PrivilegedHelperTools/\(h)"
            evidence.append(
                Evidence(
                    type: "helper",
                    path: path,
                    detail: "privileged helper inventory entry (no binary reverse)"
                )
            )
        }
        for ext in extensions.prefix(10) {
            evidence.append(Evidence(type: "system_extension", path: ext, detail: "sygext path"))
        }
        if injectWeak {
            let hits = state.injectabilityHits.filter {
                $0.disableLibraryValidation == true || $0.getTaskAllow == true || $0.hardenedRuntime == false
            }
            for hit in hits.prefix(8) {
                evidence.append(
                    Evidence(
                        type: "inject_compound",
                        path: hit.path,
                        detail: "flags=\(hit.riskFlags.joined(separator: ","))"
                    )
                )
            }
        }
        if state.protections?.sipEnabled == true {
            evidence.append(
                Evidence(
                    type: "sip_honesty",
                    detail: "SIP on - installing new system helpers still needs root; focus on existing helpers"
                )
            )
        }

        let severity: Severity
        let title: String
        if injectWeak && !helpers.isEmpty {
            severity = .high
            title = "XPC client-validation surface: helpers with injectability compound"
        } else if helpers.count >= 3 {
            severity = .medium
            title = "XPC client-validation surface: large helper inventory (\(helpers.count))"
        } else {
            severity = .low
            title = "XPC helper trust surface (\(helpers.count + extensions.count) paths)"
        }

        return [
            Finding(
                id: Self.id,
                title: title,
                severity: severity,
                confidence: .medium,
                category: .xpc,
                evidence: evidence,
                attackTechniques: ["T1559", "T1543.001", "T1543.004", "T1068"],
                remediation: [
                    "Inventory and remove unexpected Privileged Helper Tools",
                    "Prefer helpers that validate client audit token + code signature (Team ID)",
                    "Correlate with Login Items / BTM for residual helper services",
                    "OPSEC: listing helpers is quiet; installing fake helpers is lab-only high risk",
                ],
                falsePositiveNotes:
                    "Security/MDM products legitimately install helpers. Filename inventory is not proof "
                    + "of a vulnerable XPC interface.",
                dryRunSafe: true,
                opsecScore: injectWeak ? 48 : 28,
                esfExpected: ["OPEN"]
            ),
        ]
    }
}
