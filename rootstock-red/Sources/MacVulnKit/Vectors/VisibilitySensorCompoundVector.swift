import Foundation
import RootstockCore

/// Wave-10 compound depth: thin TCC/ESF visibility × missing sensors.
///
/// Research basis: eslogger / Unified Logging / TCC.db path visibility literature.
/// Safety and behavior: thin/partial visibility compounded with empty ESF clients or absent products; never dumps TCC.db.
public struct VisibilitySensorCompoundVector: Check {
    public static let id = "rootstock.vector.esf.visibility_sensor_compound"
    public static let cost: CollectorCost = .low

    public init() {}

    public func evaluate(state: CollectedState, context: EvaluationContext) async throws -> [Finding] {
        let vd = state.tccEsfVisibilityDepth
        let tcc = vd?.tccDbPathHits.count ?? 0
        let tools = vd?.visibilityToolPaths.count ?? 0
        let prefs = vd?.privacyPrefPaths.count ?? 0
        let depth = vd?.visibilityDepth ?? "unknown"
        let surface = vd?.visibilitySurfacePresent == true || tcc > 0 || tools > 0

        // Need some visibility plane signal so we are not inventing depth from thin air.
        guard surface || tcc >= 1 || tools >= 1 || prefs >= 1 else { return [] }

        let thinOrPartial = depth == "thin" || depth == "partial"
        let thinTooling = tools < 2
        // Visibility plane is weak: labeled thin/partial OR tooling inventory is thin.
        guard thinOrPartial || thinTooling else { return [] }

        let esfEmpty = state.esf?.clientPaths.isEmpty == true
            || (state.esf == nil && state.collectorNotes["collect.esf_endpoint_security"] != nil)
        let productsAbsent = state.securityProducts.filter(\.present).isEmpty
        // When securityProducts is never populated, treat as absent only if we saw ESF empty
        // or explicit product inventory was collected as empty/false.
        let sensorGap = esfEmpty || productsAbsent

        guard sensorGap else { return [] }

        let fda = state.tcc?.fullDiskAccessLikely == true
        let remote =
            state.network?.remoteLoginSSH == true
            || state.network?.screenSharingARD == true

        var evidence: [Evidence] = [
            Evidence(
                type: "visibility_sensor_compound_summary",
                detail:
                    "depth=\(depth) tccPaths=\(tcc) tools=\(tools) prefs=\(prefs) "
                    + "esfEmpty=\(esfEmpty) productsAbsent=\(productsAbsent) "
                    + "fda=\(fda) remote=\(remote)"
            ),
        ]
        if let vd {
            for path in (vd.tccDbPathHits + vd.visibilityToolPaths).prefix(10) {
                evidence.append(
                    Evidence(type: "visibility_path", path: path, detail: "visibility component (meta only)")
                )
            }
            for n in vd.notes.prefix(4) {
                evidence.append(Evidence(type: "visibility_note", detail: n))
            }
        }
        evidence.append(
            Evidence(
                type: "compound_sensor_gap",
                detail:
                    "sensor gap co-presence: esfClientsEmpty=\(esfEmpty) securityProductsAbsent=\(productsAbsent)"
            )
        )
        evidence.append(
            Evidence(
                type: "honesty",
                detail:
                    "Assess never dumps TCC.db rows, never live-subscribes Endpoint Security without ROE, "
                    + "never disables logging or unloads sensors."
            )
        )

        let severity: Severity
        if thinOrPartial && esfEmpty && remote {
            severity = .high
        } else if thinOrPartial && sensorGap {
            severity = .medium
        } else {
            severity = .low
        }

        return [
            Finding(
                id: Self.id,
                title: thinOrPartial
                    ? "TCC/ESF visibility depth \(depth) compounds with sensor gap"
                    : "Thin visibility tooling compounds with missing ESF/security products",
                severity: severity,
                confidence: .medium,
                category: .misconfig,
                evidence: evidence,
                attackTechniques: ["T1562.001", "T1083", "T1005"],
                remediation: [
                    "Deploy Endpoint Security clients and ensure TCC/FDA grants for security products",
                    "Enable eslogger / Unified Logging pipelines under ROE for purple validation",
                    "Treat unreadable TCC paths as expected without FDA - do not dump rows",
                    "OPSEC: Rootstock Red does not dump TCC.db or unload sensors",
                ],
                falsePositiveNotes:
                    "TCC.db is often unreadable without FDA. Prefer thin/partial depth + empty ESF clients "
                    + "or absent security products over single path misses on hardened hosts.",
                dryRunSafe: true,
                opsecScore: 24,
                esfExpected: ["OPEN", "READ"]
            ),
        ]
    }
}
