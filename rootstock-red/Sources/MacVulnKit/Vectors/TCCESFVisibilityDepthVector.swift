import Foundation
import RootstockCore

/// Path-to-impact: TCC/ESF operator visibility-depth posture.
///
/// Research basis: eslogger / Unified Logging / TCC.db path visibility literature.
/// Safety and behavior: depth labels + sensor-gap compound; never dumps TCC.db rows.
public struct TCCESFVisibilityDepthVector: Check {
    public static let id = "rootstock.vector.esf.tcc_visibility_depth"
    public static let cost: CollectorCost = .low

    public init() {}

    public func evaluate(state: CollectedState, context: EvaluationContext) async throws -> [Finding] {
        let vd = state.tccEsfVisibilityDepth
        let tcc = vd?.tccDbPathHits.count ?? 0
        let tools = vd?.visibilityToolPaths.count ?? 0
        let prefs = vd?.privacyPrefPaths.count ?? 0
        let depth = vd?.visibilityDepth ?? "unknown"
        let surface = vd?.visibilitySurfacePresent == true || tcc > 0 || tools > 0
        let note = state.collectorNotes["collect.tcc_esf_visibility_depth"] != nil

        guard surface || note else { return [] }
        guard tcc >= 1 || tools >= 1 || prefs >= 1 else { return [] }

        let sensorGap = state.esf?.clientPaths.isEmpty == true
        let fda = state.tcc?.fullDiskAccessLikely == true
        let remote =
            state.network?.remoteLoginSSH == true
            || state.network?.screenSharingARD == true

        var evidence: [Evidence] = [
            Evidence(
                type: "visibility_summary",
                detail:
                    "tccPaths=\(tcc) tools=\(tools) prefs=\(prefs) depth=\(depth) "
                    + "sensorGap=\(sensorGap) fda=\(fda) remote=\(remote)"
            ),
        ]
        if let vd {
            for path in (vd.tccDbPathHits + vd.visibilityToolPaths).prefix(12) {
                evidence.append(Evidence(type: "visibility_path", path: path, detail: "visibility component"))
            }
            for n in vd.notes.prefix(6) {
                evidence.append(Evidence(type: "visibility_note", detail: n))
            }
        }
        evidence.append(
            Evidence(
                type: "honesty",
                detail:
                    "Assess never dumps TCC.db rows, never live-subscribes Endpoint Security without ROE, "
                    + "never disables logging or unloads sensors."
            )
        )

        // Thin visibility with sensor gap is the interesting path-to-impact; strong visibility is lower severity.
        let severity: Severity
        if (depth == "thin" || depth == "partial") && sensorGap && remote {
            severity = .high
        } else if depth == "thin" || (sensorGap && tools < 2) {
            severity = .medium
        } else if depth == "strong" && fda {
            severity = .low
        } else {
            severity = .low
        }

        return [
            Finding(
                id: Self.id,
                title: depth == "thin" || depth == "partial"
                    ? "TCC/ESF visibility depth is \(depth) - detection-blind collection class"
                    : "TCC/ESF visibility-depth posture (\(depth))",
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
                    "TCC.db is often unreadable without FDA. Prefer sensor-gap + thin tooling compounds "
                    + "over single path misses on hardened hosts.",
                dryRunSafe: true,
                opsecScore: 22,
                esfExpected: ["OPEN", "READ"]
            ),
        ]
    }
}
