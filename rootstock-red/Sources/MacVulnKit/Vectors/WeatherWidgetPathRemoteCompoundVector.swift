import Foundation
import RootstockCore

/// Wave-16 compound: Weather widget residual × remote/FDA path-to-impact.
public struct WeatherWidgetPathRemoteCompoundVector: Check {
    public static let id = "rootstock.vector.data.weather_widget_path_remote_compound"
    public static let cost: CollectorCost = .low
    public init() {}
    public func evaluate(state: CollectedState, context: EvaluationContext) async throws -> [Finding] {
        let s = state.weatherWidgetPath
        let a = s?.weatherAppPaths.count ?? 0
        let b = s?.weatherContainerPaths.count ?? 0
        guard a >= 1, b >= 1 || a >= 2 else { return [] }
        let remote = state.network?.remoteLoginSSH == true || state.network?.screenSharingARD == true
        let fda = state.tcc?.fullDiskAccessLikely == true
        let sensorThin = state.esf?.clientPaths.isEmpty == true || state.securityProducts.filter(\.present).isEmpty
        guard remote || fda || sensorThin || a + b >= 3 else { return [] }
        var evidence: [Evidence] = [
            Evidence(type: "weather_widget_path_compound", detail: "a=\(a) b=\(b) remote=\(remote) fda=\(fda) sensorThin=\(sensorThin)"),
        ]
        if let s {
            for path in (s.weatherAppPaths + s.weatherContainerPaths).prefix(6) {
                evidence.append(Evidence(type: "compound_path", path: path, detail: "Weather widget residual compound"))
            }
        }
        evidence.append(Evidence(type: "honesty", detail: "never dumps weather personalization data or widget timeline contents."))
        let severity: Severity = (remote && fda) ? .high : ((remote || fda || sensorThin) ? .medium : .low)
        return [Finding(
            id: Self.id,
            title: remote ? "Weather widget residual × remote compound" : "Weather widget residual × impact compound",
            severity: severity, confidence: .medium, category: .misconfig, evidence: evidence,
            attackTechniques: ["T1005", "T1083", "T1518"],
            remediation: [
                "Prioritize hosts co-locating Weather widget residual with remote/FDA amplifiers",
                "Use Wave-16 lab plans under ROE for purple validation",
                "OPSEC: path-to-impact ranking only - not an auto-exploit chain",
            ],
            falsePositiveNotes: "Developer hosts may co-locate dual-use paths; rank production remote hosts first.",
            dryRunSafe: true, opsecScore: 27, esfExpected: ["OPEN", "EXEC", "READ"]
        )]
    }
}
