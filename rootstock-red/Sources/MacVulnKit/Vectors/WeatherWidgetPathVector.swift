import Foundation
import RootstockCore

/// Path-to-impact: Weather / widget data residual plane.
public struct WeatherWidgetPathVector: Check {
    public static let id = "rootstock.vector.data.weather_widget_path"
    public static let cost: CollectorCost = .low
    public init() {}
    public func evaluate(state: CollectedState, context: EvaluationContext) async throws -> [Finding] {
        let s = state.weatherWidgetPath
        let a = s?.weatherAppPaths.count ?? 0
        let b = s?.weatherContainerPaths.count ?? 0
        let c = s?.widgetServicePaths.count ?? 0
        let surface = s?.weatherSurfacePresent == true || a + b + c >= 2
        let note = state.collectorNotes["collect.weather_widget_path"] != nil
        guard surface || note else { return [] }
        guard a >= 1 || b >= 1 else { return [] }
        let remote = state.network?.remoteLoginSSH == true || state.network?.screenSharingARD == true
        let fda = state.tcc?.fullDiskAccessLikely == true
        var evidence: [Evidence] = [
            Evidence(type: "weather_widget_path_summary", detail: "a=\(a) b=\(b) c=\(c) remote=\(remote) fda=\(fda)"),
        ]
        if let s {
            for path in (s.weatherAppPaths + s.weatherContainerPaths + s.widgetServicePaths).prefix(10) {
                evidence.append(Evidence(type: "weather_widget_path_path", path: path, detail: "Weather widget residual path"))
            }
            for n in s.notes.prefix(4) { evidence.append(Evidence(type: "weather_widget_path_note", detail: n)) }
        }
        evidence.append(Evidence(type: "honesty", detail: "Assess never dumps weather personalization data or widget timeline contents."))
        let severity: Severity = (remote && fda && a + b >= 3) ? .high : ((remote || fda || a + b >= 2) ? .medium : .low)
        return [Finding(
            id: Self.id,
            title: remote ? "Weather widget residual with remote amplifier" : "Weather / widget data residual plane",
            severity: severity, confidence: .medium, category: .misconfig, evidence: evidence,
            attackTechniques: ["T1005", "T1083", "T1518"],
            remediation: [
                "Inventory and baseline Weather widget residual paths via MDM/EDR",
                "Correlate unexpected co-presence with delivery timelines",
                "Prioritize hosts with remote/FDA amplifiers",
                "OPSEC: Rootstock Red never dumps weather personalization data or widget timeline contents",
            ],
            falsePositiveNotes: "Stock paths often exist. Elevate multi-path co-presence with remote/FDA.",
            dryRunSafe: true, opsecScore: 25, esfExpected: ["OPEN", "READ", "EXEC"]
        )]
    }
}
