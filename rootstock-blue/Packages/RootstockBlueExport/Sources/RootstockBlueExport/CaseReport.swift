import Foundation
import RootstockBlueCore
import RootstockBlueCase

/// Human-readable case report export for IR operators.
/// Anchors output to case custody, timeline statistics, plugin breakdowns, and
/// optional findings.
public enum CaseReport {
    public struct Stats: Sendable {
        public var caseID: String
        public var caseName: String
        public var eventCount: Int
        public var byPlugin: [(plugin: String, count: Int)]
        public var byEventType: [(eventType: String, count: Int)]
        public var entityRefCount: Int
        public var custodyLines: Int
        public var findings: [Finding]
        public var generatedAt: Date

        public init(
            caseID: String,
            caseName: String,
            eventCount: Int,
            byPlugin: [(plugin: String, count: Int)],
            byEventType: [(eventType: String, count: Int)],
            entityRefCount: Int,
            custodyLines: Int,
            findings: [Finding] = [],
            generatedAt: Date = Date()
        ) {
            self.caseID = caseID
            self.caseName = caseName
            self.eventCount = eventCount
            self.byPlugin = byPlugin
            self.byEventType = byEventType
            self.entityRefCount = entityRefCount
            self.custodyLines = custodyLines
            self.findings = findings
            self.generatedAt = generatedAt
        }
    }

    /// Compute stats from a real `.rsbcase` package.
    public static func collectStats(
        from package: CasePackage,
        findings: [Finding] = []
    ) throws -> Stats {
        let events = try package.loadAllEvents()
        var pluginCounts: [String: Int] = [:]
        var typeCounts: [String: Int] = [:]
        var entityCount = 0
        for e in events {
            pluginCounts[e.sourcePlugin, default: 0] += 1
            typeCounts[e.eventType, default: 0] += 1
            entityCount += e.entityRefs.count
        }
        let byPlugin = pluginCounts
            .map { (plugin: $0.key, count: $0.value) }
            .sorted { $0.count > $1.count || ($0.count == $1.count && $0.plugin < $1.plugin) }
        let byType = typeCounts
            .map { (eventType: $0.key, count: $0.value) }
            .sorted { $0.count > $1.count || ($0.count == $1.count && $0.eventType < $1.eventType) }

        var custodyLines = 0
        if let text = try? String(contentsOf: package.custodyURL, encoding: .utf8) {
            custodyLines = text.split(whereSeparator: \.isNewline).filter { !$0.trimmingCharacters(in: .whitespaces).isEmpty }.count
        }

        return Stats(
            caseID: package.manifest.caseID.uuidString,
            caseName: package.manifest.name,
            eventCount: events.count,
            byPlugin: byPlugin,
            byEventType: byType,
            entityRefCount: entityCount,
            custodyLines: custodyLines,
            findings: findings
        )
    }

    /// Render a markdown IR case report (non-empty when case has events).
    public static func renderMarkdown(_ stats: Stats) -> String {
        let iso = ISO8601DateFormatter()
        var md = ""
        md += "# IR Case Report: \(stats.caseName)\n\n"
        md += "- Generated: \(iso.string(from: stats.generatedAt))\n"
        md += "- Case ID: `\(stats.caseID)`\n"
        md += "- Timeline events: \(stats.eventCount)\n"
        md += "- Entity references: \(stats.entityRefCount)\n"
        md += "- Custody log entries: \(stats.custodyLines)\n"
        md += "- Findings: \(stats.findings.count)\n\n"

        md += "## Events by source plugin\n\n"
        if stats.byPlugin.isEmpty {
            md += "_No events in case._\n\n"
        } else {
            md += "| Plugin | Count |\n|--------|------:|\n"
            for row in stats.byPlugin {
                md += "| \(row.plugin) | \(row.count) |\n"
            }
            md += "\n"
        }

        md += "## Events by type\n\n"
        if stats.byEventType.isEmpty {
            md += "_No event types._\n\n"
        } else {
            md += "| Event type | Count |\n|------------|------:|\n"
            for row in stats.byEventType.prefix(40) {
                md += "| \(row.eventType) | \(row.count) |\n"
            }
            md += "\n"
        }

        md += "## Findings\n\n"
        if stats.findings.isEmpty {
            md += "_No detection findings attached to this report._\n\n"
        } else {
            let order = ["critical", "high", "medium", "low", "info"]
            for sev in order {
                let group = stats.findings.filter { $0.severity.lowercased() == sev }
                guard !group.isEmpty else { continue }
                md += "### \(sev.uppercased()) (\(group.count))\n\n"
                for f in group {
                    md += "- [\(f.severity)] `\(f.ruleID)` - \(f.title)\n"
                    if !f.attackTechniques.isEmpty {
                        md += "  - ATT&CK: \(f.attackTechniques.joined(separator: ", "))\n"
                    }
                    if !f.evidenceSummary.isEmpty {
                        md += "  - Evidence: \(f.evidenceSummary)\n"
                    }
                }
                md += "\n"
            }
        }

        md += "## Custody\n\n"
        md += "Chain-of-custody has \(stats.custodyLines) logged action(s). "
        md += "Verify hashes with `rootstock-blue case verify`.\n"
        return md
    }

    /// Write report to disk and update case custody/hashes.
    @discardableResult
    public static func exportMarkdown(
        package: CasePackage,
        to url: URL,
        findings: [Finding] = [],
        actor: String = NSUserName()
    ) throws -> Stats {
        let stats = try collectStats(from: package, findings: findings)
        let body = renderMarkdown(stats)
        try body.write(to: url, atomically: true, encoding: .utf8)
        // Also copy into case artifacts for package integrity
        let destName = "reports/\(url.lastPathComponent)"
        _ = try? package.copyArtifact(from: url, relativeName: destName)
        try package.appendCustody(
            CustodyEvent(
                actor: actor,
                action: "report",
                detail: "Exported markdown report events=\(stats.eventCount) findings=\(findings.count) path=\(url.path)"
            )
        )
        try package.updateHashes()
        return stats
    }
}
