/// MarkdownReporter - Rootstock product source (see package README for product doctrine).
import Foundation
import RootstockCore

public enum MarkdownReporter {
    public static func render(
        _ findings: [Finding],
        state: CollectedState? = nil
    ) -> String {
        var md = "# Rootstock Red Assessment Report\n\n"
        md += "- Schema: \(RootstockCore.schemaVersion)\n"
        md += "- Platform: \(RootstockCore.version)\n"
        md += "- Findings: \(findings.count)\n\n"

        if let host = state?.host {
            md += "## Host\n\n"
            md += "- Hostname: \(host.hostname)\n"
            md += "- User: \(host.username)\n"
            md += "- OS: \(host.osVersion) (\(host.arch))\n\n"
        }

        md += "## Findings\n\n"
        if findings.isEmpty {
            md += "_No findings._\n"
            return md
        }

        let order: [Severity] = [.critical, .high, .medium, .low, .info]
        for severity in order {
            let group = findings.filter { $0.severity == severity }
            guard !group.isEmpty else { continue }
            md += "### \(severity.rawValue.uppercased()) (\(group.count))\n\n"
            for f in group {
                md += "#### `\(f.id)` - \(f.title)\n\n"
                md += "- Confidence: \(f.confidence.rawValue)\n"
                md += "- Category: \(f.category.rawValue)\n"
                if let score = f.opsecScore {
                    md += "- OPSEC score: \(score)\n"
                }
                if !f.attackTechniques.isEmpty {
                    md += "- ATT&CK: \(f.attackTechniques.joined(separator: ", "))\n"
                }
                if !f.evidence.isEmpty {
                    md += "- Evidence:\n"
                    for e in f.evidence.prefix(10) {
                        let path = e.path.map { " (`\($0)`)" } ?? ""
                        md += "  - \(e.type)\(path): \(e.detail)\n"
                    }
                }
                if !f.remediation.isEmpty {
                    md += "- Remediation: \(f.remediation.joined(separator: "; "))\n"
                }
                md += "\n"
            }
        }
        return md
    }
}
