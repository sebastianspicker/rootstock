import Foundation
import RootstockCore

/// Minimal SARIF 2.1.0 emitter for findings.
public enum SARIFReporter {
    public static func render(_ findings: [Finding]) throws -> Data {
        let results: [[String: Any]] = findings.map { finding in
            let level: String
            switch finding.severity {
            case .info: level = "note"
            case .low: level = "note"
            case .medium: level = "warning"
            case .high, .critical: level = "error"
            }
            let locations: [[String: Any]] = finding.evidence.compactMap { ev in
                guard let path = ev.path else { return nil }
                return [
                    "physicalLocation": [
                        "artifactLocation": ["uri": path],
                    ],
                ]
            }
            var result: [String: Any] = [
                "ruleId": finding.id,
                "level": level,
                "message": ["text": finding.title],
            ]
            if !locations.isEmpty {
                result["locations"] = locations
            }
            if !finding.attackTechniques.isEmpty {
                result["properties"] = ["attackTechniques": finding.attackTechniques]
            }
            return result
        }

        let rules: [[String: Any]] = findings.map { finding in
            [
                "id": finding.id,
                "name": finding.id,
                "shortDescription": ["text": finding.title],
                "fullDescription": [
                    "text": finding.evidence.map(\.detail).joined(separator: "; "),
                ],
                "properties": [
                    "severity": finding.severity.rawValue,
                    "category": finding.category.rawValue,
                ],
            ]
        }

        let sarif: [String: Any] = [
            "version": "2.1.0",
            "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
            "runs": [
                [
                    "tool": [
                        "driver": [
                            "name": "Rootstock Red",
                            "version": RootstockCore.version,
                            "informationUri": "https://github.com/example/rootstock-red",
                            "rules": rules,
                        ],
                    ],
                    "results": results,
                ],
            ],
        ]

        return try JSONSerialization.data(withJSONObject: sarif, options: [.prettyPrinted, .sortedKeys])
    }
}
