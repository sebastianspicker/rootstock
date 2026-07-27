/// Offline forensic parser: XProtectParser - fixture-backed IR events (no secret export).
import Foundation
import RootstockBlueCore

public struct XProtectParser: ArtifactParser {
    public let manifest = PluginManifest(
        id: "XPROTECT",
        tier: .tier1,
        description: "XProtect diagnostic text/logs"
    )

    public init() {}

    public func parse(source: ImageSource) throws -> [EventEnvelope] {
        let root = ArtifactRoot(source: source)
        let files = root.enumerate { url in
            let name = url.lastPathComponent.lowercased()
            return name.contains("xprotect") && (url.pathExtension == "diag" || url.pathExtension == "log" || url.pathExtension == "txt" || name.hasSuffix(".diag"))
        }
        var events: [EventEnvelope] = []
        for file in files {
            guard let text = try? String(contentsOf: file, encoding: .utf8) else { continue }
            for line in text.split(whereSeparator: \.isNewline) {
                let s = String(line)
                guard s.lowercased().contains("xprotect") || s.lowercased().contains("malware") else { continue }
                let malware = extract(after: "detected ", in: s) ?? extract(after: "OSX.", in: s).map { "OSX.\($0)" } ?? "unknown"
                let path = extract(after: "path=", in: s) ?? ""
                events.append(
                    EventEnvelope(
                        eventTime: Date(timeIntervalSince1970: 0),
                        collectedAt: Date(),
                        source: .parser,
                        sourcePlugin: "XPROTECT",
                        eventType: "xprotect.detection",
                        entityRefs: path.isEmpty ? [] : [.file(path: path)],
                        fields: [
                            FieldTaxonomy.xprotectMalware: malware,
                            FieldTaxonomy.filePath: path,
                            "xprotect.line": s,
                            "xprotect.log_path": file.path,
                            FieldTaxonomy.eventType: "xprotect.detection",
                        ],
                        rawRef: file.path,
                        confidence: 0.75
                    )
                )
            }
        }
        return events
    }

    private func extract(after token: String, in line: String) -> String? {
        guard let r = line.range(of: token, options: .caseInsensitive) else { return nil }
        let rest = line[r.upperBound...]
        let end = rest.firstIndex(where: { $0 == " " || $0 == "\t" }) ?? rest.endIndex
        let value = String(rest[..<end]).trimmingCharacters(in: .whitespaces)
        return value.isEmpty ? nil : value
    }
}
