import Foundation
import RootstockBlueCore

/// CUPS / print job history inventory for sensitive-document leakage IR.
///
/// Emits job_id, document name, user, printer, and risk tags - not full
/// spool binary dumps.
public struct PrintJobsParser: ArtifactParser {
    public let manifest = PluginManifest(
        id: "PRINTJOBS",
        tier: .tier2,
        description: "CUPS print job history with sensitive-document risk tags"
    )

    public init() {}

    public func parse(source: ImageSource) throws -> [EventEnvelope] {
        let root = ArtifactRoot(source: source)
        var events: [EventEnvelope] = []
        var seen = PathDeduper()

        for rel in [
            "Library/Preferences/print_jobs.json",
            "Library/Preferences/cups_jobs.json",
            "Library/Logs/print_jobs.jsonl",
            "var/spool/cups/jobs.json",
            "private/var/spool/cups/jobs.json",
        ] {
            if let url = root.firstExisting([rel]) {
                if seen.insert(url) {
                    events.append(contentsOf: parseFile(at: url))
                }
            }
        }

        for url in root.enumerate(matching: { url in
            let name = url.lastPathComponent
            return name == "print_jobs.json"
                || name == "cups_jobs.json"
                || name == "print_jobs.jsonl"
                || name == "jobs.json"
        }) {
            if seen.insert(url) {
                events.append(contentsOf: parseFile(at: url))
            }
        }

        return events
    }

    private func parseFile(at url: URL) -> [EventEnvelope] {
        if url.pathExtension == "jsonl" {
            return parseJSONL(at: url)
        }
        return ArtifactIO.jsonDictionaryEntries(
            contentsOf: url,
            nestedKeys: ["jobs", "items"],
            identityKeys: ["job_id", "document"]
        ).compactMap { makeEvent(from: $0, sourceURL: url) }
    }

    private func parseJSONL(at url: URL) -> [EventEnvelope] {
        ArtifactIO.jsonlDictionaries(contentsOf: url)
            .compactMap { makeEvent(from: $0, sourceURL: url) }
    }

    private func makeEvent(from item: [String: Any], sourceURL: URL) -> EventEnvelope? {
        let jobID = stringish(item["job_id"])
            ?? stringish(item["id"])
            ?? stringish(item["job-id"])
            ?? ""
        let document = stringish(item["document"])
            ?? stringish(item["title"])
            ?? stringish(item["job-name"])
            ?? stringish(item["name"])
            ?? ""
        let user = stringish(item["user"])
            ?? stringish(item["job-originating-user-name"])
            ?? ""
        let printer = stringish(item["printer"])
            ?? stringish(item["printer-name"])
            ?? stringish(item["queue"])
            ?? ""
        let pages = stringish(item["pages"]) ?? stringish(item["job-media-sheets"]) ?? ""

        guard !document.isEmpty || !jobID.isEmpty else { return nil }

        var risk: [String] = []
        if let tags = stringish(item["risk_tags"]), !tags.isEmpty {
            risk = tags.split(separator: ",").map { $0.trimmingCharacters(in: .whitespaces) }
        }
        let lowerDoc = document.lowercased()
        if lowerDoc.contains("password") || lowerDoc.contains("secret")
            || lowerDoc.contains("credential") || lowerDoc.contains("ssn")
            || lowerDoc.contains("payroll") || lowerDoc.contains("w2")
            || lowerDoc.contains("bank") || lowerDoc.contains("id_rsa") {
            if !risk.contains("sensitive_document") { risk.append("sensitive_document") }
        }
        if lowerDoc.contains("evil") || lowerDoc.contains("payload") {
            if !risk.contains("suspicious_document") { risk.append("suspicious_document") }
        }
        if printer.lowercased().contains("remote") || printer.lowercased().contains("smb://") {
            if !risk.contains("remote_printer") { risk.append("remote_printer") }
        }

        var fields: [String: String] = [
            "print.job_id": jobID,
            "print.document": document,
            "print.user": user,
            "print.printer": printer,
            "print.pages": pages,
            FieldTaxonomy.eventType: "print.job",
            FieldTaxonomy.userName: user,
        ]
        if let completed = stringish(item["completed_at"]) ?? stringish(item["timestamp"]) {
            fields["print.completed_at"] = completed
        }
        if let state = stringish(item["state"]) ?? stringish(item["job-state"]) {
            fields["print.state"] = state
        }
        if !risk.isEmpty {
            fields["print.risk_tags"] = risk.joined(separator: ",")
        }

        return EventEnvelope(
            eventTime: parseDate(item["completed_at"] ?? item["timestamp"] ?? item["created"])
                ?? Date(timeIntervalSince1970: 0),
            collectedAt: Date(),
            source: .parser,
            sourcePlugin: "PRINTJOBS",
            eventType: "print.job",
            entityRefs: [
                EntityID(kind: .file, value: "print|\(document.isEmpty ? jobID : document)"),
            ],
            fields: fields,
            rawRef: ArtifactRoot.pathKey(sourceURL),
            confidence: 0.88
        )
    }
}
