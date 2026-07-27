import Foundation
import RootstockBlueCore

/// Trash recovery inventory from `.Trash` / `.Trashes` trees and JSON exports.
///
/// Recovers deleted filenames, original paths, and deletion times for IR narrative
/// (anti-forensics delete, credential discards, dropped payloads).
public struct TrashParser: ArtifactParser {
    public let manifest = PluginManifest(
        id: "TRASH",
        tier: .tier2,
        description: "Trash recovery inventory (original path / deleted_at / risk tags)"
    )

    public init() {}

    public func parse(source: ImageSource) throws -> [EventEnvelope] {
        let root = ArtifactRoot(source: source)
        var events: [EventEnvelope] = []
        var seen = PathDeduper()

        for rel in [
            "Library/Preferences/trash_inventory.json",
            "Library/Logs/trash_export.jsonl",
            "Library/Preferences/trash_export.json",
        ] {
            if let url = root.firstExisting([rel]), seen.insert(url) {
                events.append(contentsOf: parseInventoryFile(at: url))
            }
        }

        for url in root.enumerate(matching: { url in
            let name = url.lastPathComponent
            return name == "trash_inventory.json"
                || name == "trash_export.json"
                || name == "trash_export.jsonl"
        }) {
            if seen.insert(url) {
                events.append(contentsOf: parseInventoryFile(at: url))
            }
        }

        // Walk .Trash / .Trashes for residual files not already covered by inventory.
        // Paths are emitted image-relative (under ArtifactRoot), not host-absolute.
        let inventoriedNames = Set(events.compactMap { $0.fields["trash.filename"] }.filter { !$0.isEmpty })
        for url in root.enumerate(matching: { url in
            let path = url.path
            let lower = path.lowercased()
            guard lower.contains("/.trash/") || lower.contains("/.trashes/") else { return false }
            var isDir: ObjCBool = false
            guard FileManager.default.fileExists(atPath: path, isDirectory: &isDir), !isDir.boolValue else {
                return false
            }
            let name = url.lastPathComponent
            return name != "trash_inventory.json" && !name.hasSuffix(".jsonl") && !name.hasSuffix(".json")
        }) {
            let filename = url.lastPathComponent
            // Avoid duplicate rows when inventory already listed the same item
            if inventoriedNames.contains(filename) { continue }
            let relKey = "trash-file:" + relativePath(of: url, under: root)
            if seen.insert(pathKey: relKey) {
                if let event = makeFromTrashFile(url: url, root: root) {
                    events.append(event)
                }
            }
        }

        return events
    }

    private func parseInventoryFile(at url: URL) -> [EventEnvelope] {
        if url.pathExtension == "jsonl" || url.lastPathComponent.hasSuffix(".jsonl") {
            return ArtifactIO.jsonlDictionaries(contentsOf: url).compactMap { makeEvent(from: $0, sourceURL: url) }
        }
        guard let obj = ArtifactIO.jsonObject(contentsOf: url) else { return [] }

        let entries = ArtifactIO.dictionaryEntries(
            from: obj,
            nestedKeys: ["items", "trash", "entries"],
            identityKeys: ["filename", "original_path"]
        )
        return entries.compactMap { makeEvent(from: $0, sourceURL: url) }
    }

    private func makeFromTrashFile(url: URL, root: ArtifactRoot) -> EventEnvelope? {
        let filename = url.lastPathComponent
        // Image-relative path under ArtifactRoot (never host-absolute /Users/<dev>/…)
        let trashPath = relativePath(of: url, under: root)
        return makeEvent(
            from: [
                "filename": filename,
                "trash_path": trashPath,
                "original_path": "",
            ],
            sourceURL: url,
            imageRoot: root
        )
    }

    private func makeEvent(
        from item: [String: Any],
        sourceURL: URL,
        imageRoot: ArtifactRoot? = nil
    ) -> EventEnvelope? {
        let filename = stringish(item["filename"])
            ?? stringish(item["name"])
            ?? stringish(item["item"])
            ?? ""
        let original = stringish(item["original_path"])
            ?? stringish(item["originalPath"])
            ?? stringish(item["where_from"])
            ?? ""
        var trashPath = stringish(item["trash_path"])
            ?? stringish(item["path"])
            ?? ""
        // Prefer image-relative path when source is under a known artifact root
        if trashPath.isEmpty, let imageRoot {
            trashPath = relativePath(of: sourceURL, under: imageRoot)
        } else if trashPath.isEmpty {
            // Last resort: still try to strip a host Users/.../Users/ image prefix
            trashPath = imageRelativePath(ArtifactRoot.pathKey(sourceURL))
        } else {
            trashPath = imageRelativePath(trashPath)
        }
        let deletedAt = stringish(item["deleted_at"])
            ?? stringish(item["deletion_date"])
            ?? stringish(item["timestamp"])
            ?? ""

        guard !filename.isEmpty || !original.isEmpty || trashPath.lowercased().contains(".trash") else {
            return nil
        }

        var risk: [String] = []
        if let tags = stringish(item["risk_tags"]), !tags.isEmpty {
            risk = tags.split(separator: ",").map { $0.trimmingCharacters(in: .whitespaces) }
        }
        let lowerName = filename.lowercased()
        let lowerOrig = original.lowercased()
        if lowerName.contains("id_rsa") || lowerName.hasSuffix(".pem")
            || lowerOrig.contains(".ssh/") || lowerName.contains("password")
            || lowerName.contains("credential") || lowerName.contains("secret") {
            if !risk.contains("credential_material") { risk.append("credential_material") }
            if !risk.contains("sensitive_path") { risk.append("sensitive_path") }
        }
        if lowerName.contains("evil") || lowerOrig.contains("evil")
            || lowerName.contains("payload") || lowerName.contains("implant") {
            if !risk.contains("suspicious_name") { risk.append("suspicious_name") }
        }
        if lowerOrig.contains("/tmp/") || lowerOrig.contains("/downloads/") {
            if !risk.contains("tmp_origin") { risk.append("tmp_origin") }
        }
        // Heuristic: no extension + name looks like agent/binary
        if !lowerName.contains(".")
            && (lowerName.contains("agent") || lowerName.contains("implant") || lowerName.contains("payload")
                || boolish(item["executable"]) == true) {
            if !risk.contains("executable") { risk.append("executable") }
        }
        if boolish(item["executable"]) == true, !risk.contains("executable") {
            risk.append("executable")
        }

        // Never copy private key material into fields - metadata only
        var fields: [String: String] = [
            "trash.filename": filename,
            "trash.original_path": original,
            "trash.trash_path": trashPath,
            "trash.deleted_at": deletedAt,
            FieldTaxonomy.eventType: "filesystem.trash",
        ]
        if !risk.isEmpty {
            fields["trash.risk_tags"] = risk.joined(separator: ",")
        }
        if let size = stringish(item["size_bytes"]) ?? stringish(item["size"]) {
            fields["trash.size_bytes"] = size
        }
        // Prefer last Users/ segment so fixture trees under /Users/<dev>/…/Users/alice resolve to alice
        if let user = inferUser(from: trashPath.isEmpty ? original : trashPath)
            ?? inferUser(from: original)
            ?? inferUser(from: ArtifactRoot.pathKey(sourceURL)) {
            fields[FieldTaxonomy.userName] = user
        }

        var refs: [EntityID] = []
        if !original.isEmpty { refs.append(.file(path: original)) }
        if !trashPath.isEmpty { refs.append(.file(path: trashPath)) }
        refs.append(EntityID(kind: .host, value: "trash|\(filename)"))

        return EventEnvelope(
            eventTime: parseDate(item["deleted_at"] ?? item["deletion_date"] ?? item["timestamp"])
                ?? Date(timeIntervalSince1970: 0),
            collectedAt: Date(),
            source: .parser,
            sourcePlugin: "TRASH",
            eventType: "filesystem.trash",
            entityRefs: refs,
            fields: fields,
            rawRef: ArtifactRoot.pathKey(sourceURL),
            confidence: 0.9
        )
    }

    /// Path relative to the artifact image root (POSIX separators).
    private func relativePath(of url: URL, under root: ArtifactRoot) -> String {
        let abs = ArtifactRoot.pathKey(url)
        let rootPath = ArtifactRoot.pathKey(root.root)
        if abs == rootPath { return "" }
        if abs.hasPrefix(rootPath + "/") {
            return String(abs.dropFirst(rootPath.count + 1))
        }
        return imageRelativePath(abs)
    }

    /// Strip host prefix before the image's own `Users/` segment when present.
    private func imageRelativePath(_ path: String) -> String {
        let parts = path.split(separator: "/").map(String.init)
        if let idx = parts.lastIndex(of: "Users"), idx + 1 < parts.count {
            return parts[idx...].joined(separator: "/")
        }
        // Prefer paths that already look image-relative
        if path.hasPrefix("Users/") || path.hasPrefix("Library/") || path.hasPrefix("var/") {
            return path
        }
        return path
    }
}
