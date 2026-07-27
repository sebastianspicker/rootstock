import Foundation
import RootstockBlueCore

/// Background Task Management (BTM) items - macOS 13+ login/background items.
///
/// Type bit flags (mac_apt 2025 / Apple BTM research):
/// - 0x1  user item
/// - 0x2  app
/// - 0x4  login item
/// - 0x8  agent
/// - 0x10 daemon
/// - 0x20 developer
/// - 0x40 managed
/// - 0x80 curated
///
/// Disposition bit flags:
/// - 0x1 Enabled
/// - 0x2 Allowed
/// - 0x4 Hidden
/// - 0x8 Notified
public struct BTMParser: ArtifactParser {
    public let manifest = PluginManifest(
        id: "BTM",
        tier: .tier1,
        description: "Background Task Management (BTM) login/background items"
    )

    public init() {}

    public func parse(source: ImageSource) throws -> [EventEnvelope] {
        let root = ArtifactRoot(source: source)
        var urls: [URL] = []

        // Prefer well-known BTM database locations.
        for found in root.enumerate(matching: { url in
            let name = url.lastPathComponent
            let path = url.path
            if name.hasPrefix("BackgroundItems-v") && (name.hasSuffix(".btm") || name.hasSuffix(".btm.json") || name.hasSuffix(".json")) {
                return true
            }
            if name == "BackgroundItems.json" {
                return true
            }
            if name.hasSuffix(".btm.json") {
                return true
            }
            // Intermediate forensic JSON sitting beside the BTM store.
            if path.contains("backgroundtaskmanagement") && (name.hasSuffix(".json") || name.hasSuffix(".btm")) {
                return true
            }
            return false
        }) {
            ArtifactRoot.appendUnique(&urls, found)
        }

        // Explicit firstExisting for standard paths (covers empty enumerations edge cases).
        let candidates = [
            "private/var/db/com.apple.backgroundtaskmanagement",
            "var/db/com.apple.backgroundtaskmanagement",
        ]
        for dirRel in candidates {
            let dir = root.file(dirRel)
            guard let items = try? FileManager.default.contentsOfDirectory(
                at: dir,
                includingPropertiesForKeys: nil,
                options: [.skipsHiddenFiles]
            ) else { continue }
            for item in items {
                let name = item.lastPathComponent
                if name.hasPrefix("BackgroundItems") || name.hasSuffix(".btm") || name.hasSuffix(".btm.json") || name.hasSuffix(".json") {
                    ArtifactRoot.appendUnique(&urls, item)
                }
            }
        }

        var events: [EventEnvelope] = []
        var seenSources = PathDeduper()
        for url in urls {
            guard seenSources.insert(url) else { continue }
            events.append(contentsOf: parseBTMFile(at: url))
        }
        return events
    }

    private func parseBTMFile(at url: URL) -> [EventEnvelope] {
        guard let data = ArtifactIO.data(contentsOf: url) else { return [] }

        // Forensic intermediate JSON.
        if url.pathExtension == "json" || url.lastPathComponent.hasSuffix(".btm.json") {
            if let items = parseJSONItems(data) {
                return items.enumerated().compactMap { idx, item in
                    makeEvent(item: item, sourceURL: url, index: idx)
                }
            }
        }

        // Simplified plist with an `items` array (fixture-friendly).
        if let dict = ArtifactIO.plistDict(from: data),
           let items = extractItems(from: dict) {
            return items.enumerated().compactMap { idx, item in
                makeEvent(item: item, sourceURL: url, index: idx)
            }
        }

        // Raw .btm may also be JSON dumped by collection tools.
        if let items = parseJSONItems(data) {
            return items.enumerated().compactMap { idx, item in
                makeEvent(item: item, sourceURL: url, index: idx)
            }
        }

        return []
    }

    private func parseJSONItems(_ data: Data) -> [[String: Any]]? {
        guard let obj = ArtifactIO.jsonObject(from: data) else { return nil }
        return extractItems(from: obj)
    }

    private func extractItems(from obj: Any) -> [[String: Any]]? {
        if let dict = obj as? [String: Any] {
            if let items = dict["items"] as? [[String: Any]] {
                return items
            }
            if let items = dict["Items"] as? [[String: Any]] {
                return items
            }
            if let items = dict["items"] as? [Any] {
                return items.compactMap { $0 as? [String: Any] }
            }
        }
        if let arr = obj as? [[String: Any]] {
            return arr
        }
        if let arr = obj as? [Any] {
            return arr.compactMap { $0 as? [String: Any] }
        }
        return nil
    }

    private func makeEvent(item: [String: Any], sourceURL: URL, index: Int) -> EventEnvelope? {
        let name = stringValue(item["name"]) ?? stringValue(item["Name"]) ?? ""
        let urlStr = stringValue(item["url"]) ?? stringValue(item["URL"]) ?? stringValue(item["item_url"]) ?? ""
        let execPath = stringValue(item["executable_path"])
            ?? stringValue(item["executablePath"])
            ?? stringValue(item["ExecutablePath"])
            ?? ""
        let typeRaw = intValue(item["type"] ?? item["Type"]) ?? 0
        let dispositionRaw = intValue(item["disposition"] ?? item["Disposition"]) ?? 0
        let developer = stringValue(item["developer"]) ?? stringValue(item["Developer"]) ?? ""
        let container = stringValue(item["container"]) ?? stringValue(item["Container"]) ?? ""
        let user = stringValue(item["user"]) ?? stringValue(item["User"]) ?? ""
        let uid = stringValue(item["uid"]) ?? stringValue(item["UID"]) ?? ""

        guard !name.isEmpty || !execPath.isEmpty || !urlStr.isEmpty else { return nil }

        let typeLabel = typeLabels(typeRaw).joined(separator: ",")
        let dispLabels = dispositionLabels(dispositionRaw).joined(separator: ",")

        // Prefer executable path, then file URL path, then source.
        let filePath: String = {
            if !execPath.isEmpty { return execPath }
            if urlStr.hasPrefix("file://"), let u = URL(string: urlStr) {
                return u.path
            }
            if !urlStr.isEmpty { return urlStr }
            return ArtifactRoot.pathKey(sourceURL)
        }()

        var fields: [String: String] = [
            "btm.name": name,
            "btm.type": String(typeRaw),
            "btm.type_label": typeLabel,
            "btm.disposition": String(dispositionRaw),
            "btm.disposition_labels": dispLabels,
            "btm.executable_path": execPath,
            "btm.url": urlStr,
            "btm.developer": developer,
            "btm.container": container,
            "btm.user": user,
            "btm.uid": uid,
            "btm.index": String(index),
            FieldTaxonomy.btmItemPath: filePath,
            FieldTaxonomy.btmItemType: typeLabel.isEmpty ? String(typeRaw) : typeLabel,
            FieldTaxonomy.filePath: filePath,
            FieldTaxonomy.eventType: "persistence.btm_item",
        ]
        if !user.isEmpty {
            fields[FieldTaxonomy.userName] = user
        }
        if !execPath.isEmpty {
            fields[FieldTaxonomy.processPath] = execPath
        }

        var entities: [EntityID] = [
            EntityID(kind: .persistence, value: "btm|\(name.isEmpty ? filePath : name)"),
            .file(path: filePath),
        ]
        if !user.isEmpty {
            entities.append(.user(name: user))
        } else if let uidNum = UInt32(uid), !uid.isEmpty {
            entities.append(.user(uid: uidNum))
        }

        let attrs = try? FileManager.default.attributesOfItem(atPath: sourceURL.path)
        let mtime = (attrs?[.modificationDate] as? Date) ?? Date(timeIntervalSince1970: 0)

        return EventEnvelope(
            eventTime: mtime,
            collectedAt: Date(),
            source: .parser,
            sourcePlugin: "BTM",
            eventType: "persistence.btm_item",
            entityRefs: entities,
            fields: fields,
            rawRef: ArtifactRoot.pathKey(sourceURL),
            confidence: 0.95
        )
    }

    /// Decode type bitfield into human labels (mac_apt 2025 research).
    private func typeLabels(_ raw: Int) -> [String] {
        var labels: [String] = []
        if raw & 0x1 != 0 { labels.append("user_item") }
        if raw & 0x2 != 0 { labels.append("app") }
        if raw & 0x4 != 0 { labels.append("login_item") }
        if raw & 0x8 != 0 { labels.append("agent") }
        if raw & 0x10 != 0 { labels.append("daemon") }
        if raw & 0x20 != 0 { labels.append("developer") }
        if raw & 0x40 != 0 { labels.append("managed") }
        if raw & 0x80 != 0 { labels.append("curated") }
        if labels.isEmpty && raw != 0 {
            labels.append("type_\(raw)")
        }
        return labels
    }

    private func dispositionLabels(_ raw: Int) -> [String] {
        var labels: [String] = []
        if raw & 0x1 != 0 { labels.append("Enabled") }
        if raw & 0x2 != 0 { labels.append("Allowed") }
        if raw & 0x4 != 0 { labels.append("Hidden") }
        if raw & 0x8 != 0 { labels.append("Notified") }
        if labels.isEmpty && raw != 0 {
            labels.append("disp_\(raw)")
        }
        return labels
    }

    private func intValue(_ any: Any?) -> Int? {
        if let i = any as? Int { return i }
        if let n = any as? NSNumber { return n.intValue }
        if let s = any as? String, let i = Int(s) { return i }
        return nil
    }
}
