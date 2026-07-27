/// Offline forensic parser: AutostartParser - fixture-backed IR events (no secret export).
import Foundation
import RootstockBlueCore
import RootstockMacFacts

public struct AutostartParser: ArtifactParser {
    public let manifest = PluginManifest(
        id: "AUTOSTART",
        tier: .tier1,
        description: "LaunchAgents, LaunchDaemons, and login-item style plists"
    )

    public init() {}

    public func parse(source: ImageSource) throws -> [EventEnvelope] {
        let root = ArtifactRoot(source: source)
        let plists = root.enumerate { url in
            guard url.pathExtension == "plist" else { return false }
            let path = url.path
            return path.contains("LaunchAgents")
                || path.contains("LaunchDaemons")
                || path.contains("LaunchItems")
        }

        var events: [EventEnvelope] = []
        for plistURL in plists {
            if let event = parsePlist(at: plistURL) {
                events.append(event)
            }
        }
        return events
    }

    private func parsePlist(at url: URL) -> EventEnvelope? {
        guard let dict = ArtifactIO.plistDict(contentsOf: url) else { return nil }

        // Shared Program / ProgramArguments / RunAtLoad / KeepAlive extraction
        let summary = LaunchdPlistFacts.summarize(path: url.path, dict: dict)
        let label = summary.label ?? url.deletingPathExtension().lastPathComponent
        let program = summary.program
        let args = summary.programArguments
        let runAtLoad = summary.runAtLoad
        let keepAlive = summary.keepAlive

        let kind: String
        if url.path.contains("LaunchDaemons") {
            kind = "launch_daemon"
        } else if url.path.contains("LaunchAgents") {
            kind = "launch_agent"
        } else {
            kind = "launch_item"
        }

        let programPath = program ?? args.first ?? ""
        var fields: [String: String] = [
            "persistence.kind": kind,
            "persistence.label": label,
            "persistence.path": url.path,
            "persistence.program": programPath,
            "persistence.program_arguments": args.joined(separator: " "),
            "persistence.run_at_load": runAtLoad ? "true" : "false",
            "persistence.keep_alive": keepAlive ? "true" : "false",
            "persistence.parser": "LaunchdPlistFacts",
            FieldTaxonomy.filePath: url.path,
            FieldTaxonomy.btmItemPath: url.path,
            FieldTaxonomy.btmItemType: kind,
            FieldTaxonomy.eventType: "persistence.item",
        ]
        if !programPath.isEmpty {
            fields[FieldTaxonomy.processPath] = programPath
        }

        var entities: [EntityID] = [
            EntityID(kind: .persistence, value: "\(kind)|\(label)"),
            .file(path: url.path),
        ]
        if !programPath.isEmpty {
            entities.append(.file(path: programPath))
        }

        let attrs = try? FileManager.default.attributesOfItem(atPath: url.path)
        let mtime = (attrs?[.modificationDate] as? Date) ?? Date(timeIntervalSince1970: 0)

        return EventEnvelope(
            eventTime: mtime,
            collectedAt: Date(),
            source: .parser,
            sourcePlugin: "AUTOSTART",
            eventType: "persistence.item",
            entityRefs: entities,
            fields: fields,
            rawRef: url.path,
            confidence: 0.98
        )
    }
}
