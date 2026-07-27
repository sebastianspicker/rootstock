/// CollectionPack - Rootstock product source (see package README for product doctrine).
import Foundation
import RootstockBlueCore

public struct CollectionPack: Codable, Sendable {
    public var name: String
    public var description: String
    public var requiresFDA: Bool
    public var requiresES: Bool
    public var artifacts: [String]

    public init(
        name: String,
        description: String,
        requiresFDA: Bool = true,
        requiresES: Bool = false,
        artifacts: [String]
    ) {
        self.name = name
        self.description = description
        self.requiresFDA = requiresFDA
        self.requiresES = requiresES
        self.artifacts = artifacts
    }

    enum CodingKeys: String, CodingKey {
        case name, description, artifacts
        case requiresFDA = "requires_fda"
        case requiresES = "requires_es"
    }
}

public enum CollectionPackLoader {
    public static func load(from url: URL) throws -> CollectionPack {
        let text = try String(contentsOf: url, encoding: .utf8)
        var name = url.deletingPathExtension().lastPathComponent
        var description = ""
        var requiresFDA = true
        var requiresES = false
        var artifacts: [String] = []
        var inArtifacts = false

        for rawLine in text.components(separatedBy: .newlines) {
            let line = rawLine.split(separator: "#", maxSplits: 1).first.map(String.init) ?? rawLine
            let trimmed = line.trimmingCharacters(in: .whitespaces)
            if trimmed.isEmpty { continue }
            if trimmed.hasPrefix("- ") && inArtifacts {
                artifacts.append(String(trimmed.dropFirst(2)).trimmingCharacters(in: CharacterSet(charactersIn: "\"")))
                continue
            }
            guard trimmed.contains(":") else { continue }
            let parts = trimmed.split(separator: ":", maxSplits: 1).map {
                $0.trimmingCharacters(in: .whitespaces)
            }
            let key = parts[0]
            let value = parts.count > 1 ? parts[1].trimmingCharacters(in: CharacterSet(charactersIn: "\"")) : ""
            switch key {
            case "name": name = value; inArtifacts = false
            case "description": description = value; inArtifacts = false
            case "requires_fda": requiresFDA = value.lowercased() != "false"; inArtifacts = false
            case "requires_es": requiresES = value.lowercased() == "true"; inArtifacts = false
            case "artifacts": inArtifacts = true
            default: break
            }
        }

        return CollectionPack(
            name: name,
            description: description,
            requiresFDA: requiresFDA,
            requiresES: requiresES,
            artifacts: artifacts
        )
    }

    public static func loadDirectory(_ dir: URL) throws -> [CollectionPack] {
        let fm = FileManager.default
        guard let items = try? fm.contentsOfDirectory(at: dir, includingPropertiesForKeys: nil) else {
            return []
        }
        return try items
            .filter { $0.pathExtension == "yaml" || $0.pathExtension == "yml" }
            .sorted { $0.lastPathComponent < $1.lastPathComponent }
            .map { try load(from: $0) }
    }
}
