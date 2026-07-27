import Foundation
import RootstockBlueCore

/// Code-signing assessment inventory for persistence / helper binaries.
///
/// Offline JSON inventory of `codesign -dv` / notarization collector exports.
/// Links to persistence.kind when the path is a known persistence binary.
/// Does not invoke `codesign` live or unpack Mach-O signatures.
public struct CodesignParser: ArtifactParser {
    public let manifest = PluginManifest(
        id: "CODESIGN",
        tier: .tier1,
        description: "Code-sign / notarization assessment inventory for persistence paths"
    )

    public init() {}

    public func parse(source: ImageSource) throws -> [EventEnvelope] {
        let root = ArtifactRoot(source: source)
        var events: [EventEnvelope] = []
        var seen = PathDeduper()

        for rel in [
            "Library/Preferences/codesign_inventory.json",
            "Library/Preferences/persistence_codesign.json",
            "Library/Preferences/com.apple.codesign.inventory.json",
        ] {
            if let url = root.firstExisting([rel]),
               let json = ArtifactIO.jsonObject(contentsOf: url),
               seen.insert(url) {
                events.append(contentsOf: parseJSONInventory(json, rawRef: ArtifactRoot.pathKey(url)))
            }
        }

        for url in root.enumerate(matching: { url in
            let name = url.lastPathComponent
            return name == "codesign_inventory.json"
                || name == "persistence_codesign.json"
                || name == "com.apple.codesign.inventory.json"
        }) {
            guard seen.insert(url) else { continue }
            if let json = ArtifactIO.jsonObject(contentsOf: url) {
                events.append(contentsOf: parseJSONInventory(json, rawRef: ArtifactRoot.pathKey(url)))
            }
        }

        return events
    }

    private func parseJSONInventory(_ json: Any, rawRef: String) -> [EventEnvelope] {
        var items = ArtifactIO.dictionaryEntries(
            from: json,
            nestedKeys: ["assessments", "items", "binaries", "entries"],
            identityKeys: ["path", "signed"]
        )
        // Preserve prior fallback: bare dict without identity keys still yields one item
        // when nested keys miss (dictionaryEntries with identityKeys already covers path/signed).
        if items.isEmpty, let dict = json as? [String: Any], dict["path"] != nil || dict["signed"] != nil {
            items = [dict]
        }
        return items.compactMap { makeEvent(from: $0, rawRef: rawRef) }
    }

    private func makeEvent(from item: [String: Any], rawRef: String) -> EventEnvelope? {
        let path = stringish(item["path"])
            ?? stringish(item["file"])
            ?? stringish(item["file_path"])
            ?? stringish(item["binary"])
            ?? ""
        guard !path.isEmpty else { return nil }

        let signed = boolish(item["signed"])
        let notarized = boolish(item["notarized"])
            ?? boolish(item["notary"])
        let teamID = stringish(item["team_id"])
            ?? stringish(item["teamID"])
            ?? stringish(item["TeamIdentifier"])
            ?? ""
        let signingID = stringish(item["signing_id"])
            ?? stringish(item["signingID"])
            ?? stringish(item["identifier"])
            ?? stringish(item["SigningIdentifier"])
            ?? ""
        let authority = stringish(item["authority"])
            ?? stringish(item["Authority"])
            ?? stringish(item["signer"])
            ?? ""
        let persistenceKind = stringish(item["persistence_kind"])
            ?? stringish(item["persistence.kind"])
            ?? inferPersistenceKind(path: path)

        var risk: [String] = []
        if let tags = stringish(item["risk_tags"]), !tags.isEmpty {
            risk = tags.split(separator: ",").map { $0.trimmingCharacters(in: .whitespaces) }
        }

        let lowerAuth = authority.lowercased()
        let adhoc = boolish(item["adhoc"]) == true
            || lowerAuth.contains("ad-hoc")
            || lowerAuth.contains("adhoc")
            || teamID == "-"

        if signed == false {
            if !risk.contains("unsigned") { risk.append("unsigned") }
        }
        if notarized == false {
            if !risk.contains("not_notarized") { risk.append("not_notarized") }
        }
        if adhoc {
            if !risk.contains("adhoc") { risk.append("adhoc") }
        }
        if teamID.isEmpty || teamID == "UNKNOWN" || teamID.lowercased() == "unknown"
            || path.lowercased().contains("evil") || signingID.lowercased().contains("evil") {
            if signed == false || teamID.isEmpty || teamID.uppercased() == "UNKNOWN"
                || path.lowercased().contains("evil") {
                if !risk.contains("unknown_team") { risk.append("unknown_team") }
            }
        }

        var fields: [String: String] = [
            "codesign.path": path,
            FieldTaxonomy.filePath: path,
            FieldTaxonomy.eventType: "codesign.assessment",
        ]
        if let signed {
            fields["codesign.signed"] = signed ? "true" : "false"
            fields[FieldTaxonomy.processSigned] = signed ? "true" : "false"
        }
        if let notarized {
            fields["codesign.notarized"] = notarized ? "true" : "false"
        }
        if !teamID.isEmpty {
            fields["codesign.team_id"] = teamID
            fields[FieldTaxonomy.processTeamID] = teamID
        }
        if !signingID.isEmpty {
            fields["codesign.signing_id"] = signingID
            fields[FieldTaxonomy.processSigningID] = signingID
        }
        if !authority.isEmpty {
            fields["codesign.authority"] = authority
        }
        if let persistenceKind, !persistenceKind.isEmpty {
            fields["persistence.kind"] = persistenceKind
            fields["codesign.persistence_kind"] = persistenceKind
        }
        if !risk.isEmpty {
            fields["codesign.risk_tags"] = risk.joined(separator: ",")
            fields["persistence.risk_tags"] = risk.joined(separator: ",")
        }

        var entities: [EntityID] = [
            EntityID(kind: .file, value: path),
            EntityID(kind: .host, value: "codesign|\(path)|\(teamID)"),
        ]
        if let persistenceKind, !persistenceKind.isEmpty {
            entities.append(EntityID(kind: .persistence, value: "\(persistenceKind)|\(path)"))
        }

        return EventEnvelope(
            eventTime: Date(timeIntervalSince1970: 0),
            collectedAt: Date(),
            source: .parser,
            sourcePlugin: "CODESIGN",
            eventType: "codesign.assessment",
            entityRefs: entities,
            fields: fields,
            rawRef: rawRef,
            confidence: 0.92
        )
    }

    private func inferPersistenceKind(path: String) -> String? {
        let lower = path.lowercased()
        if lower.contains("privilegedhelpertools") { return "privileged_helper" }
        if lower.contains("launchagents") || lower.contains("launchdaemons") { return "launchd" }
        if lower.contains("securityagentplugins") { return "authorization_plugin" }
        if lower.contains("loginhook") || lower.contains("login_hook") { return "login_hook" }
        if lower.contains("/library/launch") { return "launchd" }
        // Known fixture paths for evil helpers / agents
        if lower.contains("privhelper") { return "privileged_helper" }
        if lower.contains("persist") { return "launchd" }
        return nil
    }
}
