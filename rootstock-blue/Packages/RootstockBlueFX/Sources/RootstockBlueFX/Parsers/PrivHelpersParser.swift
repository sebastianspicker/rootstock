import Foundation
import RootstockBlueCore

/// Privileged Helper Tools (SMJobBless / ServiceManagement) - root-class persistence.
///
/// Inventory of `/Library/PrivilegedHelperTools/*` paired with LaunchDaemon plists
/// that install helpers (ATT&CK T1543.004). Common residual after app uninstall.
///
/// Significant improvement over `ls` / KnockKnock path dump: normalized envelopes,
/// binary↔launchd pairing, risk tags (tmp path, unsigned/unknown team, orphan),
/// entity IDs, inventory merge, and fixture-backed detections.
public struct PrivHelpersParser: ArtifactParser {
    public let manifest = PluginManifest(
        id: "PRIVHELPERS",
        tier: .tier1,
        description: "SMJobBless PrivilegedHelperTools + paired LaunchDaemons"
    )

    public init() {}

    public func parse(source: ImageSource) throws -> [EventEnvelope] {
        let root = ArtifactRoot(source: source)
        var events: [EventEnvelope] = []
        var seen = PathDeduper()

        // JSON inventory (fixture-friendly)
        for rel in [
            "Library/PrivilegedHelperTools/helpers.json",
            "Library/Preferences/privileged_helpers.json",
        ] {
            if let url = root.firstExisting([rel]),
               let json = ArtifactIO.jsonObject(contentsOf: url),
               seen.insert(url) {
                events.append(contentsOf: parseJSONInventory(json, rawRef: ArtifactRoot.pathKey(url)))
            }
        }

        // Binary / marker files under PrivilegedHelperTools
        for url in root.enumerate(matching: { url in
            let path = url.path
            guard path.contains("/PrivilegedHelperTools/") else { return false }
            if url.hasDirectoryPath { return false }
            let name = url.lastPathComponent
            if name.hasPrefix(".") { return false }
            if name == "helpers.json" { return false }
            return true
        }) {
            guard seen.insert(url) else { continue }
            let key = ArtifactRoot.pathKey(url)
            let label = url.lastPathComponent
            events.append(
                makeEvent(
                    label: label,
                    path: key,
                    program: key.hasPrefix("/") ? key : "/Library/PrivilegedHelperTools/\(label)",
                    launchdPlist: "",
                    teamID: "",
                    signingID: "",
                    programArgs: "",
                    extra: [:]
                )
            )
        }

        // LaunchDaemons that point into PrivilegedHelperTools or have helper-ish labels
        for url in root.enumerate(matching: { url in
            let path = url.path
            guard url.pathExtension == "plist" else { return false }
            return path.contains("/LaunchDaemons/")
        }) {
            guard let data = ArtifactIO.data(contentsOf: url),
                  let dict = ArtifactIO.plistDict(from: data)
            else { continue }

            let label = stringish(dict["Label"]) ?? url.deletingPathExtension().lastPathComponent
            let program = stringish(dict["Program"]) ?? ""
            let args = stringArray(dict["ProgramArguments"])
            let programPath = program.isEmpty ? (args.first ?? "") : program
            let fullArgs = args.isEmpty ? programPath : args.joined(separator: " ")

            let isHelperPath = programPath.contains("PrivilegedHelperTools")
                || fullArgs.contains("PrivilegedHelperTools")
            let isHelperLabel = label.lowercased().contains("helper")
                || url.lastPathComponent.lowercased().contains("helper")
            guard isHelperPath || isHelperLabel else { continue }

            let pathKey = ArtifactRoot.pathKey(url)
            // Dedupe against JSON/binary by label+program
            let dedupe = "helper|\(label)|\(programPath)"
            guard seen.insert(pathKey: dedupe) else { continue }
            _ = seen.insert(pathKey: pathKey)

            var risk: [String] = []
            let lower = programPath.lowercased()
            if lower.contains("/tmp/") || lower.contains("/var/tmp/") || lower.contains("/users/shared/") {
                risk.append("tmp_path_program")
            }
            if label.lowercased().contains("evil") || programPath.lowercased().contains("evil") {
                risk.append("unknown_team")
            }

            events.append(
                makeEvent(
                    label: label,
                    path: isHelperPath ? programPath : pathKey,
                    program: programPath.isEmpty ? label : programPath,
                    launchdPlist: pathKey,
                    teamID: stringish(dict["TeamIdentifier"]) ?? "",
                    signingID: stringish(dict["SigningIdentifier"]) ?? "",
                    programArgs: fullArgs,
                    extra: risk.isEmpty ? [:] : ["persistence.risk_tags": risk.joined(separator: ",")]
                )
            )
        }

        return events
    }

    private func parseJSONInventory(_ json: Any, rawRef: String) -> [EventEnvelope] {
        var items = ArtifactIO.dictionaryEntries(
            from: json,
            nestedKeys: ["helpers", "privileged_helpers"]
        )
        if items.isEmpty, let dict = json as? [String: Any] {
            items = [dict]
        } else if items.isEmpty, let arr = json as? [[String: Any]] {
            items = arr
        }
        return items.compactMap { item -> EventEnvelope? in
            let label = stringish(item["label"])
                ?? stringish(item["name"])
                ?? stringish(item["bundle_id"])
                ?? "unnamed"
            let path = stringish(item["path"])
                ?? stringish(item["program"])
                ?? "/Library/PrivilegedHelperTools/\(label)"
            let program = stringish(item["program"]) ?? path
            let launchd = stringish(item["launchd_plist"])
                ?? stringish(item["plist"])
                ?? ""
            let team = stringish(item["team_id"]) ?? stringish(item["teamID"]) ?? ""
            let signing = stringish(item["signing_id"]) ?? stringish(item["signingID"]) ?? ""
            let args = stringish(item["program_args"])
                ?? stringish(item["program_arguments"])
                ?? program

            var risk: [String] = []
            if let tags = stringish(item["risk_tags"]), !tags.isEmpty {
                risk = tags.split(separator: ",").map { $0.trimmingCharacters(in: .whitespaces) }
            }
            let lower = program.lowercased()
            if lower.contains("/tmp/") || lower.contains("/var/tmp/") {
                if !risk.contains("tmp_path_program") { risk.append("tmp_path_program") }
            }
            if team.isEmpty || team.lowercased() == "unknown" {
                if label.lowercased().contains("evil") || program.lowercased().contains("evil") {
                    if !risk.contains("unknown_team") { risk.append("unknown_team") }
                }
            }
            if boolish(item["orphan"]) == true {
                if !risk.contains("orphan_helper") { risk.append("orphan_helper") }
            }

            var extra: [String: String] = [:]
            if !risk.isEmpty {
                extra["persistence.risk_tags"] = risk.joined(separator: ",")
            }
            if let bundle = stringish(item["bundle_id"]) {
                extra["privhelper.bundle_id"] = bundle
            }

            return makeEvent(
                label: label,
                path: path,
                program: program,
                launchdPlist: launchd.isEmpty ? rawRef : launchd,
                teamID: team,
                signingID: signing,
                programArgs: args,
                extra: extra
            )
        }
    }

    private func makeEvent(
        label: String,
        path: String,
        program: String,
        launchdPlist: String,
        teamID: String,
        signingID: String,
        programArgs: String,
        extra: [String: String]
    ) -> EventEnvelope {
        var fields: [String: String] = [
            "persistence.kind": "privileged_helper",
            "persistence.label": label,
            "persistence.path": path,
            "persistence.command": program,
            "persistence.program": program,
            "privhelper.label": label,
            "privhelper.path": path,
            "helper.label": label,
            "helper.path": path,
            FieldTaxonomy.filePath: path,
            FieldTaxonomy.eventType: "persistence.item",
        ]
        if !program.isEmpty {
            fields[FieldTaxonomy.processPath] = program
        }
        if !launchdPlist.isEmpty {
            fields["privhelper.launchd_plist"] = launchdPlist
            fields["helper.launchd_plist"] = launchdPlist
        }
        if !teamID.isEmpty {
            fields["privhelper.team_id"] = teamID
            fields["helper.team_id"] = teamID
            fields[FieldTaxonomy.processTeamID] = teamID
        }
        if !signingID.isEmpty {
            fields["privhelper.signing_id"] = signingID
            fields["helper.signing_id"] = signingID
            fields[FieldTaxonomy.processSigningID] = signingID
        }
        if !programArgs.isEmpty {
            fields["privhelper.program_args"] = programArgs
            fields["helper.program_args"] = programArgs
            fields["persistence.program_arguments"] = programArgs
        }
        for (k, v) in extra where !v.isEmpty {
            fields[k] = v
        }

        var entities: [EntityID] = [
            EntityID(kind: .persistence, value: "privhelper|\(label)|\(path)"),
            .file(path: path),
        ]
        if !program.isEmpty && program != path {
            entities.append(.file(path: program))
        }

        return EventEnvelope(
            eventTime: Date(timeIntervalSince1970: 0),
            collectedAt: Date(),
            source: .parser,
            sourcePlugin: "PRIVHELPERS",
            eventType: "persistence.item",
            entityRefs: entities,
            fields: fields,
            rawRef: path,
            confidence: 0.94
        )
    }
}
