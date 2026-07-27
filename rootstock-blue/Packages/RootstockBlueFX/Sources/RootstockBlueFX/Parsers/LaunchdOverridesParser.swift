import Foundation
import RootstockBlueCore

/// launchd override / disabled job inventory - defense-evasion surface.
///
/// Reads `disabled.plist` and per-user disabled overrides under
/// `/var/db/com.apple.xpc.launchd/`. When security products or IR agents appear
/// as disabled, that is a high-signal blue-team finding (T1562.001).
///
/// Emits normalized `defense.launchd_override` events with team and product
/// heuristics suitable for case custody.
public struct LaunchdOverridesParser: ArtifactParser {
    public let manifest = PluginManifest(
        id: "LAUNCHDOVERRIDES",
        tier: .tier1,
        description: "launchd disabled overrides (defense-evasion inventory)"
    )

    public init() {}

    /// Labels that strongly suggest security / IR tooling when disabled.
    private static let securityLabelHints: [String] = [
        "santa", "falcon", "crowdstrike", "sentinel", "jamf", "osquery",
        "xprotect", "mrt", "carbonblack", "elastic", "defender", "lulu",
        "snitch", "blockblock", "oversight", "knockknock", "endpoint",
        "protect", "security", "malware", "avast", "norton", "mcafee",
    ]

    public func parse(source: ImageSource) throws -> [EventEnvelope] {
        let root = ArtifactRoot(source: source)
        var events: [EventEnvelope] = []
        var seen = PathDeduper()

        // JSON fixture inventory
        for rel in [
            "var/db/com.apple.xpc.launchd/disabled.json",
            "private/var/db/com.apple.xpc.launchd/disabled.json",
            "Library/Preferences/launchd_disabled.json",
        ] {
            if let url = root.firstExisting([rel]),
               let json = ArtifactIO.jsonObject(contentsOf: url),
               seen.insert(url) {
                events.append(contentsOf: parseJSON(json, rawRef: ArtifactRoot.pathKey(url)))
            }
        }

        // Standard disabled.plist paths
        let plistRelatives = [
            "var/db/com.apple.xpc.launchd/disabled.plist",
            "private/var/db/com.apple.xpc.launchd/disabled.plist",
        ]
        for rel in plistRelatives {
            if let url = root.firstExisting([rel]), seen.insert(url) {
                events.append(contentsOf: parseDisabledPlist(at: url))
            }
        }

        // Per-user disabled.<uid>.plist
        for url in root.enumerate(matching: { url in
            let path = url.path
            let name = url.lastPathComponent
            guard path.contains("com.apple.xpc.launchd") || path.contains("/launchd/") else {
                return false
            }
            return name == "disabled.plist"
                || name.hasPrefix("disabled.")
                || name == "overrides.plist"
        }) {
            guard seen.insert(url) else { continue }
            if url.pathExtension == "json" {
                if let json = ArtifactIO.jsonObject(contentsOf: url) {
                    events.append(contentsOf: parseJSON(json, rawRef: ArtifactRoot.pathKey(url)))
                }
            } else {
                events.append(contentsOf: parseDisabledPlist(at: url))
            }
        }

        return events
    }

    private func parseJSON(_ json: Any, rawRef: String) -> [EventEnvelope] {
        var events: [EventEnvelope] = []
        if let dict = json as? [String: Any] {
            // { "disabled": { "label": true } } or flat { "label": true }
            let disabled: [String: Any]
            if let nested = dict["disabled"] as? [String: Any] {
                disabled = nested
            } else if let items = dict["items"] as? [[String: Any]] {
                return items.compactMap { item in
                    let label = stringish(item["label"]) ?? stringish(item["Label"]) ?? ""
                    guard !label.isEmpty else { return nil }
                    let isDisabled = boolish(item["disabled"]) ?? true
                    return makeEvent(
                        label: label,
                        disabled: isDisabled,
                        path: rawRef,
                        domain: stringish(item["domain"]) ?? "system"
                    )
                }
            } else {
                disabled = dict
            }
            for (label, value) in disabled {
                if label == "disabled" || label == "items" { continue }
                let isDisabled = boolish(value) ?? true
                events.append(makeEvent(label: label, disabled: isDisabled, path: rawRef, domain: "system"))
            }
        } else if let arr = json as? [[String: Any]] {
            for item in arr {
                let label = stringish(item["label"]) ?? ""
                guard !label.isEmpty else { continue }
                let isDisabled = boolish(item["disabled"]) ?? true
                events.append(
                    makeEvent(
                        label: label,
                        disabled: isDisabled,
                        path: rawRef,
                        domain: stringish(item["domain"]) ?? "system"
                    )
                )
            }
        }
        return events
    }

    private func parseDisabledPlist(at url: URL) -> [EventEnvelope] {
        guard let data = ArtifactIO.data(contentsOf: url),
              let obj = ArtifactIO.plistObject(from: data)
        else { return [] }
        let pathKey = ArtifactRoot.pathKey(url)
        var events: [EventEnvelope] = []

        if let dict = obj as? [String: Any] {
            for (label, value) in dict {
                let isDisabled = boolish(value) ?? true
                events.append(makeEvent(label: label, disabled: isDisabled, path: pathKey, domain: domainFromPath(url)))
            }
        }
        return events
    }

    private func makeEvent(label: String, disabled: Bool, path: String, domain: String) -> EventEnvelope {
        let lower = label.lowercased()
        let securityRelated = Self.securityLabelHints.contains { lower.contains($0) }
        var fields: [String: String] = [
            "defense.kind": "launchd_override",
            "defense.label": label,
            "defense.disabled": disabled ? "true" : "false",
            "defense.domain": domain,
            "defense.path": path,
            "launchd.label": label,
            "launchd.disabled": disabled ? "true" : "false",
            FieldTaxonomy.filePath: path,
            FieldTaxonomy.eventType: "defense.launchd_override",
            FieldTaxonomy.persistenceLabel: label,
        ]
        if securityRelated {
            fields["defense.security_product_hint"] = "true"
            fields["defense.risk_tags"] = "security_agent_disabled"
        }

        return EventEnvelope(
            eventTime: Date(timeIntervalSince1970: 0),
            collectedAt: Date(),
            source: .parser,
            sourcePlugin: "LAUNCHDOVERRIDES",
            eventType: "defense.launchd_override",
            entityRefs: [
                EntityID(kind: .persistence, value: "launchd_override|\(label)"),
                .file(path: path),
            ],
            fields: fields,
            rawRef: path,
            confidence: securityRelated && disabled ? 0.97 : 0.9
        )
    }

    private func domainFromPath(_ url: URL) -> String {
        let name = url.lastPathComponent
        if name.hasPrefix("disabled."), name != "disabled.plist" {
            return "user"
        }
        return "system"
    }
}
