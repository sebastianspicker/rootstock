import Foundation
import RootstockBlueCore

/// Cron, at(1) tabs, and periodic jobs - classic Unix persistence on macOS.
///
/// Does not own LaunchAgents/LaunchDaemons (see AutostartParser).
public struct CronParser: ArtifactParser {
    public let manifest = PluginManifest(
        id: "CRON",
        tier: .tier1,
        description: "crontab, at tabs, and periodic jobs"
    )

    public init() {}

    public func parse(source: ImageSource) throws -> [EventEnvelope] {
        let root = ArtifactRoot(source: source)
        var events: [EventEnvelope] = []
        var seen = PathDeduper()

        // System crontab
        for rel in ["etc/crontab", "private/etc/crontab"] {
            if let url = root.firstExisting([rel]) {
                if seen.insert(url) {
                    events.append(contentsOf: parseCrontab(at: url, kind: "cron", defaultUser: "root"))
                }
            }
        }

        // cron.d drop-ins + user crontabs under etc/cron.d or Users/*/.cron
        for url in root.enumerate(matching: { url in
            let path = url.path
            let name = url.lastPathComponent
            if path.contains("/cron.d/") || path.hasSuffix("/cron.d/\(name)") {
                return true
            }
            if name == ".cron" || path.hasSuffix("/.cron") {
                return true
            }
            // Users/* /var/cron/tabs style exported as plain text
            if path.contains("/cron/tabs/") || path.contains("/at/tabs/") {
                return true
            }
            return false
        }) {
            if !seen.insert(url) { continue }
            let isAt = url.path.contains("/at/tabs/")
            let user = isAt ? url.lastPathComponent : cronUser(from: url)
            events.append(contentsOf: parseCrontab(
                at: url,
                kind: isAt ? "at" : "cron",
                defaultUser: user ?? "root"
            ))
        }

        // Explicit at tabs paths
        for base in ["private/var/at/tabs", "var/at/tabs"] {
            let dir = root.file(base)
            guard let items = try? FileManager.default.contentsOfDirectory(
                at: dir,
                includingPropertiesForKeys: nil,
                options: [.skipsHiddenFiles]
            ) else { continue }
            for item in items {
                if !seen.insert(item) { continue }
                events.append(contentsOf: parseCrontab(
                    at: item,
                    kind: "at",
                    defaultUser: item.lastPathComponent
                ))
            }
        }

        // periodic scripts: daily/weekly/monthly under private/etc/periodic or etc/periodic
        for url in root.enumerate(matching: { url in
            let path = url.path
            return path.contains("/periodic/")
                && !url.hasDirectoryPath
                && !url.lastPathComponent.hasPrefix(".")
        }) {
            if !seen.insert(url) { continue }
            if let event = parsePeriodic(at: url) {
                events.append(event)
            }
        }

        return events
    }

    // MARK: - crontab / at

    private func parseCrontab(at url: URL, kind: String, defaultUser: String) -> [EventEnvelope] {
        guard let text = try? String(contentsOf: url, encoding: .utf8) else { return [] }
        var events: [EventEnvelope] = []
        var lineNo = 0

        for rawLine in text.split(omittingEmptySubsequences: false, whereSeparator: \.isNewline) {
            lineNo += 1
            let line = String(rawLine).trimmingCharacters(in: .whitespaces)
            if line.isEmpty || line.hasPrefix("#") { continue }
            // env assignments like SHELL=/bin/bash - skip
            if line.contains("=") && !line.contains(" ") {
                // SHELL=/bin/sh style
                let parts = line.split(separator: "=", maxSplits: 1)
                if parts.count == 2, !parts[0].contains("/") {
                    continue
                }
            }
            if line.hasPrefix("SHELL=") || line.hasPrefix("PATH=") || line.hasPrefix("MAILTO=")
                || line.hasPrefix("HOME=") || line.hasPrefix("LOGNAME=") {
                continue
            }

            if kind == "at" {
                // at tabs are often free-form shell; treat whole line as command
                if let event = makePersistenceEvent(
                    kind: "at",
                    schedule: "at",
                    command: line,
                    user: defaultUser,
                    sourceURL: url,
                    lineNo: lineNo
                ) {
                    events.append(event)
                }
                continue
            }

            if let parsed = parseCronLine(line, defaultUser: defaultUser) {
                if let event = makePersistenceEvent(
                    kind: "cron",
                    schedule: parsed.schedule,
                    command: parsed.command,
                    user: parsed.user,
                    sourceURL: url,
                    lineNo: lineNo
                ) {
                    events.append(event)
                }
            }
        }
        return events
    }

    /// Vixie cron special schedule strings (must be handled before 5-field path).
    private static let vixieSpecials: Set<String> = [
        "@reboot", "@yearly", "@annually", "@monthly",
        "@weekly", "@daily", "@midnight", "@hourly",
    ]

    /// Parse classic crontab line: Vixie specials (`@reboot`…), user crontab (5 fields + cmd),
    /// or system/cron.d (6: schedule + user + cmd).
    private func parseCronLine(_ line: String, defaultUser: String) -> (schedule: String, user: String, command: String)? {
        let tokens = tokenizeCron(line)
        guard !tokens.isEmpty else { return nil }

        // Vixie specials: @reboot [user] command...  OR  @daily command...
        let head = tokens[0].lowercased()
        if head.hasPrefix("@") {
            guard Self.vixieSpecials.contains(head) else { return nil }
            let rest = Array(tokens.dropFirst())
            guard !rest.isEmpty else { return nil }
            let first = rest[0]
            let looksLikeUser = !first.contains("/") && !first.contains("$") && !first.contains("=")
                && first.rangeOfCharacter(from: .letters) != nil
                && first.count < 32
            if looksLikeUser && rest.count >= 2 {
                return (head, first, rest.dropFirst().joined(separator: " "))
            }
            return (head, defaultUser, rest.joined(separator: " "))
        }

        // Minimum classic: m h dom mon dow cmd  (6 tokens)
        guard tokens.count >= 6 else { return nil }

        // Heuristic: if 6th token looks like a username (no slash, no $), treat as system crontab.
        let scheduleFields = Array(tokens.prefix(5))
        let rest = Array(tokens.dropFirst(5))
        guard !rest.isEmpty else { return nil }

        let schedule = scheduleFields.joined(separator: " ")
        let sixth = rest[0]
        let looksLikeUser = !sixth.contains("/") && !sixth.contains("$") && !sixth.contains("=")
            && sixth.rangeOfCharacter(from: .letters) != nil
            && sixth.count < 32

        if looksLikeUser && rest.count >= 2 {
            let user = sixth
            let command = rest.dropFirst().joined(separator: " ")
            return (schedule, user, command)
        }

        let command = rest.joined(separator: " ")
        return (schedule, defaultUser, command)
    }

    private func tokenizeCron(_ line: String) -> [String] {
        // Split on whitespace but keep command intact by joining after schedule fields.
        line.split(whereSeparator: { $0 == " " || $0 == "\t" }).map(String.init)
    }

    // MARK: - periodic

    private func parsePeriodic(at url: URL) -> EventEnvelope? {
        let path = ArtifactRoot.pathKey(url)
        let schedule: String
        if path.contains("/daily/") {
            schedule = "daily"
        } else if path.contains("/weekly/") {
            schedule = "weekly"
        } else if path.contains("/monthly/") {
            schedule = "monthly"
        } else {
            schedule = "periodic"
        }

        // Prefer shebang / first non-comment line as command summary; fall back to path.
        var command = path
        if let text = try? String(contentsOf: url, encoding: .utf8) {
            for raw in text.split(whereSeparator: \.isNewline) {
                let line = String(raw).trimmingCharacters(in: .whitespaces)
                if line.isEmpty || line.hasPrefix("#") { continue }
                command = line
                break
            }
        }

        return makePersistenceEvent(
            kind: "periodic",
            schedule: schedule,
            command: command,
            user: "root",
            sourceURL: url,
            lineNo: 0
        )
    }

    // MARK: - event

    private func makePersistenceEvent(
        kind: String,
        schedule: String,
        command: String,
        user: String,
        sourceURL: URL,
        lineNo: Int
    ) -> EventEnvelope? {
        let trimmed = command.trimmingCharacters(in: .whitespaces)
        guard !trimmed.isEmpty else { return nil }

        var fields: [String: String] = [
            "persistence.kind": kind,
            "persistence.schedule": schedule,
            "persistence.command": trimmed,
            "persistence.path": ArtifactRoot.pathKey(sourceURL),
            FieldTaxonomy.filePath: ArtifactRoot.pathKey(sourceURL),
            FieldTaxonomy.eventType: "persistence.item",
            FieldTaxonomy.userName: user,
        ]
        if lineNo > 0 {
            fields["persistence.line"] = String(lineNo)
        }
        // First token as process path when absolute
        let first = trimmed.split(whereSeparator: { $0 == " " || $0 == "\t" }).first.map(String.init) ?? ""
        if first.hasPrefix("/") {
            fields[FieldTaxonomy.processPath] = first
            fields["persistence.program"] = first
        }

        var entities: [EntityID] = [
            EntityID(kind: .persistence, value: "\(kind)|\(schedule)|\(trimmed)"),
            .file(path: ArtifactRoot.pathKey(sourceURL)),
            .user(name: user),
        ]
        if first.hasPrefix("/") {
            entities.append(.file(path: first))
        }

        return EventEnvelope(
            eventTime: fileMTime(sourceURL),
            collectedAt: Date(),
            source: .parser,
            sourcePlugin: "CRON",
            eventType: "persistence.item",
            entityRefs: entities,
            fields: fields,
            rawRef: ArtifactRoot.pathKey(sourceURL),
            confidence: kind == "periodic" ? 0.92 : 0.96
        )
    }

    private func cronUser(from url: URL) -> String? {
        if let user = inferUser(from: url) { return user }
        // cron.d filename sometimes is username
        let base = url.lastPathComponent
        if base != "crontab" && !base.contains(".") && base.rangeOfCharacter(from: .letters) != nil {
            return base
        }
        return nil
    }

    private func fileMTime(_ url: URL) -> Date {
        let attrs = try? FileManager.default.attributesOfItem(atPath: url.path)
        return (attrs?[.modificationDate] as? Date) ?? Date(timeIntervalSince1970: 0)
    }
}
