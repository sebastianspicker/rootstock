import Foundation
import RootstockBlueCore
import RootstockBlueCase
import RootstockMacFacts

#if canImport(Darwin)
import Darwin
#endif

/// Defensive host IR posture enumeration - sibling DNA from MacEnumKit
/// protections/host collectors, inverted to **defensive case I/O**: emits
/// normalized `EventEnvelope`s with entity refs into `.rsbcase`.
///
/// Live SIP/Gatekeeper/FileVault parsing uses `HostPostureProbes` (RootstockMacFacts).
/// Offline evidence-tree mode never requires live probes.
public enum HostIRPosture {
    /// Catalog of security products (path presence only - no process storm).
    public static let securityProductCatalog: [(name: String, path: String)] = [
        ("CrowdStrike Falcon", "/Library/CS/falconctl"),
        ("CrowdStrike Falcon", "/Applications/Falcon.app"),
        ("Santa", "/Applications/Santa.app"),
        ("Santa", "/usr/local/bin/santactl"),
        ("osquery", "/usr/local/bin/osqueryd"),
        ("osquery", "/opt/osquery/bin/osqueryd"),
        ("Microsoft Defender", "/Applications/Microsoft Defender.app"),
        ("Jamf Protect", "/Library/Application Support/JamfProtect"),
        ("Jamf", "/usr/local/bin/jamf"),
        ("Elastic Endpoint", "/Library/Elastic/Endpoint"),
        ("LuLu", "/Applications/LuLu.app"),
        ("Little Snitch", "/Applications/Little Snitch.app"),
        ("Carbon Black", "/Applications/VMware Carbon Black Cloud.app"),
        ("SentinelOne", "/Library/Sentinel/sentinel-agent.bundle"),
    ]

    /// Enumerate posture from an offline artifact tree (fixture / image root).
    public static func enumerateOffline(source: ImageSource) throws -> [EventEnvelope] {
        let root = ArtifactRoot(source: source)
        var events: [EventEnvelope] = []

        // Host identity from BASICINFO-shaped paths (entity-linked)
        if let sysURL = root.firstExisting(["System/Library/CoreServices/SystemVersion.plist"]),
           let dict = ArtifactIO.plistDict(contentsOf: sysURL) {
            let version = (dict["ProductVersion"] as? String) ?? ""
            let build = (dict["ProductBuildVersion"] as? String) ?? ""
            let product = (dict["ProductName"] as? String) ?? "macOS"
            events.append(
                EventEnvelope(
                    eventTime: Date(),
                    collectedAt: Date(),
                    source: .collect,
                    sourcePlugin: "IRPOSTURE",
                    eventType: "ir.posture.host",
                    entityRefs: [EntityID(kind: .host, value: "os=\(product)|\(version)|\(build)")],
                    fields: [
                        "ir.mode": "offline",
                        "host.product_name": product,
                        "host.os_version": version,
                        "host.os_build": build,
                        FieldTaxonomy.eventType: "ir.posture.host",
                    ],
                    rawRef: ArtifactRoot.pathKey(sysURL),
                    confidence: 0.98
                )
            )
        }

        // Security products under the artifact root (relative to root)
        var seenProducts = Set<String>()
        for (name, absPath) in securityProductCatalog {
            let relative = absPath.hasPrefix("/") ? String(absPath.dropFirst()) : absPath
            let candidate = root.file(relative)
            if FileManager.default.fileExists(atPath: candidate.path) {
                if seenProducts.insert(name).inserted {
                    events.append(securityProductEvent(
                        name: name,
                        path: candidate.path,
                        mode: "offline"
                    ))
                }
            }
        }

        // Prefer synthetic security_posture.json for fixture reliability; also honor real path probes.
        events.append(contentsOf: offlineSecurityPostureJSON(root: root))
        events.append(contentsOf: offlineFileVaultMarkers(root: root))
        events.append(contentsOf: offlineFirewallALF(root: root))
        events.append(contentsOf: offlineXProtectMRT(root: root))
        events.append(contentsOf: offlineFDAHint(root: root))
        events.append(contentsOf: offlineSystemExtensions(root: root))
        events.append(contentsOf: offlineRemoteAccessSignals(root: root))
        events.append(contentsOf: offlineGatekeeperAssessments(root: root))
        // Wave-4 access / account / update surfaces (path probes when JSON incomplete)
        events.append(contentsOf: offlineAccountAndLoginwindow(root: root))
        events.append(contentsOf: offlineFileSharingMarkers(root: root))
        events.append(contentsOf: offlineSoftwareUpdateMarkers(root: root))
        events.append(contentsOf: offlineLockdownModeMarkers(root: root))
        // Wave-5: ARD AllLocalUsers depth
        events.append(contentsOf: offlineARDMarkers(root: root))

        // Offline protection heuristics from prefs if present
        if root.exists("Library/Preferences/com.apple.security.plist")
            || root.exists("Library/Preferences/com.apple.systempolicy.plist") {
            events.append(
                EventEnvelope(
                    eventTime: Date(),
                    collectedAt: Date(),
                    source: .collect,
                    sourcePlugin: "IRPOSTURE",
                    eventType: "ir.posture.protection",
                    entityRefs: [EntityID(kind: .host, value: "protections=prefs_present")],
                    fields: [
                        "ir.mode": "offline",
                        "protection.name": "Gatekeeper",
                        "protection.enabled": "unknown",
                        "protection.gatekeeper_prefs": "present",
                        "protection.note": "Offline prefs marker only; live csrutil/spctl not run",
                        FieldTaxonomy.eventType: "ir.posture.protection",
                    ],
                    confidence: 0.6
                )
            )
        }

        if events.isEmpty {
            // Always emit a posture scan record so case gains a queryable artifact
            events.append(
                EventEnvelope(
                    eventTime: Date(),
                    collectedAt: Date(),
                    source: .collect,
                    sourcePlugin: "IRPOSTURE",
                    eventType: "ir.posture.scan",
                    entityRefs: [EntityID(kind: .host, value: "scan=offline")],
                    fields: [
                        "ir.mode": "offline",
                        "ir.products_found": "0",
                        "ir.note": "No SystemVersion or known security products under artifact root",
                        FieldTaxonomy.eventType: "ir.posture.scan",
                    ],
                    confidence: 0.7
                )
            )
        }

        return events
    }

    /// Live host posture (ProcessInfo + path catalog). Optional allowlisted status probes.
    /// Does not enable AUTH/block. Honest about probe failures.
    public static func enumerateLive(runStatusProbes: Bool = true) -> [EventEnvelope] {
        var events: [EventEnvelope] = []
        let info = ProcessInfo.processInfo
        let os = info.operatingSystemVersion
        let osVersion = "\(os.majorVersion).\(os.minorVersion).\(os.patchVersion)"
        let hostname = ProcessInfo.processInfo.hostName
        let username = NSUserName()
        #if arch(arm64)
        let arch = "arm64"
        #elseif arch(x86_64)
        let arch = "x86_64"
        #else
        let arch = "unknown"
        #endif

        events.append(
            EventEnvelope(
                eventTime: Date(),
                collectedAt: Date(),
                source: .collect,
                sourcePlugin: "IRPOSTURE",
                eventType: "ir.posture.host",
                entityRefs: [
                    EntityID(kind: .host, value: "name=\(hostname)"),
                    .user(name: username),
                ],
                fields: [
                    "ir.mode": "live",
                    "host.hostname": hostname,
                    "host.os_version": osVersion,
                    "host.arch": arch,
                    "host.username": username,
                    "host.uptime_seconds": String(Int(info.systemUptime)),
                    FieldTaxonomy.userName: username,
                    FieldTaxonomy.eventType: "ir.posture.host",
                ],
                confidence: 0.99
            )
        )

        // Security products on live filesystem
        var seen = Set<String>()
        for (name, path) in securityProductCatalog {
            if FileManager.default.fileExists(atPath: path), seen.insert(name).inserted {
                events.append(securityProductEvent(name: name, path: path, mode: "live"))
            }
        }

        if runStatusProbes {
            events.append(contentsOf: protectionProbeEvents())
        }

        return events
    }

    /// Write posture events into a case (JSONL + timeline + custody + hashes).
    @discardableResult
    public static func writeToCase(
        _ events: [EventEnvelope],
        package: CasePackage,
        actor: String = NSUserName(),
        mode: String
    ) throws -> Int {
        for event in events {
            try package.appendEventJSONL(event, stream: "es")
            try package.insertTimelineEvent(event)
        }
        try package.appendCustody(
            CustodyEvent(
                actor: actor,
                action: "ir_posture",
                detail: "IR posture (\(mode)) wrote \(events.count) events plugins=IRPOSTURE"
            )
        )
        try package.updateHashes()
        return events.count
    }

    // MARK: - Offline protection helpers

    private static func offlineSecurityPostureJSON(root: ArtifactRoot) -> [EventEnvelope] {
        guard let url = root.firstExisting(["Library/Preferences/security_posture.json"]),
              let json = ArtifactIO.jsonDict(contentsOf: url)
        else { return [] }

        var events: [EventEnvelope] = []
        let rawRef = ArtifactRoot.pathKey(url)

        if let fv = boolish(json["filevault_enabled"]) {
            events.append(protectionEvent(
                name: "FileVault",
                enabled: fv ? "true" : "false",
                mode: "offline",
                extra: [
                    "protection.source": "security_posture.json",
                    "protection.note": "Offline synthetic posture JSON (fixture-friendly)",
                ],
                rawRef: rawRef,
                confidence: 0.85
            ))
        }

        if let fw = boolish(json["firewall_enabled"]) {
            events.append(protectionEvent(
                name: "Firewall",
                enabled: fw ? "true" : "false",
                mode: "offline",
                extra: [
                    "protection.source": "security_posture.json",
                    "protection.note": "Offline synthetic posture JSON (fixture-friendly)",
                ],
                rawRef: rawRef,
                confidence: 0.85
            ))
        }

        if let sip = json["sip_status"] as? String {
            let enabled = sip.lowercased().contains("enabled") && !sip.lowercased().contains("disabled")
                ? "true"
                : (sip.lowercased().contains("disabled") ? "false" : "unknown")
            events.append(protectionEvent(
                name: "SIP",
                enabled: enabled,
                mode: "offline",
                extra: [
                    "protection.raw": sip,
                    "protection.source": "security_posture.json",
                    "protection.note": "Offline SIP status from posture JSON; live csrutil not run",
                ],
                rawRef: rawRef,
                confidence: enabled == "unknown" ? 0.5 : 0.8
            ))
        }

        if let gk = json["gatekeeper_status"] as? String {
            let enabled = gk.lowercased().contains("enabled") && !gk.lowercased().contains("disabled")
                ? "true"
                : (gk.lowercased().contains("disabled") ? "false" : "unknown")
            events.append(protectionEvent(
                name: "Gatekeeper",
                enabled: enabled,
                mode: "offline",
                extra: [
                    "protection.raw": gk,
                    "protection.source": "security_posture.json",
                    "protection.note": "Offline Gatekeeper status from posture JSON; live spctl not run",
                ],
                rawRef: rawRef,
                confidence: enabled == "unknown" ? 0.5 : 0.8
            ))
        }

        if let xp = stringish(json["xprotect_version"]), !xp.isEmpty {
            events.append(
                EventEnvelope(
                    eventTime: Date(),
                    collectedAt: Date(),
                    source: .collect,
                    sourcePlugin: "IRPOSTURE",
                    eventType: "ir.posture.protection",
                    entityRefs: [EntityID(kind: .host, value: "protection=xprotect")],
                    fields: [
                        "ir.mode": "offline",
                        "protection.name": "XProtect",
                        "protection.enabled": "present",
                        "protection.xprotect_version": xp,
                        "protection.source": "security_posture.json",
                        FieldTaxonomy.eventType: "ir.posture.protection",
                    ],
                    rawRef: rawRef,
                    confidence: 0.85
                )
            )
        }

        if let mrt = stringish(json["mrt_version"]), !mrt.isEmpty {
            events.append(
                EventEnvelope(
                    eventTime: Date(),
                    collectedAt: Date(),
                    source: .collect,
                    sourcePlugin: "IRPOSTURE",
                    eventType: "ir.posture.protection",
                    entityRefs: [EntityID(kind: .host, value: "protection=mrt")],
                    fields: [
                        "ir.mode": "offline",
                        "protection.name": "MRT",
                        "protection.enabled": "present",
                        "protection.mrt_version": mrt,
                        "protection.source": "security_posture.json",
                        FieldTaxonomy.eventType: "ir.posture.protection",
                    ],
                    rawRef: rawRef,
                    confidence: 0.85
                )
            )
        }

        if let apps = json["fda_apps"] as? [Any] {
            let names = apps.compactMap { stringish($0) }.joined(separator: ",")
            if !names.isEmpty {
                events.append(
                    EventEnvelope(
                        eventTime: Date(),
                        collectedAt: Date(),
                        source: .collect,
                        sourcePlugin: "IRPOSTURE",
                        eventType: "ir.posture.fda_hint",
                        entityRefs: [EntityID(kind: .host, value: "protection=fda")],
                        fields: [
                            "ir.mode": "offline",
                            "protection.name": "FDA",
                            "protection.fda_apps": names,
                            "protection.fda_offline_note":
                                "Offline FDA app list from posture JSON; live TCC/FDA grants need live check",
                            "protection.source": "security_posture.json",
                            FieldTaxonomy.eventType: "ir.posture.fda_hint",
                        ],
                        rawRef: rawRef,
                        confidence: 0.75
                    )
                )
            }
        }

        // System extensions from posture JSON (array of names or objects)
        if let sexts = json["system_extensions"] as? [Any], !sexts.isEmpty {
            for (idx, item) in sexts.enumerated() {
                var name = ""
                var team = ""
                var state = "present"
                if let s = item as? String {
                    name = s
                } else if let d = item as? [String: Any] {
                    name = stringish(d["name"]) ?? stringish(d["identifier"]) ?? "sysext_\(idx)"
                    team = stringish(d["team_id"]) ?? stringish(d["teamID"]) ?? ""
                    state = stringish(d["state"]) ?? "present"
                }
                guard !name.isEmpty else { continue }
                var fields: [String: String] = [
                    "ir.mode": "offline",
                    "protection.name": "SystemExtension",
                    "protection.enabled": "present",
                    "sysext.name": name,
                    "sysext.state": state,
                    "protection.source": "security_posture.json",
                    "protection.note": "Offline system extension from posture JSON; live systemextensionsctl not run",
                    FieldTaxonomy.eventType: "ir.posture.system_extension",
                ]
                if !team.isEmpty { fields["sysext.team_id"] = team }
                events.append(
                    EventEnvelope(
                        eventTime: Date(),
                        collectedAt: Date(),
                        source: .collect,
                        sourcePlugin: "IRPOSTURE",
                        eventType: "ir.posture.system_extension",
                        entityRefs: [
                            EntityID(kind: .host, value: "sysext=\(name)"),
                            EntityID(kind: .persistence, value: "sysext|\(name)"),
                        ],
                        fields: fields,
                        rawRef: rawRef,
                        confidence: 0.8
                    )
                )
            }
        }

        if let ss = boolish(json["screen_sharing_enabled"]) {
            events.append(remoteAccessEvent(
                name: "ScreenSharing",
                enabled: ss ? "true" : "false",
                mode: "offline",
                extra: [
                    "protection.source": "security_posture.json",
                    "protection.note": "Offline Screen Sharing flag from posture JSON",
                ],
                rawRef: rawRef,
                confidence: 0.85
            ))
        }

        if let rm = boolish(json["remote_management_enabled"]) {
            events.append(remoteAccessEvent(
                name: "RemoteManagement",
                enabled: rm ? "true" : "false",
                mode: "offline",
                extra: [
                    "protection.source": "security_posture.json",
                    "protection.note": "Offline Remote Management (ARD) flag from posture JSON",
                ],
                rawRef: rawRef,
                confidence: 0.85
            ))
        }

        if let assessments = json["gatekeeper_assessments"] as? [Any] {
            for (idx, item) in assessments.enumerated() {
                guard let d = item as? [String: Any] else { continue }
                let path = stringish(d["path"]) ?? ""
                let result = stringish(d["result"]) ?? "unknown"
                let override = boolish(d["override"]) ?? false
                events.append(
                    EventEnvelope(
                        eventTime: Date(),
                        collectedAt: Date(),
                        source: .collect,
                        sourcePlugin: "IRPOSTURE",
                        eventType: "ir.posture.gatekeeper_assessment",
                        entityRefs: [
                            EntityID(kind: .host, value: "gatekeeper=assessment"),
                            path.isEmpty ? EntityID(kind: .host, value: "gk=\(idx)") : .file(path: path),
                        ],
                        fields: [
                            "ir.mode": "offline",
                            "protection.name": "Gatekeeper",
                            "gatekeeper.path": path,
                            "gatekeeper.result": result,
                            "gatekeeper.override": override ? "true" : "false",
                            "protection.source": "security_posture.json",
                            FieldTaxonomy.filePath: path,
                            FieldTaxonomy.eventType: "ir.posture.gatekeeper_assessment",
                        ],
                        rawRef: rawRef,
                        confidence: 0.8
                    )
                )
            }
        }

        // Wave-4: Remote Login / sshd service enablement (distinct from SSH keys/config)
        if let rl = boolish(json["remote_login_enabled"]) ?? boolish(json["sshd_enabled"]) {
            events.append(remoteAccessEvent(
                name: "RemoteLogin",
                enabled: rl ? "true" : "false",
                mode: "offline",
                extra: [
                    "remote.service": "ssh",
                    "remote.enabled": rl ? "true" : "false",
                    "protection.source": "security_posture.json",
                    "protection.note": "Offline Remote Login / sshd service flag from posture JSON",
                ],
                rawRef: rawRef,
                confidence: 0.85
            ))
        }

        // Wave-4: Guest account
        if let guest = boolish(json["guest_account_enabled"]) {
            events.append(accountPostureEvent(
                kind: "guest",
                enabled: guest ? "true" : "false",
                extra: [
                    "account.guest_enabled": guest ? "true" : "false",
                    "protection.source": "security_posture.json",
                ],
                rawRef: rawRef
            ))
        }

        // Wave-4: Auto-login
        if let auto = boolish(json["auto_login_enabled"]) {
            var extra: [String: String] = [
                "account.auto_login_enabled": auto ? "true" : "false",
                "protection.source": "security_posture.json",
            ]
            if let user = stringish(json["auto_login_user"]), !user.isEmpty {
                extra["account.auto_login_user"] = user
            }
            events.append(accountPostureEvent(
                kind: "auto_login",
                enabled: auto ? "true" : "false",
                extra: extra,
                rawRef: rawRef
            ))
        }

        // Wave-4: File Sharing
        if let fs = boolish(json["file_sharing_enabled"]) {
            events.append(remoteAccessEvent(
                name: "FileSharing",
                enabled: fs ? "true" : "false",
                mode: "offline",
                extra: [
                    "remote.service": "file_sharing",
                    "protection.source": "security_posture.json",
                    "protection.note": "Offline File Sharing (SMB/AFP) flag from posture JSON",
                ],
                rawRef: rawRef,
                confidence: 0.85
            ))
        }

        // Wave-4: Lockdown Mode
        if let ldm = boolish(json["lockdown_mode_enabled"]) {
            events.append(protectionEvent(
                name: "LockdownMode",
                enabled: ldm ? "true" : "false",
                mode: "offline",
                extra: [
                    "protection.source": "security_posture.json",
                    "protection.note": "Offline Lockdown Mode from posture JSON (LDMGlobalEnabled class)",
                    "lockdown.enabled": ldm ? "true" : "false",
                ],
                rawRef: rawRef,
                confidence: 0.8
            ))
        } else if let ldmStatus = stringish(json["lockdown_mode"]) {
            let enabled: String
            let lower = ldmStatus.lowercased()
            if lower.contains("enabled") || lower == "on" || lower == "1" {
                enabled = "true"
            } else if lower.contains("disabled") || lower == "off" || lower == "0" {
                enabled = "false"
            } else {
                enabled = "unknown"
            }
            events.append(protectionEvent(
                name: "LockdownMode",
                enabled: enabled,
                mode: "offline",
                extra: [
                    "protection.raw": ldmStatus,
                    "protection.source": "security_posture.json",
                    "lockdown.enabled": enabled,
                ],
                rawRef: rawRef,
                confidence: enabled == "unknown" ? 0.5 : 0.8
            ))
        }

        // Wave-4: Software Update honesty
        if let autoCheck = boolish(json["software_update_automatic_check"]) {
            events.append(protectionEvent(
                name: "SoftwareUpdateAuto",
                enabled: autoCheck ? "true" : "false",
                mode: "offline",
                extra: [
                    "su.automatic_check": autoCheck ? "true" : "false",
                    "protection.source": "security_posture.json",
                    "protection.note": "Offline software update automatic check flag",
                ],
                rawRef: rawRef,
                confidence: 0.85
            ))
        }
        if let catalog = stringish(json["software_update_catalog_url"]), !catalog.isEmpty {
            let isApple = catalog.contains("swscan.apple.com") || catalog.contains("swcdn.apple.com")
            events.append(
                EventEnvelope(
                    eventTime: Date(),
                    collectedAt: Date(),
                    source: .collect,
                    sourcePlugin: "IRPOSTURE",
                    eventType: "ir.posture.software_update",
                    entityRefs: [EntityID(kind: .host, value: "su=catalog")],
                    fields: [
                        "ir.mode": "offline",
                        "protection.name": "SoftwareUpdateCatalog",
                        "protection.enabled": isApple ? "apple_default" : "custom",
                        "su.catalog_url": catalog,
                        "su.catalog_non_apple": isApple ? "false" : "true",
                        "protection.source": "security_posture.json",
                        FieldTaxonomy.eventType: "ir.posture.software_update",
                    ],
                    rawRef: rawRef,
                    confidence: 0.9
                )
            )
        }

        return events
    }

    private static func offlineSystemExtensions(root: ArtifactRoot) -> [EventEnvelope] {
        // Skip path heuristic when posture JSON already listed system_extensions
        if let url = root.firstExisting(["Library/Preferences/security_posture.json"]),
           let json = ArtifactIO.jsonDict(contentsOf: url),
           let sexts = json["system_extensions"] as? [Any], !sexts.isEmpty {
            return []
        }

        let markers = [
            "Library/SystemExtensions",
            "Library/SystemExtensions/db.plist",
        ]
        guard let hit = root.firstExisting(markers) else { return [] }

        var events: [EventEnvelope] = []
        // Enumerate bundle-like children when directory
        var isDir: ObjCBool = false
        if FileManager.default.fileExists(atPath: hit.path, isDirectory: &isDir), isDir.boolValue,
           let children = try? FileManager.default.contentsOfDirectory(at: hit, includingPropertiesForKeys: nil) {
            for child in children where !child.lastPathComponent.hasPrefix(".") {
                let name = child.lastPathComponent
                events.append(
                    EventEnvelope(
                        eventTime: Date(),
                        collectedAt: Date(),
                        source: .collect,
                        sourcePlugin: "IRPOSTURE",
                        eventType: "ir.posture.system_extension",
                        entityRefs: [
                            EntityID(kind: .host, value: "sysext=\(name)"),
                            .file(path: ArtifactRoot.pathKey(child)),
                        ],
                        fields: [
                            "ir.mode": "offline",
                            "protection.name": "SystemExtension",
                            "protection.enabled": "present",
                            "sysext.name": name,
                            "sysext.state": "present",
                            "protection.marker_path": ArtifactRoot.pathKey(child),
                            "protection.note": "Offline SystemExtensions path presence; team ID / activation unknown",
                            FieldTaxonomy.filePath: ArtifactRoot.pathKey(child),
                            FieldTaxonomy.eventType: "ir.posture.system_extension",
                        ],
                        rawRef: ArtifactRoot.pathKey(child),
                        confidence: 0.65
                    )
                )
            }
        }
        if events.isEmpty {
            events.append(
                EventEnvelope(
                    eventTime: Date(),
                    collectedAt: Date(),
                    source: .collect,
                    sourcePlugin: "IRPOSTURE",
                    eventType: "ir.posture.system_extension",
                    entityRefs: [
                        EntityID(kind: .host, value: "sysext=marker"),
                        .file(path: ArtifactRoot.pathKey(hit)),
                    ],
                    fields: [
                        "ir.mode": "offline",
                        "protection.name": "SystemExtension",
                        "protection.enabled": "present",
                        "sysext.name": "unknown",
                        "sysext.state": "marker",
                        "protection.marker_path": ArtifactRoot.pathKey(hit),
                        "protection.note": "SystemExtensions tree present offline",
                        FieldTaxonomy.filePath: ArtifactRoot.pathKey(hit),
                        FieldTaxonomy.eventType: "ir.posture.system_extension",
                    ],
                    rawRef: ArtifactRoot.pathKey(hit),
                    confidence: 0.6
                )
            )
        }
        return events
    }

    /// Wave-5: emit explicit `ard.all_local_users` when RemoteManagement plist sets ARD_AllLocalUsers.
    private static func offlineARDMarkers(root: ArtifactRoot) -> [EventEnvelope] {
        let rmPaths = [
            "Library/Preferences/com.apple.RemoteManagement.plist",
            "Library/Preferences/com.apple.RemoteDesktop.plist",
            "Library/Preferences/ard_inventory.json",
        ]
        guard let hit = root.firstExisting(rmPaths) else { return [] }

        var allLocalUsers: Bool?
        var ardEnabled: Bool?

        if hit.pathExtension == "json",
           let json = ArtifactIO.jsonDict(contentsOf: hit) {
            allLocalUsers = boolish(json["ARD_AllLocalUsers"])
                ?? boolish(json["ard_all_local_users"])
                ?? boolish(json["all_local_users"])
            ardEnabled = boolish(json["enabled"]) ?? boolish(json["ard_enabled"])
        } else if let dict = ArtifactIO.plistDict(contentsOf: hit) {
            allLocalUsers = boolish(dict["ARD_AllLocalUsers"])
            ardEnabled = boolish(dict["ScreenSharingEnabled"])
                ?? boolish(dict["LoadRemoteManagementMenuExtra"])
                ?? allLocalUsers
        }

        guard allLocalUsers == true else { return [] }

        var fields: [String: String] = [
            "ir.mode": "offline",
            "protection.name": "RemoteManagement",
            "protection.enabled": (ardEnabled ?? true) ? "true" : "false",
            "remote.service": "ard",
            "remote.enabled": (ardEnabled ?? true) ? "true" : "false",
            "ard.enabled": (ardEnabled ?? true) ? "true" : "false",
            "ard.all_local_users": "true",
            "protection.marker_path": ArtifactRoot.pathKey(hit),
            "protection.source": hit.lastPathComponent,
            "protection.note": "Offline ARD_AllLocalUsers=true from Remote Management prefs",
            FieldTaxonomy.eventType: "ir.posture.remote_access",
        ]
        fields[FieldTaxonomy.remoteService] = "ard"
        fields[FieldTaxonomy.remoteEnabled] = (ardEnabled ?? true) ? "true" : "false"

        return [
            EventEnvelope(
                eventTime: Date(),
                collectedAt: Date(),
                source: .collect,
                sourcePlugin: "IRPOSTURE",
                eventType: "ir.posture.remote_access",
                entityRefs: [EntityID(kind: .host, value: "remote=ard|all_local_users")],
                fields: fields,
                rawRef: ArtifactRoot.pathKey(hit),
                confidence: 0.9
            ),
        ]
    }

    private static func offlineRemoteAccessSignals(root: ArtifactRoot) -> [EventEnvelope] {
        var events: [EventEnvelope] = []
        // Skip when posture JSON already covered these
        let hasPosture = root.exists("Library/Preferences/security_posture.json")

        let rmPaths = [
            "Library/Preferences/com.apple.RemoteManagement.plist",
            "Library/Preferences/com.apple.RemoteDesktop.plist",
        ]
        if let hit = root.firstExisting(rmPaths) {
            var enabled = "unknown"
            if let dict = ArtifactIO.plistDict(contentsOf: hit) {
                if let b = boolish(dict["ScreenSharingEnabled"]) ?? boolish(dict["ARD_AllLocalUsers"]) {
                    enabled = b ? "true" : "false"
                }
            }
            // Always emit when prefs present and posture JSON did not set remote_management
            if !hasPosture || rootPostureMissingBool(root, key: "remote_management_enabled") {
                events.append(remoteAccessEvent(
                    name: "RemoteManagement",
                    enabled: enabled == "unknown" ? "present" : enabled,
                    mode: "offline",
                    extra: [
                        "protection.marker_path": ArtifactRoot.pathKey(hit),
                        "protection.source": "com.apple.RemoteManagement.plist",
                        "protection.note": "Offline Remote Management prefs present",
                    ],
                    rawRef: ArtifactRoot.pathKey(hit),
                    confidence: enabled == "unknown" ? 0.55 : 0.8
                ))
            }
        }

        let ssPaths = [
            "Library/Preferences/com.apple.screensharing.plist",
            "Library/Preferences/com.apple.screensharing.allowlist.plist",
            "Library/Preferences/com.apple.screensharing.agent.launchd.plist",
        ]
        if let hit = root.firstExisting(ssPaths) {
            if !hasPosture || rootPostureMissingBool(root, key: "screen_sharing_enabled") {
                events.append(remoteAccessEvent(
                    name: "ScreenSharing",
                    enabled: "present",
                    mode: "offline",
                    extra: [
                        "protection.marker_path": ArtifactRoot.pathKey(hit),
                        "protection.source": hit.lastPathComponent,
                        "protection.note": "Offline Screen Sharing prefs marker; live status unknown",
                    ],
                    rawRef: ArtifactRoot.pathKey(hit),
                    confidence: 0.55
                ))
            }
        }
        return events
    }

    private static func offlineGatekeeperAssessments(root: ArtifactRoot) -> [EventEnvelope] {
        // Prefer dedicated fixture; skip if already emitted via security_posture.json assessments
        if let posture = root.firstExisting(["Library/Preferences/security_posture.json"]),
           let json = ArtifactIO.jsonDict(contentsOf: posture),
           let assessments = json["gatekeeper_assessments"] as? [Any], !assessments.isEmpty {
            return []
        }

        var events: [EventEnvelope] = []

        // JSON object with assessments array
        if let url = root.firstExisting([
            "Library/Preferences/gatekeeper_assessments.json",
            "Library/Preferences/com.apple.security.assessment.json",
            "Library/Preferences/com.apple.security.gk.json",
            "Library/Logs/Gatekeeper/assessments.json",
        ]),
           let json = ArtifactIO.jsonObject(contentsOf: url) {
            let rawRef = ArtifactRoot.pathKey(url)
            let list: [Any]
            if let dict = json as? [String: Any] {
                list = (dict["assessments"] as? [Any]) ?? []
            } else if let arr = json as? [Any] {
                list = arr
            } else {
                list = []
            }
            for (idx, item) in list.enumerated() {
                guard let d = item as? [String: Any] else { continue }
                let path = stringish(d["path"]) ?? ""
                let result = stringish(d["result"]) ?? "unknown"
                let override = boolish(d["override"]) ?? (result.lowercased().contains("override"))
                events.append(
                    EventEnvelope(
                        eventTime: Date(),
                        collectedAt: Date(),
                        source: .collect,
                        sourcePlugin: "IRPOSTURE",
                        eventType: "ir.posture.gatekeeper_assessment",
                        entityRefs: [
                            EntityID(kind: .host, value: "gatekeeper=assessment"),
                            path.isEmpty ? EntityID(kind: .host, value: "gk=\(idx)") : .file(path: path),
                        ],
                        fields: [
                            "ir.mode": "offline",
                            "protection.name": "Gatekeeper",
                            "gatekeeper.path": path,
                            "gatekeeper.result": result,
                            "gatekeeper.override": override ? "true" : "false",
                            "protection.source": url.lastPathComponent,
                            FieldTaxonomy.filePath: path,
                            FieldTaxonomy.eventType: "ir.posture.gatekeeper_assessment",
                        ],
                        rawRef: rawRef,
                        confidence: 0.8
                    )
                )
            }
        }

        // JSONL assessment export
        if let url = root.firstExisting(["Library/Logs/Gatekeeper/assessments.jsonl"]),
           let text = try? String(contentsOf: url, encoding: .utf8) {
            let rawRef = ArtifactRoot.pathKey(url)
            for (idx, line) in text.components(separatedBy: .newlines).enumerated() {
                let trimmed = line.trimmingCharacters(in: .whitespacesAndNewlines)
                guard !trimmed.isEmpty,
                      let data = trimmed.data(using: .utf8),
                      let d = ArtifactIO.jsonDict(from: data)
                else { continue }
                let path = stringish(d["path"]) ?? ""
                let result = stringish(d["result"]) ?? "unknown"
                let override = boolish(d["override"]) ?? result.lowercased().contains("override")
                events.append(
                    EventEnvelope(
                        eventTime: Date(),
                        collectedAt: Date(),
                        source: .collect,
                        sourcePlugin: "IRPOSTURE",
                        eventType: "ir.posture.gatekeeper_assessment",
                        entityRefs: [
                            EntityID(kind: .host, value: "gatekeeper=assessment"),
                            path.isEmpty ? EntityID(kind: .host, value: "gk=\(idx)") : .file(path: path),
                        ],
                        fields: [
                            "ir.mode": "offline",
                            "protection.name": "Gatekeeper",
                            "gatekeeper.path": path,
                            "gatekeeper.result": result,
                            "gatekeeper.override": override ? "true" : "false",
                            "protection.source": "assessments.jsonl",
                            FieldTaxonomy.filePath: path,
                            FieldTaxonomy.eventType: "ir.posture.gatekeeper_assessment",
                        ],
                        rawRef: rawRef,
                        confidence: 0.8
                    )
                )
            }
        }

        if events.isEmpty {
            return []
        }
        return events
    }

    private static func rootPostureMissingBool(_ root: ArtifactRoot, key: String) -> Bool {
        guard let url = root.firstExisting(["Library/Preferences/security_posture.json"]),
              let json = ArtifactIO.jsonDict(contentsOf: url)
        else { return true }
        return boolish(json[key]) == nil
    }

    /// Wave-4: Guest / auto-login / kcpassword markers from loginwindow + etc/kcpassword.
    private static func offlineAccountAndLoginwindow(root: ArtifactRoot) -> [EventEnvelope] {
        var events: [EventEnvelope] = []
        let hasPosture = root.exists("Library/Preferences/security_posture.json")

        // kcpassword presence only (never dump bytes into events)
        if let kc = root.firstExisting(["etc/kcpassword", "private/etc/kcpassword"]) {
            events.append(accountPostureEvent(
                kind: "auto_login",
                enabled: "true",
                extra: [
                    "account.kcpassword_present": "true",
                    "account.auto_login_enabled": "true",
                    "protection.marker_path": ArtifactRoot.pathKey(kc),
                    "protection.note": "kcpassword present - auto-login credential material at rest (bytes not exported)",
                ],
                rawRef: ArtifactRoot.pathKey(kc)
            ))
        }

        let loginwindowPaths = [
            "Library/Preferences/com.apple.loginwindow.plist",
            "var/root/Library/Preferences/com.apple.loginwindow.plist",
        ]
        guard let url = root.firstExisting(loginwindowPaths) else { return events }
        let rawRef = ArtifactRoot.pathKey(url)
        guard let dict = ArtifactIO.jsonOrPlistDict(contentsOf: url) else { return events }

        if let guest = boolish(dict["GuestEnabled"]), !hasPosture || rootPostureMissingBool(root, key: "guest_account_enabled") {
            events.append(accountPostureEvent(
                kind: "guest",
                enabled: guest ? "true" : "false",
                extra: [
                    "account.guest_enabled": guest ? "true" : "false",
                    "protection.source": "com.apple.loginwindow.plist",
                ],
                rawRef: rawRef
            ))
        }

        if let autoUser = stringish(dict["autoLoginUser"]), !autoUser.isEmpty {
            if !hasPosture || rootPostureMissingBool(root, key: "auto_login_enabled") {
                events.append(accountPostureEvent(
                    kind: "auto_login",
                    enabled: "true",
                    extra: [
                        "account.auto_login_enabled": "true",
                        "account.auto_login_user": autoUser,
                        "user.name": autoUser,
                        "protection.source": "com.apple.loginwindow.plist",
                    ],
                    rawRef: rawRef
                ))
            }
        }

        return events
    }

    /// Wave-4: SMB / File Sharing prefs markers.
    private static func offlineFileSharingMarkers(root: ArtifactRoot) -> [EventEnvelope] {
        if root.exists("Library/Preferences/security_posture.json"),
           !rootPostureMissingBool(root, key: "file_sharing_enabled") {
            return []
        }
        let paths = [
            "Library/Preferences/SystemConfiguration/com.apple.smb.server.plist",
            "Library/Preferences/com.apple.AppleFileServer.plist",
        ]
        guard let hit = root.firstExisting(paths) else { return [] }
        var enabled = "present"
        if let dict = ArtifactIO.plistDict(contentsOf: hit) {
            if let b = boolish(dict["Enabled"]) ?? boolish(dict["serverEnabled"]) {
                enabled = b ? "true" : "false"
            }
        }
        return [
            remoteAccessEvent(
                name: "FileSharing",
                enabled: enabled == "present" ? "true" : enabled,
                mode: "offline",
                extra: [
                    "remote.service": "file_sharing",
                    "protection.marker_path": ArtifactRoot.pathKey(hit),
                    "protection.source": hit.lastPathComponent,
                    "protection.note": "Offline File Sharing prefs marker",
                ],
                rawRef: ArtifactRoot.pathKey(hit),
                confidence: enabled == "present" ? 0.6 : 0.85
            ),
        ]
    }

    /// Wave-4: Software Update catalog / auto-check honesty.
    private static func offlineSoftwareUpdateMarkers(root: ArtifactRoot) -> [EventEnvelope] {
        if root.exists("Library/Preferences/security_posture.json"),
           !rootPostureMissingBool(root, key: "software_update_automatic_check"),
           ArtifactIO.jsonDict(contentsOf: root.file("Library/Preferences/security_posture.json"))?["software_update_catalog_url"] != nil {
            return []
        }
        guard let url = root.firstExisting(["Library/Preferences/com.apple.SoftwareUpdate.plist"]),
              let dict = ArtifactIO.plistDict(contentsOf: url)
        else { return [] }

        var events: [EventEnvelope] = []
        let rawRef = ArtifactRoot.pathKey(url)
        if let auto = boolish(dict["AutomaticCheckEnabled"]) {
            events.append(protectionEvent(
                name: "SoftwareUpdateAuto",
                enabled: auto ? "true" : "false",
                mode: "offline",
                extra: [
                    "su.automatic_check": auto ? "true" : "false",
                    "protection.source": "com.apple.SoftwareUpdate.plist",
                ],
                rawRef: rawRef,
                confidence: 0.9
            ))
        }
        if let catalog = stringish(dict["CatalogURL"]), !catalog.isEmpty {
            let isApple = catalog.contains("swscan.apple.com") || catalog.contains("swcdn.apple.com")
            events.append(
                EventEnvelope(
                    eventTime: Date(),
                    collectedAt: Date(),
                    source: .collect,
                    sourcePlugin: "IRPOSTURE",
                    eventType: "ir.posture.software_update",
                    entityRefs: [EntityID(kind: .host, value: "su=catalog")],
                    fields: [
                        "ir.mode": "offline",
                        "protection.name": "SoftwareUpdateCatalog",
                        "protection.enabled": isApple ? "apple_default" : "custom",
                        "su.catalog_url": catalog,
                        "su.catalog_non_apple": isApple ? "false" : "true",
                        "protection.source": "com.apple.SoftwareUpdate.plist",
                        FieldTaxonomy.eventType: "ir.posture.software_update",
                    ],
                    rawRef: rawRef,
                    confidence: 0.92
                )
            )
        }
        return events
    }

    /// Wave-4: Lockdown Mode LDMGlobalEnabled from user GlobalPreferences.
    private static func offlineLockdownModeMarkers(root: ArtifactRoot) -> [EventEnvelope] {
        if root.exists("Library/Preferences/security_posture.json"),
           !rootPostureMissingBool(root, key: "lockdown_mode_enabled")
            || (ArtifactIO.jsonDict(contentsOf: root.file("Library/Preferences/security_posture.json"))?["lockdown_mode"] != nil) {
            // Posture JSON already covered Lockdown Mode
            if !rootPostureMissingBool(root, key: "lockdown_mode_enabled") { return [] }
            if let json = ArtifactIO.jsonDict(contentsOf: root.file("Library/Preferences/security_posture.json")),
               json["lockdown_mode"] != nil {
                return []
            }
        }

        var events: [EventEnvelope] = []
        for url in root.enumerate(matching: { url in
            url.lastPathComponent == ".GlobalPreferences.plist"
                || url.lastPathComponent == "GlobalPreferences.plist"
        }) {
            guard let dict = ArtifactIO.plistDict(contentsOf: url)
            else { continue }
            guard let ldm = dict["LDMGlobalEnabled"] else { continue }
            let enabled: String
            if let n = ldm as? NSNumber {
                enabled = n.intValue == 1 ? "true" : "false"
            } else if let b = boolish(ldm) {
                enabled = b ? "true" : "false"
            } else {
                enabled = "unknown"
            }
            events.append(protectionEvent(
                name: "LockdownMode",
                enabled: enabled,
                mode: "offline",
                extra: [
                    "lockdown.enabled": enabled,
                    "protection.source": ArtifactRoot.pathKey(url),
                    "protection.note": "LDMGlobalEnabled from GlobalPreferences (1=on, 0=was on/now off)",
                ],
                rawRef: ArtifactRoot.pathKey(url),
                confidence: enabled == "unknown" ? 0.5 : 0.88
            ))
            break
        }
        return events
    }

    private static func accountPostureEvent(
        kind: String,
        enabled: String,
        extra: [String: String] = [:],
        rawRef: String? = nil
    ) -> EventEnvelope {
        var fields: [String: String] = [
            "ir.mode": "offline",
            "account.kind": kind,
            "account.enabled": enabled,
            "protection.name": kind == "guest" ? "GuestAccount" : "AutoLogin",
            "protection.enabled": enabled,
            FieldTaxonomy.eventType: "ir.posture.account",
        ]
        for (k, v) in extra { fields[k] = v }
        return EventEnvelope(
            eventTime: Date(),
            collectedAt: Date(),
            source: .collect,
            sourcePlugin: "IRPOSTURE",
            eventType: "ir.posture.account",
            entityRefs: [EntityID(kind: .host, value: "account=\(kind)")],
            fields: fields,
            rawRef: rawRef,
            confidence: 0.88
        )
    }

    private static func remoteAccessEvent(
        name: String,
        enabled: String,
        mode: String,
        extra: [String: String] = [:],
        rawRef: String? = nil,
        confidence: Double
    ) -> EventEnvelope {
        var fields: [String: String] = [
            "ir.mode": mode,
            "protection.name": name,
            "protection.enabled": enabled,
            "remote.service": name,
            FieldTaxonomy.eventType: "ir.posture.remote_access",
        ]
        for (k, v) in extra { fields[k] = v }
        return EventEnvelope(
            eventTime: Date(),
            collectedAt: Date(),
            source: .collect,
            sourcePlugin: "IRPOSTURE",
            eventType: "ir.posture.remote_access",
            entityRefs: [EntityID(kind: .host, value: "remote=\(name.lowercased())")],
            fields: fields,
            rawRef: rawRef,
            confidence: confidence
        )
    }

    private static func offlineFileVaultMarkers(root: ArtifactRoot) -> [EventEnvelope] {
        // Skip if posture JSON already emitted FileVault (avoid duplicate noise)
        let markers = [
            "var/db/volinfo.database",
            "Library/Preferences/com.apple.FileVault.plist",
            "var/db/FileVault",
        ]
        guard let hit = root.firstExisting(markers) else { return [] }
        // Only emit path-marker event when security_posture.json did not cover FileVault
        if root.exists("Library/Preferences/security_posture.json") {
            return []
        }
        return [
            protectionEvent(
                name: "FileVault",
                enabled: "unknown",
                mode: "offline",
                extra: [
                    "protection.marker_path": ArtifactRoot.pathKey(hit),
                    "protection.note": "FileVault marker present offline; status unknown without fdesetup",
                ],
                rawRef: ArtifactRoot.pathKey(hit),
                confidence: 0.55
            ),
        ]
    }

    private static func offlineFirewallALF(root: ArtifactRoot) -> [EventEnvelope] {
        guard let url = root.firstExisting(["Library/Preferences/com.apple.alf.plist"]),
              let dict = ArtifactIO.plistDict(contentsOf: url)
        else { return [] }

        let globalState: Int
        if let i = dict["globalstate"] as? Int {
            globalState = i
        } else if let n = dict["globalstate"] as? NSNumber {
            globalState = n.intValue
        } else {
            globalState = -1
        }
        // ALF: 0 = off, 1 = on for specific, 2 = on for essential
        let enabled: String
        if globalState == 0 { enabled = "false" }
        else if globalState > 0 { enabled = "true" }
        else { enabled = "unknown" }

        return [
            protectionEvent(
                name: "Firewall",
                enabled: enabled,
                mode: "offline",
                extra: [
                    "protection.alf_globalstate": String(globalState),
                    "protection.source": "com.apple.alf.plist",
                    "protection.note": "Application Layer Firewall globalstate from offline plist",
                ],
                rawRef: ArtifactRoot.pathKey(url),
                confidence: enabled == "unknown" ? 0.5 : 0.9
            ),
        ]
    }

    private static func offlineXProtectMRT(root: ArtifactRoot) -> [EventEnvelope] {
        // Skip path probes when posture JSON already provided versions
        if root.exists("Library/Preferences/security_posture.json") {
            return []
        }
        var events: [EventEnvelope] = []
        let xpPaths = [
            "Library/Apple/System/Library/CoreServices/XProtect.bundle",
            "System/Library/CoreServices/XProtect.bundle",
            "Library/Logs/DiagnosticReports",
        ]
        if let hit = root.firstExisting(xpPaths) {
            events.append(
                EventEnvelope(
                    eventTime: Date(),
                    collectedAt: Date(),
                    source: .collect,
                    sourcePlugin: "IRPOSTURE",
                    eventType: "ir.posture.protection",
                    entityRefs: [
                        EntityID(kind: .host, value: "protection=xprotect"),
                        .file(path: ArtifactRoot.pathKey(hit)),
                    ],
                    fields: [
                        "ir.mode": "offline",
                        "protection.name": "XProtect",
                        "protection.enabled": "present",
                        "protection.marker_path": ArtifactRoot.pathKey(hit),
                        FieldTaxonomy.filePath: ArtifactRoot.pathKey(hit),
                        FieldTaxonomy.eventType: "ir.posture.protection",
                    ],
                    rawRef: ArtifactRoot.pathKey(hit),
                    confidence: 0.7
                )
            )
        }
        let mrtPaths = [
            "Library/Apple/System/Library/CoreServices/MRT.app",
            "System/Library/CoreServices/MRT.app",
        ]
        if let hit = root.firstExisting(mrtPaths) {
            events.append(
                EventEnvelope(
                    eventTime: Date(),
                    collectedAt: Date(),
                    source: .collect,
                    sourcePlugin: "IRPOSTURE",
                    eventType: "ir.posture.protection",
                    entityRefs: [
                        EntityID(kind: .host, value: "protection=mrt"),
                        .file(path: ArtifactRoot.pathKey(hit)),
                    ],
                    fields: [
                        "ir.mode": "offline",
                        "protection.name": "MRT",
                        "protection.enabled": "present",
                        "protection.marker_path": ArtifactRoot.pathKey(hit),
                        FieldTaxonomy.filePath: ArtifactRoot.pathKey(hit),
                        FieldTaxonomy.eventType: "ir.posture.protection",
                    ],
                    rawRef: ArtifactRoot.pathKey(hit),
                    confidence: 0.7
                )
            )
        }
        return events
    }

    private static func offlineFDAHint(root: ArtifactRoot) -> [EventEnvelope] {
        let tccPaths = [
            "Library/Application Support/com.apple.TCC/TCC.db",
            "Users/alice/Library/Application Support/com.apple.TCC/TCC.db",
        ]
        guard let hit = root.firstExisting(tccPaths) else { return [] }
        // If posture JSON already emitted fda_hint, still note TCC.db presence with distinct type detail
        return [
            EventEnvelope(
                eventTime: Date(),
                collectedAt: Date(),
                source: .collect,
                sourcePlugin: "IRPOSTURE",
                eventType: "ir.posture.fda_hint",
                entityRefs: [
                    EntityID(kind: .host, value: "protection=fda"),
                    .file(path: ArtifactRoot.pathKey(hit)),
                ],
                fields: [
                    "ir.mode": "offline",
                    "protection.name": "FDA",
                    "protection.fda_offline_note":
                        "Offline TCC.db present under artifact tree; FDA grants require live TCC/Full Disk Access check",
                    "protection.tcc_path": ArtifactRoot.pathKey(hit),
                    FieldTaxonomy.filePath: ArtifactRoot.pathKey(hit),
                    FieldTaxonomy.eventType: "ir.posture.fda_hint",
                ],
                rawRef: ArtifactRoot.pathKey(hit),
                confidence: 0.7
            ),
        ]
    }

    // MARK: - Private

    private static func securityProductEvent(name: String, path: String, mode: String) -> EventEnvelope {
        EventEnvelope(
            eventTime: Date(),
            collectedAt: Date(),
            source: .collect,
            sourcePlugin: "IRPOSTURE",
            eventType: "ir.posture.security_product",
            entityRefs: [
                EntityID(kind: .host, value: "security=\(name)"),
                .file(path: path),
            ],
            fields: [
                "ir.mode": mode,
                "security.product": name,
                "security.path": path,
                FieldTaxonomy.filePath: path,
                FieldTaxonomy.eventType: "ir.posture.security_product",
            ],
            rawRef: path,
            confidence: 0.95
        )
    }

    private static func protectionEvent(
        name: String,
        enabled: String,
        mode: String,
        extra: [String: String] = [:],
        rawRef: String? = nil,
        confidence: Double = 0.9
    ) -> EventEnvelope {
        var fields: [String: String] = [
            "ir.mode": mode,
            "protection.name": name,
            "protection.enabled": enabled,
            FieldTaxonomy.eventType: "ir.posture.protection",
        ]
        for (k, v) in extra { fields[k] = v }
        return EventEnvelope(
            eventTime: Date(),
            collectedAt: Date(),
            source: .collect,
            sourcePlugin: "IRPOSTURE",
            eventType: "ir.posture.protection",
            entityRefs: [EntityID(kind: .host, value: "protection=\(name.lowercased())")],
            fields: fields,
            rawRef: rawRef,
            confidence: confidence
        )
    }

    private static func protectionProbeEvents() -> [EventEnvelope] {
        var events: [EventEnvelope] = []

        // Shared SIP / Gatekeeper / FileVault via RootstockMacFacts parsers
        let sipRaw = runProbe(path: HostPostureProbes.csrutilPath, args: ["status"])
        let gkRaw = runProbe(path: HostPostureProbes.spctlPath, args: ["--status"])
        let fvRaw = runProbe(path: HostPostureProbes.fdesetupPath, args: ["status"])

        if let fvRaw {
            let enabled = HostPostureProbes.enabledLabel(
                HostPostureProbes.parseFileVaultOutput(fvRaw)
            )
            events.append(protectionEvent(
                name: "FileVault",
                enabled: enabled,
                mode: "live",
                extra: [
                    "protection.raw": String(fvRaw.prefix(200)),
                    "protection.parser": "HostPostureProbes",
                ],
                confidence: enabled == "unknown" ? 0.5 : 0.9
            ))
        }

        // Application Firewall via socketfilterfw (prefer) or fail soft - product-specific
        let fwPath = "/usr/libexec/ApplicationFirewall/socketfilterfw"
        if let fw = runProbe(path: fwPath, args: ["--getglobalstate"]) {
            let lower = fw.lowercased()
            let enabled: String
            if lower.contains("enabled") && !lower.contains("disabled") {
                enabled = "true"
            } else if lower.contains("disabled") {
                enabled = "false"
            } else {
                enabled = "unknown"
            }
            events.append(protectionEvent(
                name: "Firewall",
                enabled: enabled,
                mode: "live",
                extra: ["protection.raw": String(fw.prefix(200))],
                confidence: enabled == "unknown" ? 0.5 : 0.9
            ))
        }

        if let sipRaw {
            let enabled = HostPostureProbes.enabledLabel(
                HostPostureProbes.parseSIPOutput(sipRaw)
            )
            events.append(protectionEvent(
                name: "SIP",
                enabled: enabled,
                mode: "live",
                extra: [
                    "protection.raw": String(sipRaw.prefix(200)),
                    "protection.parser": "HostPostureProbes",
                ],
                confidence: enabled == "unknown" ? 0.5 : 0.9
            ))
        }

        if let gkRaw {
            let enabled = HostPostureProbes.enabledLabel(
                HostPostureProbes.parseGatekeeperOutput(gkRaw)
            )
            events.append(protectionEvent(
                name: "Gatekeeper",
                enabled: enabled,
                mode: "live",
                extra: [
                    "protection.raw": String(gkRaw.prefix(200)),
                    "protection.parser": "HostPostureProbes",
                ],
                confidence: enabled == "unknown" ? 0.5 : 0.9
            ))
        }

        // systemextensionsctl list - graceful fail when binary/absent/denied
        if let sext = runProbe(path: "/usr/bin/systemextensionsctl", args: ["list"]) {
            let lines = sext.split(whereSeparator: \.isNewline).map(String.init)
            let dataLines = lines.filter {
                let t = $0.trimmingCharacters(in: .whitespaces)
                return !t.isEmpty && !t.hasPrefix("---") && !t.lowercased().hasPrefix("extensionname")
                    && !t.lowercased().contains("1 extension") && !t.lowercased().contains("0 extension")
            }
            if dataLines.isEmpty {
                events.append(
                    EventEnvelope(
                        eventTime: Date(),
                        collectedAt: Date(),
                        source: .collect,
                        sourcePlugin: "IRPOSTURE",
                        eventType: "ir.posture.system_extension",
                        entityRefs: [EntityID(kind: .host, value: "sysext=none")],
                        fields: [
                            "ir.mode": "live",
                            "protection.name": "SystemExtension",
                            "protection.enabled": "none",
                            "sysext.name": "none",
                            "sysext.state": "none",
                            "protection.raw": String(sext.prefix(200)),
                            FieldTaxonomy.eventType: "ir.posture.system_extension",
                        ],
                        confidence: 0.7
                    )
                )
            } else {
                for (idx, line) in dataLines.prefix(20).enumerated() {
                    let name = line.trimmingCharacters(in: .whitespaces)
                    events.append(
                        EventEnvelope(
                            eventTime: Date(),
                            collectedAt: Date(),
                            source: .collect,
                            sourcePlugin: "IRPOSTURE",
                            eventType: "ir.posture.system_extension",
                            entityRefs: [EntityID(kind: .host, value: "sysext=\(idx)")],
                            fields: [
                                "ir.mode": "live",
                                "protection.name": "SystemExtension",
                                "protection.enabled": "present",
                                "sysext.name": String(name.prefix(120)),
                                "sysext.state": "listed",
                                "protection.raw": String(name.prefix(200)),
                                FieldTaxonomy.eventType: "ir.posture.system_extension",
                            ],
                            confidence: 0.85
                        )
                    )
                }
            }
        }

        return events
    }

    private static func runProbe(path: String, args: [String]) -> String? {
        guard FileManager.default.isExecutableFile(atPath: path) else { return nil }
        let proc = Process()
        proc.executableURL = URL(fileURLWithPath: path)
        proc.arguments = args
        let pipe = Pipe()
        proc.standardOutput = pipe
        proc.standardError = pipe
        do {
            try proc.run()
        } catch {
            return nil
        }
        // Bound wait - do not hang IR path
        let deadline = Date().addingTimeInterval(3)
        while proc.isRunning && Date() < deadline {
            Thread.sleep(forTimeInterval: 0.05)
        }
        if proc.isRunning {
            proc.terminate()
            return nil
        }
        let data = pipe.fileHandleForReading.readDataToEndOfFile()
        return String(data: data, encoding: .utf8)
    }

}
