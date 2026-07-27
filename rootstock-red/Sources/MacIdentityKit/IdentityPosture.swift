import Foundation
import RootstockCore

/// Read-only identity posture (AD bind / Platform SSO) via filesystem heuristics.
///
/// No `dscl`, no shell, no osascript. Evidence is path existence/readability only,
/// never secret material from plists.
public struct IdentityPostureCollector: Collector {
    public static let id = "collect.identity"
    public static let cost: CollectorCost = .low

    public init() {}

    public func collect(context: EvaluationContext) async throws -> CollectedState {
        let fm = FileManager.default
        var notes: [String] = [
            "Identity posture via filesystem heuristics (no dscl/osascript)",
        ]
        var odConfigPaths: [String] = []
        var ssoPaths: [String] = []

        // MARK: - Open Directory / Active Directory bind

        let adDirConfig = "/Library/Preferences/OpenDirectory/Configurations/Active Directory"
        let odConfigsRoot = "/Library/Preferences/OpenDirectory/Configurations"
        let adPlist = "/Library/Preferences/DirectoryService/ActiveDirectory.plist"
        let dsADContact = "/Library/Preferences/DirectoryService/ActiveDirectoryContact.plist"
        let dsConfigPlist = "/Library/Preferences/DirectoryService/DirectoryService.plist"
        let dsSearchPlist = "/Library/Preferences/DirectoryService/SearchNodeConfig.plist"
        let dsconfigadState = "/Library/Preferences/OpenDirectory/Configurations/Active Directory/Active Directory.plist"
        let comAppleDirectoryService =
            "/Library/Preferences/com.apple.DirectoryService.plist"

        let adCandidates = [
            adDirConfig,
            adPlist,
            dsADContact,
            dsconfigadState,
        ]
        for path in adCandidates {
            let exists = fm.fileExists(atPath: path)
            let readable = fm.isReadableFile(atPath: path)
            if exists {
                odConfigPaths.append(path)
                notes.append("AD candidate: \(path) exists=\(exists) readable=\(readable)")
            } else {
                notes.append("AD candidate: \(path) missing")
            }
        }

        // List OD configuration nodes when readable (names only).
        var odConfigEntries: [String] = []
        if fm.fileExists(atPath: odConfigsRoot) {
            odConfigPaths.append(odConfigsRoot)
            if let entries = try? fm.contentsOfDirectory(atPath: odConfigsRoot) {
                odConfigEntries = entries.sorted()
                notes.append(
                    "OD Configurations listable (\(odConfigEntries.count)): \(odConfigEntries.joined(separator: ", "))"
                )
                for name in odConfigEntries {
                    let child = (odConfigsRoot as NSString).appendingPathComponent(name)
                    if !odConfigPaths.contains(child) {
                        odConfigPaths.append(child)
                    }
                }
            } else {
                notes.append("OD Configurations present but not listable (permissions)")
            }
        } else {
            notes.append("OD Configurations root missing: \(odConfigsRoot)")
        }

        for path in [dsConfigPlist, dsSearchPlist, comAppleDirectoryService] {
            let exists = fm.fileExists(atPath: path)
            notes.append("DirectoryService prefs: \(path) exists=\(exists)")
            if exists {
                odConfigPaths.append(path)
            }
        }

        let adPathHit = adCandidates.contains { fm.fileExists(atPath: $0) }
        let adNameHit = odConfigEntries.contains {
            $0.localizedCaseInsensitiveContains("Active Directory")
                || $0.localizedCaseInsensitiveContains("ActiveDirectory")
                || $0.caseInsensitiveCompare("AD") == .orderedSame
        }
        let adBound: Bool?
        if adPathHit || adNameHit {
            adBound = true
            notes.append("AD bind signal: positive (path and/or OD node name)")
        } else if fm.fileExists(atPath: odConfigsRoot),
                  (try? fm.contentsOfDirectory(atPath: odConfigsRoot)) != nil
        {
            // Readable OD configs and no AD node → not bound (heuristic).
            adBound = false
            notes.append("AD bind signal: negative (OD configs readable, no AD node/path)")
        } else {
            adBound = nil
            notes.append("AD bind signal: unknown (insufficient OD path visibility)")
        }

        // MARK: - Kerberos

        let kerberosPrefs = "/Library/Preferences/edu.mit.Kerberos"
        let kerberosConf = "/etc/krb5.conf"
        let kerberosConfPrivate = "/private/etc/krb5.conf"
        let kerberosHome = (NSHomeDirectory() as NSString)
            .appendingPathComponent("Library/Preferences/edu.mit.Kerberos")
        let kerberosHits = [kerberosPrefs, kerberosConf, kerberosConfPrivate, kerberosHome].filter {
            fm.fileExists(atPath: $0)
        }
        for path in [kerberosPrefs, kerberosConf, kerberosConfPrivate, kerberosHome] {
            notes.append("Kerberos: \(path) exists=\(fm.fileExists(atPath: path))")
        }
        let kerberosConfigPresent = !kerberosHits.isEmpty
        if kerberosConfigPresent {
            notes.append("Kerberos config present at: \(kerberosHits.joined(separator: ", "))")
        }

        // MARK: - Platform SSO / AppSSO

        let home = NSHomeDirectory()
        let platformSSOSystem = "/Library/Application Support/com.apple.PlatformSSO"
        let platformSSOUser =
            (home as NSString).appendingPathComponent(
                "Library/Application Support/com.apple.PlatformSSO"
            )
        let platformSSOPrefs = [
            "/Library/Preferences/com.apple.PlatformSSO.plist",
            "/Library/Managed Preferences/com.apple.PlatformSSO.plist",
            "/Library/Managed Preferences/com.apple.AppSSO.plist",
            "/Library/Preferences/com.apple.AppSSO.plist",
            "/Library/Managed Preferences/com.apple.AppSSOAgent.plist",
        ]
        let appSupport = "/Library/Application Support"

        for path in [platformSSOSystem, platformSSOUser] {
            let exists = fm.fileExists(atPath: path)
            notes.append("PlatformSSO support dir: \(path) exists=\(exists)")
            if exists {
                ssoPaths.append(path)
            }
        }
        for path in platformSSOPrefs {
            let exists = fm.fileExists(atPath: path)
            notes.append("SSO prefs: \(path) exists=\(exists)")
            if exists {
                ssoPaths.append(path)
            }
        }

        // Scan Application Support for SSO-related containers (names only).
        if let supportEntries = try? fm.contentsOfDirectory(atPath: appSupport) {
            let ssoNamed = supportEntries.filter { name in
                let lower = name.lowercased()
                return lower.contains("platformsso")
                    || lower.contains("appssso")
                    || lower.contains("app.sso")
                    || lower.contains("com.apple.appsso")
                    || lower.contains("ssoextension")
                    || lower.contains("sso-extension")
            }
            for name in ssoNamed.sorted() {
                let path = (appSupport as NSString).appendingPathComponent(name)
                if !ssoPaths.contains(path) {
                    ssoPaths.append(path)
                }
                notes.append("SSO-related Application Support: \(path)")
            }
        }

        // Managed Preferences: any domain suggesting Platform SSO / AppSSO.
        let managedPrefs = "/Library/Managed Preferences"
        if let managed = try? fm.contentsOfDirectory(atPath: managedPrefs) {
            let ssoManaged = managed.filter { name in
                let lower = name.lowercased()
                return lower.contains("platformsso")
                    || lower.contains("appssso")
                    || lower.contains("appsso")
                    || lower.contains("sso")
            }
            for name in ssoManaged.sorted() {
                let path = (managedPrefs as NSString).appendingPathComponent(name)
                if !ssoPaths.contains(path) {
                    ssoPaths.append(path)
                }
                notes.append("SSO managed preference: \(path)")
            }
        }

        let platformSSO: Bool? = !ssoPaths.isEmpty ? true : false
        notes.append(
            "Platform SSO signal: \(platformSSO == true ? "positive" : "negative") "
                + "(\(ssoPaths.count) path(s))"
        )
        notes.append(
            "Summary: adBound=\(adBound.rootstockDescribe) platformSSO=\(platformSSO.rootstockDescribe) "
                + "kerberos=\(kerberosConfigPresent) odPaths=\(odConfigPaths.count) ssoPaths=\(ssoPaths.count)"
        )

        var state = CollectedState()
        state.identity = IdentityState(
            adBound: adBound,
            platformSSO: platformSSO,
            kerberosConfigPresent: kerberosConfigPresent,
            odConfigPaths: Array(Set(odConfigPaths)).sorted(),
            ssoPaths: Array(Set(ssoPaths)).sorted(),
            notes: notes
        )
        state.collectorNotes[Self.id] =
            "identity fs probes adBound=\(adBound.rootstockDescribe) "
            + "platformSSO=\(platformSSO.rootstockDescribe) kerberos=\(kerberosConfigPresent)"
        return state
    }

}
