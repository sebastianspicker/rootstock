import Foundation
import RootstockCore

/// MDM profile shallow parse depth (Wave-9).
///
/// Research basis: Configuration Profile PayloadType taxonomy; enterprise mobileconfig research.
/// Safety and behavior: shallow PayloadType / PayloadDisplayName inventory only; never dumps secrets or installs profiles.
public struct MDMProfileParseDepthCollector: Collector {
    public static let id = "collect.mdm_profile_parse_depth"
    public static let cost: CollectorCost = .low

    private static let searchRoots: [String] = [
        NSHomeDirectory() + "/Downloads",
        NSHomeDirectory() + "/Desktop",
        NSHomeDirectory() + "/Documents",
        "/Library/Managed Preferences",
        "/var/db/ConfigurationProfiles",
        "/Library/ConfigurationProfiles",
    ]

    private static let secretKeyHints: Set<String> = [
        "password", "Password", "PayloadContent", "PasswordHash",
        "SharedSecret", "PrivateKey", "privateKey", "Certificate",
        "PayloadCertificateFileName", "PasswordData", "EAPClientConfiguration",
    ]

    public init() {}

    public func collect(context: EvaluationContext) async throws -> CollectedState {
        let fm = FileManager.default
        var notes: [String] = [
            "MDM profile parse depth: shallow PayloadType inventory only - never dumps secrets, never installs profiles",
        ]

        var candidates: [String] = []
        for root in Self.searchRoots {
            guard fm.fileExists(atPath: root) else { continue }
            // Shallow directory listing only (one level) for *.mobileconfig / *.mobileConfig.
            if let entries = try? fm.contentsOfDirectory(atPath: root) {
                for name in entries where name.lowercased().hasSuffix(".mobileconfig") {
                    candidates.append((root as NSString).appendingPathComponent(name))
                }
            }
            // Also record known profile store roots when present.
            if root.contains("ConfigurationProfiles") || root.contains("Managed Preferences") {
                notes.append("profile_root: \(root)")
            }
        }

        // Cap examination for cost honesty.
        candidates = Array(Set(candidates)).sorted().prefix(12).map { $0 }

        var examined: [String] = []
        var payloadTypes = Set<String>()
        var displayNamePresent = false
        var parsed = 0

        for path in candidates {
            examined.append(path)
            guard let data = try? Data(contentsOf: URL(fileURLWithPath: path), options: [.mappedIfSafe]) else {
                notes.append("unreadable_profile: \(path)")
                continue
            }
            // Refuse huge blobs (avoid accidental secret-heavy payloads in memory narrative).
            if data.count > 512_000 {
                notes.append("skipped_large_profile: \(path) size=\(data.count)")
                continue
            }
            var format = PropertyListSerialization.PropertyListFormat.xml
            guard let plist = try? PropertyListSerialization.propertyList(
                from: data,
                options: [.mutableContainers],
                format: &format
            ) as? [String: Any] else {
                notes.append("unparseable_profile: \(path)")
                continue
            }
            parsed += 1
            if plist["PayloadDisplayName"] != nil {
                displayNamePresent = true
            }
            if let type = plist["PayloadType"] as? String {
                payloadTypes.insert(type)
            }
            // Walk PayloadContent array for nested PayloadType only.
            if let content = plist["PayloadContent"] as? [[String: Any]] {
                for item in content {
                    if let type = item["PayloadType"] as? String {
                        payloadTypes.insert(type)
                    }
                    if item["PayloadDisplayName"] != nil {
                        displayNamePresent = true
                    }
                    // Honesty: note if secret-shaped keys exist without capturing values.
                    for key in item.keys where Self.secretKeyHints.contains(key) {
                        notes.append("secret_shaped_key_present_not_dumped: \(key) in \(path)")
                    }
                }
            }
            notes.append("parsed_profile: \(path) types≈\(payloadTypes.count)")
        }

        let types = payloadTypes.sorted()
        let surface = parsed > 0 || !examined.isEmpty
            || notes.contains(where: { $0.hasPrefix("profile_root:") })

        var state = CollectedState()
        state.mdmProfileParseDepth = MDMProfileParseDepthState(
            examinedProfilePaths: examined,
            payloadTypes: types,
            parsedProfileCount: parsed,
            displayNamePresent: displayNamePresent,
            parseSurfacePresent: surface,
            notes: notes
        )
        state.collectorNotes[Self.id] =
            "examined=\(examined.count) parsed=\(parsed) types=\(types.count) "
            + "displayName=\(displayNamePresent) surface=\(surface)"
        return state
    }
}
