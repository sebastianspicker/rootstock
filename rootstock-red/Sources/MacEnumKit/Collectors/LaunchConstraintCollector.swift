import Foundation
import RootstockCore

/// Launch-constraint / library-validation injectability truth (path + codesign note heuristics).
///
/// Research basis: InjectCheck-style HR/LV flags; Apple launch-constraint documentation themes.
/// Safety and behavior: explicit constrained vs unconstrained-risk path sets; never claims process
/// injection success; feeds `LaunchConstraintInjectTruthVector`.
public struct LaunchConstraintCollector: Collector {
    public static let id = "collect.launch_constraints"
    public static let cost: CollectorCost = .medium

    /// Lightweight sample set: common high-value app locations (metadata only).
    private static let sampleRoots: [String] = [
        "/Applications",
        "/usr/local/bin",
        "/opt/homebrew/bin",
    ]

    public init() {}

    public func collect(context: EvaluationContext) async throws -> CollectedState {
        let fm = FileManager.default
        var notes: [String] = [
            "Launch-constraint honesty: path/codesign heuristics only - no runtime inject",
        ]
        var constrained: [String] = []
        var unconstrainedRisk: [String] = []
        var injectHits: [InjectabilityHit] = []
        var codesignSamples: [CodesignSample] = []

        // Probe a small set of application bundles for Info.plist / MacOS binary presence.
        let appsRoot = URL(fileURLWithPath: "/Applications", isDirectory: true)
        let appURLs = (try? fm.contentsOfDirectory(
            at: appsRoot,
            includingPropertiesForKeys: [.isDirectoryKey],
            options: [.skipsHiddenFiles]
        )) ?? []
        let apps = appURLs
            .filter { $0.pathExtension == "app" }
            .prefix(12)

        for app in apps {
            let macOS = app
                .appendingPathComponent("Contents/MacOS", isDirectory: true)
            let info = app.appendingPathComponent("Contents/Info.plist")
            guard fm.fileExists(atPath: info.path) else { continue }

            // Launch constraint plists sometimes shipped under Contents/Library or Resources.
            let constraintCandidates = [
                app.appendingPathComponent("Contents/Library/LaunchConstraints"),
                app.appendingPathComponent("Contents/Resources/launchd-constraint.plist"),
                app.appendingPathComponent("Contents/CodeResources"),
            ]
            var hasConstraintArtifact = false
            for c in constraintCandidates {
                if fm.fileExists(atPath: c.path) {
                    hasConstraintArtifact = true
                    constrained.append(c.path)
                    notes.append("constraint-ish artifact: \(c.path)")
                }
            }

            // codesign --display is allowlisted in spirit; prefer lightweight file presence.
            // Sample executable name from MacOS dir if listable.
            if let bins = try? fm.contentsOfDirectory(atPath: macOS.path),
               let first = bins.first
            {
                let binPath = macOS.appendingPathComponent(first).path
                let sample = Self.codesignProbe(path: binPath)
                codesignSamples.append(sample)

                let riskFlags = Self.riskFlags(from: sample)
                if !riskFlags.isEmpty {
                    injectHits.append(
                        InjectabilityHit(
                            path: binPath,
                            hardenedRuntime: sample.hardenedRuntime,
                            getTaskAllow: sample.getTaskAllow,
                            disableLibraryValidation: sample.disableLibraryValidation,
                            allowDyldEnvironmentVariables: sample.allowDyldEnvironmentVariables,
                            allowUnsignedExecutableMemory: sample.allowUnsignedExecutableMemory,
                            riskFlags: riskFlags,
                            notes: sample.notes
                        )
                    )
                    if !hasConstraintArtifact {
                        unconstrainedRisk.append(binPath)
                        notes.append(
                            "risk without constraint artifact: \(binPath) flags=\(riskFlags.joined(separator: ","))"
                        )
                    }
                } else if hasConstraintArtifact {
                    notes.append("constrained sample with no entitlement risk flags: \(binPath)")
                }
            }
        }

        // Also note roots scanned.
        for root in Self.sampleRoots {
            notes.append("sample_root_exists=\(fm.fileExists(atPath: root)): \(root)")
        }

        var state = CollectedState()
        state.launchConstraints = LaunchConstraintState(
            constrainedPaths: Array(Set(constrained)).sorted(),
            unconstrainedRiskPaths: Array(Set(unconstrainedRisk)).sorted(),
            notes: notes
        )
        if !injectHits.isEmpty {
            state.injectabilityHits = injectHits
        }
        if !codesignSamples.isEmpty {
            state.codesignSamples = codesignSamples
        }
        state.collectorNotes[Self.id] =
            "constrained=\(constrained.count) unconstrainedRisk=\(unconstrainedRisk.count) "
            + "injectSamples=\(injectHits.count)"
        return state
    }

    /// Best-effort codesign display via Process (allowlisted security tooling).
    private static func codesignProbe(path: String) -> CodesignSample {
        var sample = CodesignSample(path: path, notes: ["launch_constraint_collector_probe"])
        let proc = Process()
        proc.executableURL = URL(fileURLWithPath: "/usr/bin/codesign")
        proc.arguments = ["-d", "--entitlements", ":-", path]
        let out = Pipe()
        let err = Pipe()
        proc.standardOutput = out
        proc.standardError = err
        do {
            try proc.run()
            proc.waitUntilExit()
        } catch {
            sample.notes.append("codesign spawn failed: \(error.localizedDescription)")
            return sample
        }
        let errData = err.fileHandleForReading.readDataToEndOfFile()
        let outData = out.fileHandleForReading.readDataToEndOfFile()
        let text = String(data: errData + outData, encoding: .utf8) ?? ""
        sample.signed = proc.terminationStatus == 0 || text.contains("Authority=")
        if text.localizedCaseInsensitiveContains("flags=0x")
            || text.localizedCaseInsensitiveContains("runtime")
        {
            sample.hardenedRuntime =
                text.localizedCaseInsensitiveContains("runtime")
                || text.contains("flags=0x10000")
                || text.contains("flags=0x30000")
        }
        // Key-adjacent bool only - never use a global `<true` scan (other entitlements pollute).
        sample.getTaskAllow = entitlementBool(
            in: text,
            key: "com.apple.security.get-task-allow"
        )
        sample.disableLibraryValidation = entitlementBool(
            in: text,
            key: "com.apple.security.cs.disable-library-validation"
        )
        sample.allowDyldEnvironmentVariables = entitlementBool(
            in: text,
            key: "com.apple.security.cs.allow-dyld-environment-variables"
        )
        sample.allowUnsignedExecutableMemory = entitlementBool(
            in: text,
            key: "com.apple.security.cs.allow-unsigned-executable-memory"
        )
        if sample.signed == false {
            sample.notes.append("codesign exit=\(proc.terminationStatus)")
        }
        return sample
    }

    /// Parse a boolean entitlement from codesign XML using key-adjacent true/false only.
    ///
    /// Returns `nil` when the key is absent; `true`/`false` only when the value tag
    /// immediately follows that key (does not treat unrelated `<true/>` elsewhere as a hit).
    public static func entitlementBool(in text: String, key: String) -> Bool? {
        let escaped = NSRegularExpression.escapedPattern(for: key)
        // `<key>…key…</key>` then optional whitespace then `<true/>` or `<false/>` (or non-self-closing).
        let pattern =
            #"<key>\s*"# + escaped + #"</key>\s*<(true|false)\s*/?>"#
        guard let regex = try? NSRegularExpression(pattern: pattern, options: [.caseInsensitive])
        else { return nil }
        let range = NSRange(text.startIndex..<text.endIndex, in: text)
        guard let match = regex.firstMatch(in: text, options: [], range: range),
              match.numberOfRanges >= 2,
              let valueRange = Range(match.range(at: 1), in: text)
        else { return nil }
        return text[valueRange].lowercased() == "true"
    }

    private static func riskFlags(from sample: CodesignSample) -> [String] {
        var flags: [String] = []
        if sample.hardenedRuntime == false { flags.append("hardened_runtime_off") }
        if sample.getTaskAllow == true { flags.append("get-task-allow") }
        if sample.disableLibraryValidation == true { flags.append("disable-library-validation") }
        if sample.allowDyldEnvironmentVariables == true {
            flags.append("allow-dyld-environment-variables")
        }
        if sample.allowUnsignedExecutableMemory == true {
            flags.append("allow-unsigned-executable-memory")
        }
        if sample.signed == false { flags.append("unsigned_or_untrusted") }
        return flags
    }
}
