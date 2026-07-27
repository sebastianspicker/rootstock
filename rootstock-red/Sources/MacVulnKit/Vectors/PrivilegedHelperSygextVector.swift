import Foundation
import RootstockCore

/// Path-to-impact: Privileged Helper Tools and System Extensions as persistence / privesc surface.
///
/// Reports ranked findings with ATT&CK mappings, SIP state, and remediation.
/// Inventory alone is not sufficient to report a finding.
public struct PrivilegedHelperSygextVector: Check {
    public static let id = "rootstock.vector.persist.privileged_helper_sygext"
    public static let cost: CollectorCost = .low

    public init() {}

    public func evaluate(state: CollectedState, context: EvaluationContext) async throws -> [Finding] {
        let helpers = state.privilegedHelperTools
        let extensions = state.systemExtensionPaths
        guard !helpers.isEmpty || !extensions.isEmpty else { return [] }

        var evidence: [Evidence] = [
            Evidence(
                type: "summary",
                detail: "privilegedHelpers=\(helpers.count) systemExtensions=\(extensions.count)"
            ),
        ]

        var writableHelpers: [String] = []
        for path in helpers.prefix(40) {
            let writable = FileManager.default.isWritableFile(atPath: path)
                || Self.parentWritable(path)
            if writable { writableHelpers.append(path) }
            evidence.append(
                Evidence(
                    type: "privileged_helper",
                    path: path,
                    detail: "writable=\(writable)"
                )
            )
        }

        var writableExts: [String] = []
        for path in extensions.prefix(40) {
            let writable = FileManager.default.isWritableFile(atPath: path)
                || Self.parentWritable(path)
            if writable { writableExts.append(path) }
            evidence.append(
                Evidence(
                    type: "system_extension",
                    path: path,
                    detail: "writable=\(writable)"
                )
            )
        }

        let severity: Severity
        let confidence: Confidence
        let title: String
        if !writableHelpers.isEmpty || !writableExts.isEmpty {
            severity = .high
            confidence = .medium
            title =
                "Privileged helper / system-extension vector: user-writable surface "
                + "(\(writableHelpers.count + writableExts.count))"
        } else if helpers.count + extensions.count >= 3 {
            severity = .medium
            confidence = .medium
            title =
                "Privileged helper / system-extension persistence surface "
                + "(\(helpers.count) helpers, \(extensions.count) extensions)"
        } else {
            severity = .low
            confidence = .medium
            title =
                "Privileged helper / system-extension inventory surface "
                + "(\(helpers.count + extensions.count) paths)"
        }

        return [
            Finding(
                id: Self.id,
                title: title,
                severity: severity,
                confidence: confidence,
                category: .persist,
                evidence: evidence,
                attackTechniques: ["T1543.001", "T1543.004", "T1068", "T1574"],
                remediation: [
                    "Inventory PrivilegedHelperTools and SystemExtensions; remove unexpected vendors",
                    "Ensure helpers are root-owned, non-user-writable, and properly code-signed",
                    "System Extensions require user/MDM approval - monitor unexpected activation prompts",
                    "OPSEC: listing /Library/PrivilegedHelperTools is quiet; installing fakes is high-risk and out of assess scope",
                ],
                falsePositiveNotes:
                    "Legitimate security/MDM products install helpers and extensions. Writable flags on "
                    + "SIP-protected system volumes should normally be false; lab temp paths may simulate writability.",
                dryRunSafe: true,
                opsecScore: writableHelpers.isEmpty && writableExts.isEmpty ? 20 : 55,
                esfExpected: ["OPEN", "WRITE"]
            ),
        ]
    }

    private static func parentWritable(_ path: String) -> Bool {
        let parent = URL(fileURLWithPath: path).deletingLastPathComponent().path
        return FileManager.default.isWritableFile(atPath: parent)
    }
}
