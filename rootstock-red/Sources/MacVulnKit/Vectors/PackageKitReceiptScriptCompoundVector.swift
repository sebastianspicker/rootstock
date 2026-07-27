import Foundation
import RootstockCore

/// Wave-10 compound depth: PackageKit services × receipts path-to-impact.
///
/// Research basis: PackageKit design-based persistence research (package_script_service / receipts).
/// Safety and behavior: services+receipts co-presence with remote/root/sipOff amplifiers; never builds pkgs.
public struct PackageKitReceiptScriptCompoundVector: Check {
    public static let id = "rootstock.vector.persist.packagekit_receipt_script_compound"
    public static let cost: CollectorCost = .low

    public init() {}

    public func evaluate(state: CollectedState, context: EvaluationContext) async throws -> [Finding] {
        let pk = state.packageKitInstallerDesign
        let services = pk?.installerServicePaths.count ?? 0
        let receipts = pk?.receiptAndHistoryPaths.count ?? 0
        let tooling = pk?.toolingPaths.count ?? 0
        let plugins = pk?.installerPluginPaths.count ?? 0

        // Compound gate: services ≥ 1 AND receipts ≥ 1 (deeper than base design vector).
        guard services >= 1, receipts >= 1 else { return [] }

        let remote =
            state.network?.remoteLoginSSH == true
            || state.network?.screenSharingARD == true
        let isRoot = state.host?.isRoot == true
        let sipOff = state.protections?.sipEnabled == false
        let amplified = remote || isRoot || sipOff

        var evidence: [Evidence] = [
            Evidence(
                type: "receipt_script_compound_summary",
                detail:
                    "services=\(services) receipts=\(receipts) plugins=\(plugins) tooling=\(tooling) "
                    + "remote=\(remote) root=\(isRoot) sipOff=\(sipOff) amplified=\(amplified)"
            ),
        ]
        if let pk {
            for path in (pk.installerServicePaths + pk.receiptAndHistoryPaths).prefix(10) {
                evidence.append(
                    Evidence(type: "installer_compound_path", path: path, detail: "service/receipt co-presence")
                )
            }
            for n in pk.notes.prefix(4) {
                evidence.append(Evidence(type: "installer_note", detail: n))
            }
        }
        if amplified {
            evidence.append(
                Evidence(
                    type: "compound_amplifier",
                    detail:
                        "amplifiers: remote=\(remote) root=\(isRoot) sipOff=\(sipOff) "
                        + "(engagement ranking only - not an auto-exploit trigger)"
                )
            )
        }
        evidence.append(
            Evidence(
                type: "honesty",
                detail:
                    "Assess never builds pkgs, never invokes installd/package_script_service, "
                    + "never weaponizes InstallerSandboxes or preinstall/postinstall scripts."
            )
        )

        let severity: Severity
        if amplified && services >= 2 && receipts >= 2 {
            severity = .high
        } else if amplified || (services >= 2 && receipts >= 2) {
            severity = .medium
        } else {
            severity = .low
        }

        return [
            Finding(
                id: Self.id,
                title: amplified
                    ? "PackageKit service×receipt compound on amplified host (remote/root/SIP-off)"
                    : "PackageKit installer service × receipt script compound",
                severity: severity,
                confidence: .medium,
                category: .misconfig,
                evidence: evidence,
                attackTechniques: ["T1546", "T1059", "T1072"],
                remediation: [
                    "Correlate package_script_service / installd activity with unexpected receipt changes",
                    "Monitor InstallerSandboxes and /var/db/receipts for post-install script abuse narratives",
                    "Restrict local pkg installs via MDM; prefer notarized MDM-distributed software",
                    "OPSEC: Rootstock Red does not build pkgs or weaponize PackageKit design classes",
                ],
                falsePositiveNotes:
                    "installd and receipts exist on every macOS host. Elevate when services and receipts "
                    + "co-present with remote access, root assess context, or SIP-off.",
                dryRunSafe: true,
                opsecScore: 22,
                esfExpected: ["OPEN", "EXEC", "WRITE"]
            ),
        ]
    }
}
