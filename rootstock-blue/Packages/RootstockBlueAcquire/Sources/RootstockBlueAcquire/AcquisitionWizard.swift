import Foundation
import RootstockBlueCore
import RootstockBlueCase

/// Creates a case and optionally materializes an evidence tree into it.
public struct AcquisitionWizard: Sendable {
    public init() {}

    /// Create a destination case and materialize a rooted source tree into its artifacts.
    /// Does not unlock FileVault or bypass FDA.
    public func run(
        outputCase: URL,
        sourceTree: URL? = nil,
        actor: String = NSUserName()
    ) throws -> CasePackage {
        let fileManager = FileManager.default
        guard !pathEntryExistsOrIsSymlink(outputCase, fileManager: fileManager) else {
            throw RootstockBlueError.caseAlreadyExists(outputCase)
        }

        try fileManager.createDirectory(
            at: outputCase.deletingLastPathComponent(),
            withIntermediateDirectories: true
        )
        let stagedCase = outputCase.deletingLastPathComponent().appendingPathComponent(
            ".\(outputCase.lastPathComponent).rootstock-staging-\(UUID().uuidString)",
            isDirectory: true
        )
        var published = false
        defer {
            if !published, pathEntryExistsOrIsSymlink(stagedCase, fileManager: fileManager) {
                try? fileManager.removeItem(at: stagedCase)
            }
        }

        let pkg = try CasePackage.create(
            at: stagedCase,
            name: outputCase.deletingPathExtension().lastPathComponent
        )

        if let sourceTree {
            let acquisitionRoot = pkg.rootURL.appendingPathComponent(
                "artifacts/logical_acquire",
                isDirectory: true
            )
            let result = try LogicalAcquire.materializeFixtureBundle(
                from: sourceTree,
                to: acquisitionRoot,
                actor: actor
            )
            try pkg.appendCustody(
                CustodyEvent(
                    actor: actor,
                    action: "acquisition_wizard",
                    detail: "Materialized \(result.filesCopied) files from \(sourceTree.path) into logical_acquire (hashes=\(result.custodyHashes.count))"
                )
            )
        } else {
            try pkg.appendCustody(
                CustodyEvent(
                    actor: actor,
                    action: "acquisition_wizard",
                    detail: "Case created without a source tree"
                )
            )
        }
        try pkg.updateHashes()

        guard !pathEntryExistsOrIsSymlink(outputCase, fileManager: fileManager) else {
            throw RootstockBlueError.caseAlreadyExists(outputCase)
        }
        try fileManager.moveItem(at: stagedCase, to: outputCase)
        published = true
        return try CasePackage.open(at: outputCase)
    }

    /// Return the acquisition preflight summary.
    public func preflightLines() -> [String] {
        AcquisitionPreflight.report().summaryLines
    }

    private func pathEntryExistsOrIsSymlink(_ url: URL, fileManager: FileManager) -> Bool {
        fileManager.fileExists(atPath: url.path)
            || (try? fileManager.destinationOfSymbolicLink(atPath: url.path)) != nil
    }
}
