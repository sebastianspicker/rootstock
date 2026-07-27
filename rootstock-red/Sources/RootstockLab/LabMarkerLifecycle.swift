import Foundation
import RootstockCore

/// Shared plan / install / status / remove lifecycle for reversible lab file markers.
///
/// Technique-specific ids, messages, and marker bodies stay at call sites; only the
/// filesystem and `ActionResult` assembly lives here.
public enum LabMarkerLifecycle: Sendable {
    // MARK: - Filesystem primitives

    /// Create parent directories and write `body` atomically to `markerURL`.
    public static func writeMarker(at markerURL: URL, body: String) throws {
        try FileManager.default.createDirectory(
            at: markerURL.deletingLastPathComponent(),
            withIntermediateDirectories: true
        )
        try Data(body.utf8).write(to: markerURL, options: .atomic)
    }

    /// Whether a marker file currently exists.
    public static func markerExists(at markerURL: URL) -> Bool {
        FileManager.default.fileExists(atPath: markerURL.path)
    }

    /// Delete the marker if present. Returns whether it was present before removal.
    @discardableResult
    public static func removeMarker(at markerURL: URL) throws -> Bool {
        let exists = markerExists(at: markerURL)
        if exists {
            try FileManager.default.removeItem(at: markerURL)
        }
        return exists
    }

    // MARK: - Operation results

    /// Build a plan (always documentation-style) `ActionResult`.
    public static func plan(
        actionId: String,
        markerURL: URL,
        message: String,
        plannedSteps: [String],
        cleanupNotes: [String],
        dryRun: Bool = true
    ) -> ActionResult {
        ActionResult(
            actionId: actionId,
            success: true,
            message: message,
            dryRun: dryRun,
            plannedSteps: plannedSteps,
            cleanupNotes: cleanupNotes,
            artifacts: [markerURL.path]
        )
    }

    /// Install / apply a file marker, honoring dry-run.
    public static func apply(
        actionId: String,
        markerURL: URL,
        body: String,
        dryRun: Bool,
        dryRunMessage: String,
        successMessage: String,
        plannedSteps: [String],
        cleanupNotes: [String]
    ) throws -> ActionResult {
        if dryRun {
            return ActionResult(
                actionId: actionId,
                success: true,
                message: dryRunMessage,
                dryRun: true,
                plannedSteps: plannedSteps,
                cleanupNotes: cleanupNotes,
                artifacts: [markerURL.path]
            )
        }
        try writeMarker(at: markerURL, body: body)
        return ActionResult(
            actionId: actionId,
            success: true,
            message: successMessage,
            dryRun: false,
            plannedSteps: plannedSteps,
            cleanupNotes: cleanupNotes,
            artifacts: [markerURL.path]
        )
    }

    /// Status check for a single marker file.
    public static func status(
        actionId: String,
        markerURL: URL,
        presentMessage: String,
        absentMessage: String,
        plannedSteps: [String]? = nil,
        presentCleanup: [String]? = nil,
        absentCleanup: [String]? = nil
    ) -> ActionResult {
        let exists = markerExists(at: markerURL)
        let steps = plannedSteps ?? ["exists=\(exists)"]
        let cleanup = exists
            ? (presentCleanup ?? ["Delete \(markerURL.path)"])
            : (absentCleanup ?? ["No artifact"])
        return ActionResult(
            actionId: actionId,
            success: true,
            message: exists ? presentMessage : absentMessage,
            dryRun: false,
            plannedSteps: steps,
            cleanupNotes: cleanup,
            artifacts: exists ? [markerURL.path] : []
        )
    }

    /// Remove a marker file, honoring dry-run.
    public static func remove(
        actionId: String,
        markerURL: URL,
        dryRun: Bool,
        dryRunMessage: String,
        successMessage: String,
        plannedSteps: [String]? = nil,
        cleanupNotes: [String]
    ) throws -> ActionResult {
        let exists = markerExists(at: markerURL)
        let steps = plannedSteps ?? ["Delete \(markerURL.path)"]
        if dryRun {
            return ActionResult(
                actionId: actionId,
                success: true,
                message: dryRunMessage,
                dryRun: true,
                plannedSteps: steps,
                cleanupNotes: cleanupNotes,
                artifacts: exists ? [markerURL.path] : []
            )
        }
        if exists {
            try FileManager.default.removeItem(at: markerURL)
        }
        return ActionResult(
            actionId: actionId,
            success: true,
            message: successMessage,
            dryRun: false,
            plannedSteps: steps,
            cleanupNotes: cleanupNotes,
            artifacts: exists ? [markerURL.path] : []
        )
    }

    /// Dispatch a full plan/install/status/remove lifecycle for a single file marker.
    public static func runFileMarker(
        actionId: String,
        operation: LabOperation,
        markerURL: URL,
        body: String,
        contextDryRun: Bool,
        copy: FileMarkerCopy
    ) throws -> ActionResult {
        switch operation {
        case .plan:
            return plan(
                actionId: actionId,
                markerURL: markerURL,
                message: copy.planMessage,
                plannedSteps: copy.planSteps,
                cleanupNotes: copy.planCleanup,
                dryRun: true
            )
        case .install:
            return try apply(
                actionId: actionId,
                markerURL: markerURL,
                body: body,
                dryRun: contextDryRun,
                dryRunMessage: copy.applyDryRunMessage,
                successMessage: copy.applySuccessMessage,
                plannedSteps: copy.applySteps,
                cleanupNotes: copy.applyCleanup
            )
        case .status:
            return status(
                actionId: actionId,
                markerURL: markerURL,
                presentMessage: copy.presentMessage,
                absentMessage: copy.absentMessage,
                plannedSteps: copy.statusSteps,
                presentCleanup: copy.statusPresentCleanup,
                absentCleanup: copy.statusAbsentCleanup
            )
        case .remove:
            let exists = markerExists(at: markerURL)
            return try remove(
                actionId: actionId,
                markerURL: markerURL,
                dryRun: contextDryRun,
                dryRunMessage: copy.removeDryRunMessage(exists),
                successMessage: copy.removeSuccessMessage(exists),
                plannedSteps: copy.removeSteps,
                cleanupNotes: copy.removeCleanup
            )
        }
    }
}

/// Technique-specific strings for a single file-marker lab action.
public struct FileMarkerCopy: Sendable {
    public var planMessage: String
    public var planSteps: [String]
    public var planCleanup: [String]
    public var applyDryRunMessage: String
    public var applySuccessMessage: String
    public var applySteps: [String]
    public var applyCleanup: [String]
    public var presentMessage: String
    public var absentMessage: String
    public var statusSteps: [String]?
    public var statusPresentCleanup: [String]?
    public var statusAbsentCleanup: [String]?
    public var removeDryRunMessage: @Sendable (Bool) -> String
    public var removeSuccessMessage: @Sendable (Bool) -> String
    public var removeSteps: [String]?
    public var removeCleanup: [String]

    public init(
        planMessage: String,
        planSteps: [String],
        planCleanup: [String],
        applyDryRunMessage: String,
        applySuccessMessage: String,
        applySteps: [String],
        applyCleanup: [String],
        presentMessage: String,
        absentMessage: String,
        statusSteps: [String]? = nil,
        statusPresentCleanup: [String]? = nil,
        statusAbsentCleanup: [String]? = nil,
        removeDryRunMessage: @escaping @Sendable (Bool) -> String,
        removeSuccessMessage: @escaping @Sendable (Bool) -> String,
        removeSteps: [String]? = nil,
        removeCleanup: [String]
    ) {
        self.planMessage = planMessage
        self.planSteps = planSteps
        self.planCleanup = planCleanup
        self.applyDryRunMessage = applyDryRunMessage
        self.applySuccessMessage = applySuccessMessage
        self.applySteps = applySteps
        self.applyCleanup = applyCleanup
        self.presentMessage = presentMessage
        self.absentMessage = absentMessage
        self.statusSteps = statusSteps
        self.statusPresentCleanup = statusPresentCleanup
        self.statusAbsentCleanup = statusAbsentCleanup
        self.removeDryRunMessage = removeDryRunMessage
        self.removeSuccessMessage = removeSuccessMessage
        self.removeSteps = removeSteps
        self.removeCleanup = removeCleanup
    }
}
