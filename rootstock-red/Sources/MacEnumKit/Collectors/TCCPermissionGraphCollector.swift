import Foundation
import RootstockCore

/// Multi-domain TCC permission graph (non-prompting, assess-safe).
///
/// Research basis: SwiftBelt path probes; PEASS TCC themes; Screen/AX/Automation research.
/// Safety and behavior: domain-level signal graph into `TCCState.domainSignals` + notes;
/// never dumps TCC.db rows; never forces permission dialogs; compounds domains for depth.
public struct TCCPermissionGraphCollector: Collector {
    public static let id = "collect.tcc_permission_graph"
    public static let cost: CollectorCost = .medium

    public init() {}

    public func collect(context: EvaluationContext) async throws -> CollectedState {
        let fm = FileManager.default
        let home = fm.homeDirectoryForCurrentUser
        var notes: [String] = [
            "TCC permission graph: non-prompting domain heuristics only",
        ]
        var domainSignals: [String] = []

        // MARK: Screen Recording - screencapture binary presence + recent capture dirs
        let screenCaptureBin = "/usr/sbin/screencapture"
        let screenCapturePresent = fm.fileExists(atPath: screenCaptureBin)
        let pictures = home.appendingPathComponent("Pictures")
        let desktop = home.appendingPathComponent("Desktop")
        var screenLikely: String = "unknown"
        if screenCapturePresent {
            // Listability of Desktop/Pictures is weak signal only; do not open screen APIs.
            let deskOK = (try? fm.contentsOfDirectory(atPath: desktop.path)) != nil
            let picOK = (try? fm.contentsOfDirectory(atPath: pictures.path)) != nil
            if deskOK || picOK {
                screenLikely = "tool_present_folders_listable"
            } else {
                screenLikely = "tool_present"
            }
        } else {
            screenLikely = "tool_absent"
        }
        domainSignals.append("ScreenCapture=\(screenLikely)")
        notes.append("ScreenCapture signal=\(screenLikely) bin=\(screenCapturePresent)")

        // MARK: Accessibility - AX-related support paths (no AXIsProcessTrusted prompt path)
        let axCandidates: [String] = [
            home.appendingPathComponent("Library/Application Support/com.apple.TCC").path,
            "/Library/Application Support/com.apple.TCC",
        ]
        var axSignal = "unknown"
        let anyAXPath = axCandidates.contains { fm.fileExists(atPath: $0) }
        if anyAXPath {
            axSignal = "tcc_support_paths_present"
        }
        // Running apps that commonly hold AX (inventory only).
        domainSignals.append("Accessibility=\(axSignal)")
        notes.append("Accessibility signal=\(axSignal)")

        // MARK: Automation / Apple Events - osascript presence
        let osa = "/usr/bin/osascript"
        let osaPresent = fm.fileExists(atPath: osa)
        domainSignals.append("Automation=\(osaPresent ? "osascript_present" : "osascript_absent")")
        notes.append("Automation osascript present=\(osaPresent)")

        // MARK: Camera / Microphone - device node / framework presence only (no capture)
        let avFoundation = "/System/Library/Frameworks/AVFoundation.framework"
        let avPresent = fm.fileExists(atPath: avFoundation)
        domainSignals.append("CameraMic=\(avPresent ? "avfoundation_present" : "unknown")")
        notes.append("Camera/Mic: AVFoundation present=\(avPresent) (no device open)")

        // MARK: FDA (lightweight, complementary to TCCCollector)
        let systemTCC = "/Library/Application Support/com.apple.TCC/TCC.db"
        let systemTCCReadable = fm.isReadableFile(atPath: systemTCC)
        let safariHistory = home.appendingPathComponent("Library/Safari/History.db").path
        let safariReadable = fm.isReadableFile(atPath: safariHistory)
        let fdaSignal: String
        if systemTCCReadable {
            fdaSignal = "likely"
        } else if safariReadable {
            fdaSignal = "possible"
        } else {
            fdaSignal = "not_indicated"
        }
        domainSignals.append("FullDiskAccess=\(fdaSignal)")
        notes.append("FDA graph signal=\(fdaSignal)")

        // MARK: Files and Folders (Desktop/Documents/Downloads listability)
        let folders: [(String, URL)] = [
            ("Desktop", home.appendingPathComponent("Desktop")),
            ("Documents", home.appendingPathComponent("Documents")),
            ("Downloads", home.appendingPathComponent("Downloads")),
        ]
        var listable: [String] = []
        for (name, url) in folders {
            if (try? fm.contentsOfDirectory(atPath: url.path)) != nil {
                listable.append(name)
            }
        }
        domainSignals.append(
            "FilesAndFolders=\(listable.isEmpty ? "none_listable" : listable.joined(separator: "+"))"
        )
        notes.append("Files-and-Folders listable: \(listable.joined(separator: ",").ifEmpty("none"))")

        // Collector note for ScreenAccessibilitySurfaceVector compound.
        let screenNote = "screen_recording=\(screenLikely)|accessibility=\(axSignal)"
        notes.append("screen_ax_compound=\(screenNote)")

        var state = CollectedState()
        // Merge-friendly TCC fragment: graph collector fills domainSignals; FDA collector may win fullDiskAccess.
        let fdaLikely: Bool? =
            systemTCCReadable ? true : (fdaSignal == "not_indicated" ? false : nil)
        state.tcc = TCCState(
            fullDiskAccessLikely: fdaLikely,
            notes: notes,
            probeMethod: "tcc_permission_graph_domains_v1",
            domainSignals: domainSignals
        )
        state.collectorNotes[Self.id] = domainSignals.joined(separator: ";")
        state.collectorNotes["tcc.screen_accessibility"] = screenNote
        return state
    }
}

private extension String {
    func ifEmpty(_ fallback: String) -> String {
        isEmpty ? fallback : self
    }
}
