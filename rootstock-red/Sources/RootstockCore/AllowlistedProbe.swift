import Foundation

/// Result of a single allowlisted status probe.
public struct AllowlistedProbeResult: Sendable, Equatable {
    public var executable: String
    public var arguments: [String]
    public var exitCode: Int32?
    public var stdout: String
    public var stderr: String
    public var timedOut: Bool
    public var errorDescription: String?

    public init(
        executable: String,
        arguments: [String],
        exitCode: Int32? = nil,
        stdout: String = "",
        stderr: String = "",
        timedOut: Bool = false,
        errorDescription: String? = nil
    ) {
        self.executable = executable
        self.arguments = arguments
        self.exitCode = exitCode
        self.stdout = stdout
        self.stderr = stderr
        self.timedOut = timedOut
        self.errorDescription = errorDescription
    }

    public var combinedOutput: String {
        let out = stdout.trimmingCharacters(in: .whitespacesAndNewlines)
        let err = stderr.trimmingCharacters(in: .whitespacesAndNewlines)
        if out.isEmpty { return err }
        if err.isEmpty { return out }
        return out + "\n" + err
    }
}

/// Hard-coded, read-only status CLI allowlist for assess mode.
///
/// Unlike `ProcessRunner` (lab/agent only), this may run in assess - but only for the
/// exact (executable, arguments) pairs listed below. No arbitrary shell, no PATH lookup.
public enum AllowlistedProbe: Sendable {
    public enum Command: String, Sendable, CaseIterable {
        case csrutilStatus
        case spctlStatus
        case fdesetupStatus

        public var executable: String {
            switch self {
            case .csrutilStatus: return "/usr/bin/csrutil"
            case .spctlStatus: return "/usr/sbin/spctl"
            case .fdesetupStatus: return "/usr/bin/fdesetup"
            }
        }

        public var arguments: [String] {
            switch self {
            case .csrutilStatus: return ["status"]
            case .spctlStatus: return ["--status"]
            case .fdesetupStatus: return ["status"]
            }
        }
    }

    /// Default wall-clock timeout for status probes (seconds).
    public static let defaultTimeoutSeconds: TimeInterval = 3

    /// Run a single allowlisted status command with a short timeout.
    public static func run(
        _ command: Command,
        timeoutSeconds: TimeInterval = defaultTimeoutSeconds
    ) -> AllowlistedProbeResult {
        let executable = command.executable
        let arguments = command.arguments

        guard FileManager.default.isExecutableFile(atPath: executable) else {
            return AllowlistedProbeResult(
                executable: executable,
                arguments: arguments,
                errorDescription: "executable missing or not executable"
            )
        }

        let process = Process()
        process.executableURL = URL(fileURLWithPath: executable)
        process.arguments = arguments

        let outPipe = Pipe()
        let errPipe = Pipe()
        process.standardOutput = outPipe
        process.standardError = errPipe
        process.standardInput = FileHandle.nullDevice

        do {
            try process.run()
        } catch {
            return AllowlistedProbeResult(
                executable: executable,
                arguments: arguments,
                errorDescription: "failed to launch: \(error.localizedDescription)"
            )
        }

        let deadline = Date().addingTimeInterval(timeoutSeconds)
        while process.isRunning, Date() < deadline {
            Thread.sleep(forTimeInterval: 0.05)
        }

        if process.isRunning {
            process.terminate()
            // Brief grace, then hard kill if needed.
            let killDeadline = Date().addingTimeInterval(0.5)
            while process.isRunning, Date() < killDeadline {
                Thread.sleep(forTimeInterval: 0.05)
            }
            if process.isRunning {
                process.interrupt()
            }
            _ = try? outPipe.fileHandleForReading.readToEnd()
            _ = try? errPipe.fileHandleForReading.readToEnd()
            return AllowlistedProbeResult(
                executable: executable,
                arguments: arguments,
                timedOut: true,
                errorDescription: "timed out after \(timeoutSeconds)s"
            )
        }

        let stdoutData = outPipe.fileHandleForReading.readDataToEndOfFile()
        let stderrData = errPipe.fileHandleForReading.readDataToEndOfFile()
        let stdout = String(data: stdoutData, encoding: .utf8) ?? ""
        let stderr = String(data: stderrData, encoding: .utf8) ?? ""

        return AllowlistedProbeResult(
            executable: executable,
            arguments: arguments,
            exitCode: process.terminationStatus,
            stdout: stdout,
            stderr: stderr
        )
    }
}
