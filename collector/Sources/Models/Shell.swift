import Foundation
import Darwin

private final class PipeCapture: @unchecked Sendable {
    let pipe = Pipe()

    private let queue: DispatchQueue
    private let source: DispatchSourceRead
    private let stopped = DispatchSemaphore(value: 0)
    private let lock = NSLock()
    private let fileDescriptor: Int32
    private var data = Data()

    init(label: String) {
        queue = DispatchQueue(label: label)
        fileDescriptor = pipe.fileHandleForReading.fileDescriptor
        source = DispatchSource.makeReadSource(fileDescriptor: fileDescriptor, queue: queue)

        let flags = fcntl(fileDescriptor, F_GETFL)
        if flags >= 0 {
            _ = fcntl(fileDescriptor, F_SETFL, flags | O_NONBLOCK)
        }

        source.setEventHandler { [weak self] in
            guard let self else { return }
            if self.drainAvailableBytes() {
                self.source.cancel()
            }
        }
        source.setCancelHandler { [weak self] in
            guard let self else { return }
            _ = self.drainAvailableBytes()
            try? self.pipe.fileHandleForReading.close()
            self.stopped.signal()
        }
        source.resume()
    }

    func finish() -> Data {
        source.cancel()
        stopped.wait()
        lock.lock()
        defer { lock.unlock() }
        return data
    }

    /// Drain without blocking so descendant-held write descriptors cannot delay return.
    /// Returns true only after observing EOF or a terminal read error.
    private func drainAvailableBytes() -> Bool {
        var bytes = [UInt8](repeating: 0, count: 64 * 1024)
        while true {
            let count = bytes.withUnsafeMutableBytes { buffer in
                Darwin.read(fileDescriptor, buffer.baseAddress, buffer.count)
            }
            if count > 0 {
                lock.lock()
                data.append(contentsOf: bytes.prefix(Int(count)))
                lock.unlock()
            } else if count == 0 {
                return true
            } else if errno == EINTR {
                continue
            } else {
                return errno != EAGAIN && errno != EWOULDBLOCK
            }
        }
    }
}

public struct ShellResult: Sendable {
    public let stdout: String
    public let stderr: String
    public let terminationStatus: Int32
    public let timedOut: Bool
}

/// Shared helper for running subprocesses. Used by data sources that invoke
/// system commands (dscl, launchctl, codesign, profiles, etc.).
public enum Shell {
    /// Every collector command has a finite runtime budget so a stalled system
    /// utility cannot prevent the scan from completing.
    public static let defaultTimeoutSeconds: TimeInterval = 15

    /// Limit concurrently-running collector utilities. Several data sources
    /// invoke system tools, and unbounded fan-out can exhaust file descriptors.
    private static let processSlots = DispatchSemaphore(value: 4)

    /// Run a command and return stdout as a trimmed String, or nil on failure / non-zero exit.
    public static func run(_ path: String, _ arguments: [String]) -> String? {
        run(path, arguments, timeoutSeconds: defaultTimeoutSeconds)
    }

    /// Run a command with an optional timeout and return stdout as a trimmed String.
    public static func run(_ path: String, _ arguments: [String], timeoutSeconds: TimeInterval?) -> String? {
        guard let result = runProcess(path, arguments, timeoutSeconds: timeoutSeconds),
              result.terminationStatus == 0,
              !result.timedOut else {
            return nil
        }
        return result.stdout.trimmingCharacters(in: .whitespacesAndNewlines)
    }

    /// Run a command, draining stdout and stderr concurrently to avoid pipe deadlocks.
    public static func runProcess(
        _ path: String,
        _ arguments: [String],
        timeoutSeconds: TimeInterval? = defaultTimeoutSeconds
    ) -> ShellResult? {
        let deadline = timeoutSeconds.map { DispatchTime.now() + max(0, $0) }
        if let deadline {
            guard processSlots.wait(timeout: deadline) == .success else { return nil }
        } else {
            processSlots.wait()
        }
        defer { processSlots.signal() }

        let process = Process()
        process.executableURL = URL(fileURLWithPath: path)
        process.arguments = arguments

        let stdoutCapture = PipeCapture(label: "rootstock.shell.stdout")
        let stderrCapture = PipeCapture(label: "rootstock.shell.stderr")
        process.standardOutput = stdoutCapture.pipe
        process.standardError = stderrCapture.pipe

        let completed = DispatchSemaphore(value: 0)
        process.terminationHandler = { _ in completed.signal() }

        do {
            try process.run()
        } catch {
            _ = stdoutCapture.finish()
            _ = stderrCapture.finish()
            return nil
        }

        let timedOut = waitForCompletion(
            of: process,
            completionSignal: completed,
            deadline: deadline
        )
        let stdoutData = stdoutCapture.finish()
        let stderrData = stderrCapture.finish()

        return ShellResult(
            stdout: String(data: stdoutData, encoding: .utf8) ?? "",
            stderr: String(data: stderrData, encoding: .utf8) ?? "",
            terminationStatus: process.terminationStatus,
            timedOut: timedOut
        )
    }

    private static func waitForCompletion(
        of process: Process,
        completionSignal: DispatchSemaphore,
        deadline: DispatchTime?
    ) -> Bool {
        guard let deadline else {
            process.waitUntilExit()
            return false
        }

        if completionSignal.wait(timeout: deadline) == .timedOut {
            if process.isRunning {
                process.terminate()
            }
            if completionSignal.wait(timeout: .now() + .milliseconds(100)) == .timedOut,
               process.isRunning {
                _ = Darwin.kill(process.processIdentifier, SIGKILL)
            }
            process.waitUntilExit()
            return true
        }
        process.waitUntilExit()
        return false
    }

    /// Run a command and return stderr as a trimmed String, or nil on failure / non-zero exit.
    /// Useful for tools like `codesign -d` that write informational output to stderr.
    public static func runStderr(_ path: String, _ arguments: [String]) -> String? {
        guard let result = runProcess(path, arguments),
              result.terminationStatus == 0,
              !result.timedOut else {
            return nil
        }
        return result.stderr.trimmingCharacters(in: .whitespacesAndNewlines)
    }

    /// Parse Data as a plist dictionary. Returns nil if parsing fails.
    public static func parsePlistDict(from data: Data) -> [String: Any]? {
        var format = PropertyListSerialization.PropertyListFormat.xml
        return try? PropertyListSerialization.propertyList(
            from: data, options: [], format: &format
        ) as? [String: Any]
    }

    /// Returns true if the command exits with status 0 (stdout/stderr discarded).
    public static func succeeds(_ path: String, _ arguments: [String]) -> Bool {
        guard let result = runProcess(path, arguments) else { return false }
        return result.terminationStatus == 0 && !result.timedOut
    }
}
