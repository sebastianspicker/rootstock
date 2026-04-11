import XCTest
import Foundation
@testable import ProcessSnapshot
import Models

final class ProcessSnapshotTests: XCTestCase {

    func testRunningProcessNodeType() {
        let proc = RunningProcess(pid: 1234, user: "root", command: "/usr/sbin/httpd", bundleId: nil)
        XCTAssertEqual(proc.nodeType, "RunningProcess")
    }

    func testRunningProcessJSONEncoding() throws {
        let proc = RunningProcess(pid: 42, user: "admin", command: "/Applications/Safari.app/Contents/MacOS/Safari", bundleId: "com.apple.Safari")
        let data = try JSONEncoder().encode(proc)
        let json = try JSONSerialization.jsonObject(with: data) as! [String: Any]
        XCTAssertEqual(json["pid"] as? Int, 42)
        XCTAssertEqual(json["bundle_id"] as? String, "com.apple.Safari")
    }

    func testParsePsOutputBasic() {
        let output = """
          PID USER             COMM
            1 root             /sbin/launchd
          123 admin            /Applications/Safari.app/Contents/MacOS/Safari
          456 admin            /usr/sbin/httpd
        """
        let apps = [
            Application(
                name: "Safari", bundleId: "com.apple.Safari",
                path: "/Applications/Safari.app",
                version: nil, teamId: nil,
                hardenedRuntime: true, libraryValidation: true,
                isElectron: false, isSystem: true, signed: true
            ),
        ]
        let processes = ProcessSnapshotDataSource.parsePsOutput(output, knownApps: apps)
        // Only processes with resolved bundle IDs are emitted
        XCTAssertEqual(processes.count, 1)
        XCTAssertEqual(processes[0].bundleId, "com.apple.Safari")
        XCTAssertEqual(processes[0].pid, 123)
        XCTAssertEqual(processes[0].user, "admin")
    }

    func testParsePsOutputEmpty() {
        let processes = ProcessSnapshotDataSource.parsePsOutput("", knownApps: [])
        XCTAssertTrue(processes.isEmpty)
    }

    func testProcessSnapshotDataSourceMetadata() {
        let ds = ProcessSnapshotDataSource()
        XCTAssertEqual(ds.name, "Process Snapshot")
        XCTAssertFalse(ds.requiresElevation)
    }
}
