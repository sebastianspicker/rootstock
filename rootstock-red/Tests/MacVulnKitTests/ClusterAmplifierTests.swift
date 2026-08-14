import RootstockCore
import XCTest

@testable import MacVulnKit

final class ClusterAmplifierTests: XCTestCase {
  func testClusterAmplifierLabelsTruthTable() {
    let cases: [(name: String, expected: [String], configure: (inout CollectedState) -> Void)] = [
      ("baseline", [], { _ in }),
      (
        "SSH", ["remote"],
        { state in
          state.network = NetworkState(reachability: .init(remoteLoginSSH: true))
        }
      ),
      (
        "ARD", ["remote"],
        { state in
          state.network = NetworkState(reachability: .init(screenSharingARD: true))
        }
      ),
      (
        "FDA", ["fda"],
        { state in
          state.tcc = TCCState(fullDiskAccessLikely: true)
        }
      ),
      (
        "SIP off", ["sip_off"],
        { state in
          state.protections = ProtectionsState(sipEnabled: false)
        }
      ),
      (
        "Gatekeeper off", ["gk_off"],
        { state in
          state.protections = ProtectionsState(gatekeeperEnabled: false)
        }
      ),
      (
        "empty ESF paths", ["sensor_gap"],
        { state in
          state.esf = ESFPostureState(clientPaths: [])
        }
      ),
      (
        "no present security products", ["products_absent"],
        { state in
          state.securityProducts = []
        }
      ),
    ]

    for testCase in cases {
      var state = baselineState()
      testCase.configure(&state)
      XCTAssertEqual(clusterAmplifierLabels(state: state), testCase.expected, testCase.name)
    }
  }

  func testClusterAmplifierLabelsPreserveLabelOrder() {
    var state = baselineState()
    state.network = NetworkState(reachability: .init(remoteLoginSSH: true))
    state.tcc = TCCState(fullDiskAccessLikely: true)
    state.protections = ProtectionsState(sipEnabled: false, gatekeeperEnabled: false)
    state.esf = ESFPostureState(clientPaths: [])
    state.securityProducts = []

    XCTAssertEqual(
      clusterAmplifierLabels(state: state),
      ["remote", "fda", "sip_off", "gk_off", "sensor_gap", "products_absent"]
    )
  }

  private func baselineState() -> CollectedState {
    var state = CollectedState()
    state.securityProducts = [
      SecurityProductHit(
        name: "Synthetic EDR", path: "/Applications/SyntheticEDR.app", present: true)
    ]
    return state
  }
}
