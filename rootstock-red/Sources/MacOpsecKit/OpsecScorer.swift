import Foundation
import RootstockCore

/// Computes 0–100 OPSEC noise scores (higher = noisier).
public struct OpsecScorer: Sendable {
    public var weights: OpsecWeights

    public init(weights: OpsecWeights = .default) {
        self.weights = weights
    }

    public func score(_ signals: OpsecSignals) -> Int {
        var total = 0
        total += min(signals.processSpawns, 5) * weights.processSpawn
        total += min(signals.sensitiveFileOpens, 5) * weights.sensitiveFileOpen
        total += min(signals.tccDomains.count, 4) * weights.tccDomainTouch
        if signals.networkEgress { total += weights.networkEgress }
        if signals.userVisible { total += weights.userVisible }
        // Distinct ESF classes (exclude synthetic USER_PROMPT which is covered by userVisible).
        let esfCount = Set(
            signals.esfEventClasses.filter { !$0.uppercased().contains("USER_PROMPT") }
        ).count
        total += min(esfCount, 6) * weights.esfEventClass
        total += min(signals.sensitivePathReads, 5) * weights.sensitivePathRead
        if signals.appleEvents { total += weights.appleEvents }
        return min(100, total)
    }

    /// Human-readable score breakdown for evidence / debugging.
    public func breakdown(_ signals: OpsecSignals) -> String {
        let esf = signals.esfEventClasses.isEmpty
            ? "none"
            : signals.esfEventClasses.joined(separator: ",")
        let tcc = signals.tccDomains.isEmpty
            ? "none"
            : signals.tccDomains.joined(separator: ",")
        return [
            "score=\(score(signals))",
            "esf=[\(esf)]",
            "tcc=[\(tcc)]",
            "pathOpens=\(signals.sensitiveFileOpens)",
            "sensitiveReads=\(signals.sensitivePathReads)",
            "net=\(signals.networkEgress)",
            "userVisible=\(signals.userVisible)",
            "appleEvents=\(signals.appleEvents)",
            "spawns=\(signals.processSpawns)",
        ].joined(separator: " ")
    }

    /// Attach score (always) and enrich ESF expectations from category when empty.
    public func annotate(_ finding: Finding) -> Finding {
        var copy = finding

        if copy.esfExpected.isEmpty {
            copy.esfExpected = OpsecESFCatalog.defaultShortClasses(for: copy.category)
        }

        let pathEvidence = copy.evidence.compactMap(\.path)
        let sensitiveReads = pathEvidence.filter { OpsecESFCatalog.isSensitivePath($0) }.count
        let notifyClasses = OpsecESFCatalog.notifyEventNames(from: copy.esfExpected)

        let tccLower = copy.tccDomains.map { $0.lowercased() }
        let appleEvents =
            tccLower.contains { $0.contains("appleevent") || $0.contains("automation") }

        let networkish =
            copy.category == .network
            || copy.esfExpected.contains {
                let u = $0.uppercased()
                return u.contains("CONNECT") || u.contains("NETWORK") || u == "LOOKUP"
            }

        let userVisible =
            copy.esfExpected.contains {
                $0.uppercased().contains("USER_PROMPT")
            }

        let signals = OpsecSignals(
            processSpawns: copy.esfExpected.contains {
                let u = $0.uppercased()
                return u == "EXEC" || u == "FORK" || u.contains("NOTIFY_EXEC") || u.contains("NOTIFY_FORK")
            } ? 1 : 0,
            sensitiveFileOpens: pathEvidence.count,
            tccDomains: copy.tccDomains,
            networkEgress: networkish,
            userVisible: userVisible,
            esfEventClasses: notifyClasses,
            sensitivePathReads: sensitiveReads,
            appleEvents: appleEvents
        )

        let scoreValue = score(signals)
        copy.opsecScore = scoreValue

        // Schema-compatible optional note (Evidence.type = "opsec").
        if !copy.evidence.contains(where: { $0.type == "opsec" }) {
            copy.evidence.append(
                Evidence(
                    type: "opsec",
                    detail: breakdown(signals)
                )
            )
        }

        return copy
    }

    public func annotateAll(_ findings: [Finding]) -> [Finding] {
        findings.map { annotate($0) }
    }
}
