import Foundation
import RootstockCore

/// Ranked LOOBin selection with noise and TCC-impact heuristics.
public struct RankedPlanEntry: Sendable, Equatable {
    public var loobin: LOOBin
    public var goal: LOLPlanner.Goal
    /// 0–100; higher = noisier / more OPSEC risk.
    public var noiseScore: Int
    public var tccImpact: [String]
    public var rankReason: String

    public init(
        loobin: LOOBin,
        goal: LOLPlanner.Goal,
        noiseScore: Int,
        tccImpact: [String] = [],
        rankReason: String = ""
    ) {
        self.loobin = loobin
        self.goal = goal
        self.noiseScore = noiseScore
        self.tccImpact = tccImpact
        self.rankReason = rankReason
    }

    /// Codable snapshot for CollectedState.
    public func asPlanEntry() -> LOLPlanEntry {
        LOLPlanEntry(
            name: loobin.name,
            path: loobin.path,
            goal: goal.rawValue,
            noiseScore: noiseScore,
            tccImpact: tccImpact,
            rankReason: rankReason
        )
    }
}

/// Goal-driven LOOBin planner: ranks present catalog entries by noise (quieter first).
public struct LOLPlanner: Sendable {
    public enum Goal: String, Sendable, CaseIterable {
        case download
        case execute
        case exfil
        case persist
        case discovery
    }

    public var catalog: LOOBinCatalog

    public init(catalog: LOOBinCatalog) {
        self.catalog = catalog
    }

    /// Rank present LOOBins suitable for `goal`, sorted by noise ascending (quieter first).
    public func plan(goal: Goal) -> [RankedPlanEntry] {
        let inventory = catalog.inventory().filter(\.present)
        let presentNames = Set(inventory.map(\.name))
        let candidates = catalog.entries.filter { presentNames.contains($0.name) }.filter {
            Self.matches(goal: goal, bin: $0)
        }

        return candidates.map { bin in
            let noise = Self.noiseScore(for: bin)
            let tcc = Self.tccImpact(for: bin)
            let reason = Self.rankReason(for: bin, goal: goal, noise: noise, tcc: tcc)
            return RankedPlanEntry(
                loobin: bin,
                goal: goal,
                noiseScore: noise,
                tccImpact: tcc,
                rankReason: reason
            )
        }
        .sorted { lhs, rhs in
            if lhs.noiseScore != rhs.noiseScore {
                return lhs.noiseScore < rhs.noiseScore
            }
            return lhs.loobin.name < rhs.loobin.name
        }
    }

    /// Plans for multiple goals, each capped at `topN` quietest entries.
    public func plan(goals: [Goal], topN: Int = 5) -> [RankedPlanEntry] {
        goals.flatMap { Array(plan(goal: $0).prefix(topN)) }
    }

    // MARK: - Heuristics

    private static func matches(goal: Goal, bin: LOOBin) -> Bool {
        let tactics = Set(bin.tactics.map { $0.lowercased() })
        switch goal {
        case .discovery:
            return tactics.contains(where: { $0.contains("discovery") })
                || ["system_profiler", "mdfind", "codesign", "profiles"].contains(bin.name)
        case .persist:
            return tactics.contains(where: { $0.contains("persist") })
                || ["launchctl", "profiles"].contains(bin.name)
        case .execute:
            return tactics.contains(where: { $0.contains("execution") })
                || ["osascript", "launchctl"].contains(bin.name)
        case .exfil, .download:
            return tactics.contains(where: {
                $0.contains("collection") || $0.contains("discovery") || $0.contains("credential")
            })
                || ["screencapture", "sqlite3", "security", "mdfind"].contains(bin.name)
        }
    }

    /// Noise score 0–100. Higher = more telemetry / human-visible risk.
    public static func noiseScore(for bin: LOOBin) -> Int {
        switch bin.name.lowercased() {
        case "system_profiler": return 15
        case "mdfind": return 40
        case "xattr": return 30
        case "codesign": return 35
        case "launchctl": return 50
        case "profiles": return 55
        case "sqlite3": return 55
        case "security": return 78
        case "osascript": return 85
        case "screencapture": return 90
        default:
            // Tactic-based fallback.
            let tactics = bin.tactics.map { $0.lowercased() }
            if tactics.contains(where: { $0.contains("credential") }) { return 70 }
            if tactics.contains(where: { $0.contains("execution") }) { return 65 }
            if tactics.contains(where: { $0.contains("persist") }) { return 55 }
            if tactics.contains(where: { $0.contains("collection") }) { return 60 }
            if tactics.contains(where: { $0.contains("discovery") }) { return 35 }
            return 50
        }
    }

    public static func tccImpact(for bin: LOOBin) -> [String] {
        switch bin.name.lowercased() {
        case "screencapture":
            return ["Screen Recording"]
        case "osascript":
            return ["Automation", "Accessibility"]
        case "security":
            return ["Keychain"]
        case "sqlite3":
            return ["Full Disk Access"]
        case "mdfind":
            return []
        case "system_profiler":
            return []
        case "profiles":
            return []
        case "launchctl":
            return []
        case "xattr", "codesign":
            return []
        default:
            return []
        }
    }

    private static func rankReason(
        for bin: LOOBin,
        goal: Goal,
        noise: Int,
        tcc: [String]
    ) -> String {
        let band: String
        switch noise {
        case 0..<30: band = "low noise"
        case 30..<60: band = "medium noise"
        case 60..<80: band = "high noise"
        default: band = "very high noise"
        }
        let tccPart = tcc.isEmpty ? "no TCC domain" : "TCC: \(tcc.joined(separator: ", "))"
        let tactics = bin.tactics.isEmpty ? "unspecified tactics" : bin.tactics.joined(separator: "/")
        return "\(goal.rawValue): \(bin.name) \(band) (\(noise)) · \(tccPart) · \(tactics)"
    }
}
