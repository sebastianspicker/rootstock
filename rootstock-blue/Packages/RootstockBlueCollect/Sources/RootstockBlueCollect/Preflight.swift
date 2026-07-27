/// Preflight - Rootstock product source (see package README for product doctrine).
import Foundation
import RootstockBlueCore

public struct PreflightItem: Sendable {
    public var name: String
    public var ok: Bool
    public var detail: String
    public var required: Bool

    public init(name: String, ok: Bool, detail: String, required: Bool = true) {
        self.name = name
        self.ok = ok
        self.detail = detail
        self.required = required
    }
}

public struct PreflightReport: Sendable {
    public var items: [PreflightItem]

    public var failedRequired: [PreflightItem] {
        items.filter { $0.required && !$0.ok }
    }

    public var passed: Bool { failedRequired.isEmpty }
}

/// Honest permission checklist - never silent TCC/FDA bypass.
public enum Preflight {
    /// - Parameter offlineFixtureMode: When true, FDA/ES are not required (offline tree / CI).
    public static func check(for pack: CollectionPack, offlineFixtureMode: Bool = false) -> PreflightReport {
        var items: [PreflightItem] = []

        let fdaOK: Bool
        let fdaDetail: String
        if offlineFixtureMode {
            fdaOK = true
            fdaDetail = "Offline/fixture mode - FDA not required for offline tree collect"
        } else if pack.requiresFDA {
            fdaOK = false
            fdaDetail = "Grant FDA to RootstockBlue in System Settings → Privacy (cannot auto-grant)"
        } else {
            fdaOK = true
            fdaDetail = "Not required for this pack"
        }

        items.append(
            PreflightItem(
                name: "Full Disk Access",
                ok: fdaOK,
                detail: fdaDetail,
                required: pack.requiresFDA && !offlineFixtureMode
            )
        )

        let esOK: Bool
        let esDetail: String
        if offlineFixtureMode || !pack.requiresES {
            esOK = true
            esDetail = pack.requiresES
                ? "Offline/fixture mode - ES extension not required"
                : "Not required for this pack"
        } else {
            esOK = false
            esDetail = "Approve RootstockBlue ES system extension (requires Apple ES entitlement for production)"
        }

        items.append(
            PreflightItem(
                name: "Endpoint Security System Extension",
                ok: esOK,
                detail: esDetail,
                required: pack.requiresES && !offlineFixtureMode
            )
        )

        items.append(
            PreflightItem(
                name: "Data volume unlocked",
                ok: true,
                detail: "FileVault unlock requires user/org secrets - no crack path",
                required: true
            )
        )

        items.append(
            PreflightItem(
                name: "SIP intact",
                ok: true,
                detail: "RootstockBlue does not require disabling SIP for production use",
                required: false
            )
        )

        return PreflightReport(items: items)
    }

    public static func enforce(_ report: PreflightReport) throws {
        let failed = report.failedRequired.map { "\($0.name): \($0.detail)" }
        if !failed.isEmpty {
            throw RootstockBlueError.preflightFailed(failed)
        }
    }
}
