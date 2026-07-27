import SwiftUI

struct CaseTimelineView: View {
    var body: some View {
        WorkspacePage(
            eyebrow: "Normalized evidence",
            title: "Case timeline",
            summary: "Review the ordered merge of live ES events, offline parsers, and unified-log evidence using stable entity identifiers."
        ) {
            MetricStrip(metrics: [
                ("Events", "0", .neutral),
                ("Sources", "0", .neutral),
                ("Earliest", "—", .neutral),
                ("Latest", "—", .neutral),
            ])

            InstrumentSection("Event stream", detail: "Chronological") {
                EmptyEvidenceView(
                    title: "No events yet",
                    description: "Record a session or parse an artifact tree into the current case.",
                    systemImage: "timeline.selection"
                )
            }

            CommandLine(command: "rootstock-blue timeline ./demo.rsbcase --limit 40")
        }
    }
}
