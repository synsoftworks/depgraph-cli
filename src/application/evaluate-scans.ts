import type {
  CoverageSignalFrequency,
  EvaluationSummary,
  MetadataCoverageSummary,
  ReviewEvent,
  SignalFrequency,
} from '../domain/contracts.js'
import type { PackageNode, RiskSignal } from '../domain/entities.js'
import type { ScanReviewStore } from '../domain/ports.js'

interface EvaluateScansDependencies {
  reviewStore: ScanReviewStore
}

export function createEvaluateScansUseCase({ reviewStore }: EvaluateScansDependencies) {
  return async function evaluateScans(): Promise<EvaluationSummary> {
    const [scanRecords, reviewEvents] = await Promise.all([
      reviewStore.listScanRecords(),
      reviewStore.listReviewEvents(),
    ])

    const latestReviewByRecordId = selectLatestReviews(reviewEvents)
    const signalCounts = new Map<string, number>()
    const knownDownloadsSignalCounts = new Map<string, number>()
    const missingDownloadsSignalCounts = new Map<string, number>()
    const knownDependentsSignalCounts = new Map<string, number>()
    const missingDependentsSignalCounts = new Map<string, number>()
    let totalNodes = 0
    let nodesMissingWeeklyDownloads = 0
    let nodesMissingDependentsCount = 0
    let maliciousCount = 0
    let benignCount = 0
    let needsReviewCount = 0

    for (const record of scanRecords) {
      // This is feature-surface observability for the dataset, not a quality metric.
      for (const node of flattenNodes(record.root)) {
        totalNodes += 1

        if (node.weekly_downloads === null) {
          nodesMissingWeeklyDownloads += 1
          collectSignals(node.signals, missingDownloadsSignalCounts)
        } else {
          collectSignals(node.signals, knownDownloadsSignalCounts)
        }

        if (node.dependents_count === null) {
          nodesMissingDependentsCount += 1
          collectSignals(node.signals, missingDependentsSignalCounts)
        } else {
          collectSignals(node.signals, knownDependentsSignalCounts)
        }

        collectSignals(node.signals, signalCounts)
      }

      const latestReview = latestReviewByRecordId.get(record.record_id)

      if (latestReview === undefined) {
        continue
      }

      switch (latestReview.outcome) {
        case 'malicious':
          maliciousCount += 1
          break
        case 'benign':
          benignCount += 1
          break
        case 'needs_review':
          needsReviewCount += 1
          break
      }
    }

    return {
      total_scans: scanRecords.length,
      labeled_records: latestReviewByRecordId.size,
      malicious_count: maliciousCount,
      benign_count: benignCount,
      needs_review_count: needsReviewCount,
      signal_frequency: toSortedSignalFrequency(signalCounts),
      metadata_coverage: buildMetadataCoverageSummary({
        totalNodes,
        nodesMissingWeeklyDownloads,
        nodesMissingDependentsCount,
        knownDownloadsSignalCounts,
        missingDownloadsSignalCounts,
        knownDependentsSignalCounts,
        missingDependentsSignalCounts,
      }),
    }
  }
}

function selectLatestReviews(reviewEvents: ReviewEvent[]): Map<string, ReviewEvent> {
  const latestByRecordId = new Map<string, ReviewEvent>()

  for (const event of reviewEvents) {
    const current = latestByRecordId.get(event.record_id)

    if (current === undefined || current.created_at < event.created_at) {
      latestByRecordId.set(event.record_id, event)
    }
  }

  return latestByRecordId
}

function flattenNodes(root: PackageNode): PackageNode[] {
  return [root, ...root.dependencies.flatMap(flattenNodes)]
}

function collectSignals(signals: RiskSignal[], counts: Map<string, number>): void {
  for (const signal of signals) {
    counts.set(signal.type, (counts.get(signal.type) ?? 0) + 1)
  }
}

function toSortedSignalFrequency(signalCounts: Map<string, number>): SignalFrequency[] {
  return Array.from(signalCounts.entries())
    .map(([type, count]) => ({ type, count }))
    .sort((left, right) => {
      if (left.count !== right.count) {
        return right.count - left.count
      }

      return left.type.localeCompare(right.type)
    })
}

function buildMetadataCoverageSummary({
  totalNodes,
  nodesMissingWeeklyDownloads,
  nodesMissingDependentsCount,
  knownDownloadsSignalCounts,
  missingDownloadsSignalCounts,
  knownDependentsSignalCounts,
  missingDependentsSignalCounts,
}: {
  totalNodes: number
  nodesMissingWeeklyDownloads: number
  nodesMissingDependentsCount: number
  knownDownloadsSignalCounts: Map<string, number>
  missingDownloadsSignalCounts: Map<string, number>
  knownDependentsSignalCounts: Map<string, number>
  missingDependentsSignalCounts: Map<string, number>
}): MetadataCoverageSummary {
  return {
    weekly_downloads: {
      total_nodes: totalNodes,
      missing_count: nodesMissingWeeklyDownloads,
      missing_percent: percentage(nodesMissingWeeklyDownloads, totalNodes),
    },
    dependents_count: {
      total_nodes: totalNodes,
      missing_count: nodesMissingDependentsCount,
      missing_percent: percentage(nodesMissingDependentsCount, totalNodes),
    },
    signal_frequency_by_weekly_downloads: toCoverageSignalFrequency(
      knownDownloadsSignalCounts,
      missingDownloadsSignalCounts,
    ),
    signal_frequency_by_dependents_count: toCoverageSignalFrequency(
      knownDependentsSignalCounts,
      missingDependentsSignalCounts,
    ),
  }
}

function toCoverageSignalFrequency(
  knownCounts: Map<string, number>,
  missingCounts: Map<string, number>,
): CoverageSignalFrequency {
  return {
    known: toSortedSignalFrequency(knownCounts),
    missing: toSortedSignalFrequency(missingCounts),
  }
}

function percentage(part: number, total: number): number {
  if (total === 0) {
    return 0
  }

  return Number(((part / total) * 100).toFixed(2))
}
