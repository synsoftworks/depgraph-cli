import type {
  CoverageSignalFrequency,
  EvaluationSummary,
  MetadataCoverageSummary,
  SignalFrequency,
} from '../domain/contracts.js'
import type { PackageNode, RiskSignal } from '../domain/entities.js'
import type { ScanReviewStore } from '../domain/ports.js'
import { resolveReviewState, resolveReviewStates } from './resolve-review-state.js'

interface EvaluateScansDependencies {
  reviewStore: ScanReviewStore
}

export function createEvaluateScansUseCase({ reviewStore }: EvaluateScansDependencies) {
  return async function evaluateScans(): Promise<EvaluationSummary> {
    const [scanRecords, reviewEvents] = await Promise.all([
      reviewStore.listScanRecords(),
      reviewStore.listReviewEvents(),
    ])

    const signalCounts = new Map<string, number>()
    const knownDownloadsSignalCounts = new Map<string, number>()
    const missingDownloadsSignalCounts = new Map<string, number>()
    const knownDependentsSignalCounts = new Map<string, number>()
    const missingDependentsSignalCounts = new Map<string, number>()
    let totalNodes = 0
    let nodesMissingWeeklyDownloads = 0
    let nodesMissingDependentsCount = 0
    let unreviewedRecords = 0
    let needsReviewRecords = 0
    let resolvedRecords = 0
    let canonicalMaliciousRecords = 0
    let canonicalBenignRecords = 0
    let maliciousEvents = 0
    let benignEvents = 0
    let needsReviewEvents = 0
    const resolvedReviewStates = resolveReviewStates(reviewEvents)

    for (const event of reviewEvents) {
      switch (event.outcome) {
        case 'malicious':
          maliciousEvents += 1
          break
        case 'benign':
          benignEvents += 1
          break
        case 'needs_review':
          needsReviewEvents += 1
          break
      }
    }

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

      const resolvedReviewState =
        resolvedReviewStates.get(record.record_id) ?? resolveReviewState(record.record_id, [])

      switch (resolvedReviewState.workflow_status) {
        case 'unreviewed':
          unreviewedRecords += 1
          break
        case 'needs_review':
          needsReviewRecords += 1
          break
        case 'resolved':
          resolvedRecords += 1
          break
      }

      switch (resolvedReviewState.canonical_label) {
        case 'malicious':
          canonicalMaliciousRecords += 1
          break
        case 'benign':
          canonicalBenignRecords += 1
          break
      }
    }

    return {
      total_scans: scanRecords.length,
      raw_review_events: {
        total_events: reviewEvents.length,
        malicious_events: maliciousEvents,
        benign_events: benignEvents,
        needs_review_events: needsReviewEvents,
      },
      canonical_labels: {
        total_labeled_records: canonicalMaliciousRecords + canonicalBenignRecords,
        malicious_records: canonicalMaliciousRecords,
        benign_records: canonicalBenignRecords,
        unlabeled_records: scanRecords.length - (canonicalMaliciousRecords + canonicalBenignRecords),
        derived_from: 'latest_label_bearing_event',
      },
      workflow_status: {
        unreviewed_records: unreviewedRecords,
        needs_review_records: needsReviewRecords,
        resolved_records: resolvedRecords,
      },
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
