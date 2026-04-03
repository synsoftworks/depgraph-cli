import type {
  CoverageSignalFrequency,
  EvaluationSummary,
  MetadataCoverageSummary,
  ResolvedReviewTargetState,
  ReviewTarget,
  SignalFrequency,
} from '../domain/contracts.js'
import type { PackageNode, RiskSignal } from '../domain/entities.js'
import type { ScanReviewStore } from '../domain/ports.js'
import { getResolvedReviewState } from './resolve-review-state.js'

interface EvaluateScansDependencies {
  scanRecordSource: Pick<ScanReviewStore, 'listScanRecords'>
  rawReviewEventSource: Pick<ScanReviewStore, 'listReviewEvents'>
  resolveReviewStateIndex: () => Promise<ReadonlyMap<string, ResolvedReviewTargetState>>
}

export function createEvaluateScansUseCase({
  scanRecordSource,
  rawReviewEventSource,
  resolveReviewStateIndex,
}: EvaluateScansDependencies) {
  return async function evaluateScans(): Promise<EvaluationSummary> {
    const [scanRecords, rawReviewEvents, resolvedReviewStateIndex] = await Promise.all([
      scanRecordSource.listScanRecords(),
      rawReviewEventSource.listReviewEvents(),
      resolveReviewStateIndex(),
    ])

    const signalCounts = new Map<string, number>()
    const knownDownloadsSignalCounts = new Map<string, number>()
    const missingDownloadsSignalCounts = new Map<string, number>()
    const knownDependentsSignalCounts = new Map<string, number>()
    const missingDependentsSignalCounts = new Map<string, number>()
    let totalNodes = 0
    let nodesMissingWeeklyDownloads = 0
    let nodesMissingDependentsCount = 0
    let totalTargets = 0
    let packageFindingTargets = 0
    let edgeFindingTargets = 0
    let unreviewedTargets = 0
    let needsReviewTargets = 0
    let resolvedTargets = 0
    let canonicalMaliciousTargets = 0
    let canonicalBenignTargets = 0
    let maliciousEvents = 0
    let benignEvents = 0
    let needsReviewEvents = 0
    // `ReviewEvent` is append-only source history. Eval still reads raw events
    // for raw-event counters, but all label-aware aggregation flows through the
    // resolved-review-state boundary.

    for (const event of rawReviewEvents) {
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
      for (const node of flattenMetadataNodes(record.root)) {
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

      for (const reviewTarget of listReviewTargets(record)) {
        totalTargets += 1

        if (reviewTarget.kind === 'package_finding') {
          packageFindingTargets += 1
        } else {
          edgeFindingTargets += 1
        }

        const resolvedReviewState = getResolvedReviewState(reviewTarget, resolvedReviewStateIndex)

        switch (resolvedReviewState.workflow_status) {
          case 'unreviewed':
            unreviewedTargets += 1
            break
          case 'needs_review':
            needsReviewTargets += 1
            break
          case 'resolved':
            resolvedTargets += 1
            break
        }

        switch (resolvedReviewState.canonical_label) {
          case 'malicious':
            canonicalMaliciousTargets += 1
            break
          case 'benign':
            canonicalBenignTargets += 1
            break
        }
      }
    }

    return {
      total_scans: scanRecords.length,
      review_targets: {
        total_targets: totalTargets,
        package_finding_targets: packageFindingTargets,
        edge_finding_targets: edgeFindingTargets,
      },
      raw_review_events: {
        total_events: rawReviewEvents.length,
        malicious_events: maliciousEvents,
        benign_events: benignEvents,
        needs_review_events: needsReviewEvents,
      },
      canonical_labels: {
        total_labeled_targets: canonicalMaliciousTargets + canonicalBenignTargets,
        malicious_targets: canonicalMaliciousTargets,
        benign_targets: canonicalBenignTargets,
        unlabeled_targets: totalTargets - (canonicalMaliciousTargets + canonicalBenignTargets),
        derived_from: 'source_precedence_then_latest_within_source',
      },
      workflow_status: {
        unreviewed_targets: unreviewedTargets,
        needs_review_targets: needsReviewTargets,
        resolved_targets: resolvedTargets,
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

function listReviewTargets(record: Awaited<ReturnType<ScanReviewStore['listScanRecords']>>[number]): ReviewTarget[] {
  return [
    ...record.findings.map((finding) => finding.review_target),
    ...record.edge_findings.map((edgeFinding) => edgeFinding.review_target),
  ]
}

function flattenMetadataNodes(root: PackageNode): PackageNode[] {
  const descendants = root.dependencies.flatMap(flattenMetadataNodes)

  if (root.is_project_root) {
    return descendants
  }

  return [root, ...descendants]
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
