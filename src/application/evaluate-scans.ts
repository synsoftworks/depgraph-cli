import type {
  EvaluationSummary,
  ResolvedReviewTargetState,
  ReviewTarget,
} from '../domain/contracts.js'
import type { ScanReviewStore } from '../domain/ports.js'
import { buildEvaluationDatasetSummary } from './evaluation-readiness.js'
import { getResolvedReviewState } from './resolve-review-state.js'

interface EvaluateScansDependencies {
  scanRecordSource: Pick<ScanReviewStore, 'listScanRecords'>
  rawReviewEventSource: Pick<ScanReviewStore, 'listReviewEvents'>
  resolveReviewStateIndex: () => Promise<ReadonlyMap<string, ResolvedReviewTargetState>>
}

/**
 * Creates the evaluation use case for persisted scans and review history.
 *
 * @param dependencies Runtime dependencies for scan records, review events, and resolved review state.
 * @returns Use case that aggregates evaluation summary output.
 */
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

    const datasetSummary = buildEvaluationDatasetSummary(scanRecords)

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
      signal_frequency: datasetSummary.signal_frequency,
      metadata_coverage: datasetSummary.metadata_coverage,
      field_reliability_distribution: datasetSummary.field_reliability_distribution,
      integrity_signals: datasetSummary.integrity_signals,
      field_readiness_issues: datasetSummary.field_readiness_issues,
      heuristic_output_presence: datasetSummary.heuristic_output_presence,
      export_readiness: datasetSummary.export_readiness,
    }
  }
}

function listReviewTargets(record: Awaited<ReturnType<ScanReviewStore['listScanRecords']>>[number]): ReviewTarget[] {
  return [
    ...record.findings.map((finding) => finding.review_target),
    ...record.edge_findings.map((edgeFinding) => edgeFinding.review_target),
  ]
}
