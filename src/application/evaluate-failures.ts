/**
 * Responsibilities:
 * - Surface known failure patterns from persisted scan history.
 * - Deduplicate historical matches into stable failure summaries.
 *
 * Non-responsibilities:
 * - Do not perform new scans, change review state, or render output.
 * - Do not recalculate package risk, signals, or thresholds.
 */
import type { ScanReviewRecord } from '../domain/contracts.js'
import type { PackageNode } from '../domain/entities.js'
import type { FailureSurfacingSummary, SurfacedFailure } from '../domain/failure-surfacing.js'
import { KNOWN_BOUNDARY_CASES } from '../domain/failure-surfacing.js'
import type { ScanReviewStore } from '../domain/ports.js'
import { hasSecurityDeprecationLanguage, packageKey } from '../domain/value-objects.js'

interface EvaluateFailuresDependencies {
  scanRecordSource: Pick<ScanReviewStore, 'listScanRecords'>
}

/**
 * Creates the failure-surfacing use case over persisted scan history.
 *
 * @param dependencies Access to stored scan records.
 * @returns A use case that summarizes known historical failure patterns.
 */
export function createEvaluateFailuresUseCase({
  scanRecordSource,
}: EvaluateFailuresDependencies) {
  return async function evaluateFailures(): Promise<FailureSurfacingSummary> {
    const scanRecords = await scanRecordSource.listScanRecords()
    const surfacedFailures = new Map<string, SurfacedFailure>()

    for (const record of scanRecords) {
      for (const node of flattenAllNodes(record.root)) {
        collectSecurityDeprecationUnderThresholdMatch(record, node, surfacedFailures)
        collectKnownBoundaryMatch(record, node, surfacedFailures)
      }
    }

    const failures = [...surfacedFailures.values()].sort(compareSurfacedFailures)

    return {
      total_records_scanned: scanRecords.length,
      total_matches: failures.length,
      failures,
    }
  }
}

function collectSecurityDeprecationUnderThresholdMatch(
  record: ScanReviewRecord,
  node: PackageNode,
  surfacedFailures: Map<string, SurfacedFailure>,
): void {
  if (
    node.deprecated_message === null ||
    !hasSecurityDeprecationLanguage(node.deprecated_message) ||
    node.risk_level !== 'safe' ||
    node.risk_score >= record.threshold
  ) {
    return
  }

  upsertSurfacedFailure(surfacedFailures, {
    package: node.name,
    version: node.version,
    failure_class: 'underweighted_signal',
    status: 'historical_match',
    record_ids: [record.record_id],
    reason:
      'Security-related deprecation language was present, but the package remained below the review threshold in persisted scan history.',
  })
}

function collectKnownBoundaryMatch(
  record: ScanReviewRecord,
  node: PackageNode,
  surfacedFailures: Map<string, SurfacedFailure>,
): void {
  const boundaryCase = KNOWN_BOUNDARY_CASES.find(
    (candidate) => candidate.package === node.name && candidate.version === node.version,
  )

  if (boundaryCase === undefined) {
    return
  }

  upsertSurfacedFailure(surfacedFailures, {
    package: boundaryCase.package,
    version: boundaryCase.version,
    failure_class: boundaryCase.failure_class,
    status: boundaryCase.status,
    record_ids: [record.record_id],
    reason: boundaryCase.reason,
  })
}

function upsertSurfacedFailure(
  surfacedFailures: Map<string, SurfacedFailure>,
  failure: SurfacedFailure,
): void {
  const key = surfacedFailureKey(failure)
  const existing = surfacedFailures.get(key)

  if (existing === undefined) {
    surfacedFailures.set(key, {
      ...failure,
      record_ids: [...failure.record_ids].sort((left, right) => left.localeCompare(right)),
    })
    return
  }

  // Record ids are merged into a set so repeated historical matches stay idempotent across multiple scans.
  const recordIds = new Set([...existing.record_ids, ...failure.record_ids])
  existing.record_ids = [...recordIds].sort((left, right) => left.localeCompare(right))
}

function surfacedFailureKey(
  failure: Pick<SurfacedFailure, 'package' | 'version' | 'failure_class'>,
): string {
  return `${failure.failure_class}:${packageKey({ name: failure.package, version: failure.version })}`
}

function flattenAllNodes(root: PackageNode): PackageNode[] {
  return [root, ...root.dependencies.flatMap(flattenAllNodes)]
}

function compareSurfacedFailures(left: SurfacedFailure, right: SurfacedFailure): number {
  const packageComparison = left.package.localeCompare(right.package)

  if (packageComparison !== 0) {
    return packageComparison
  }

  const versionComparison = left.version.localeCompare(right.version)

  if (versionComparison !== 0) {
    return versionComparison
  }

  return left.failure_class.localeCompare(right.failure_class)
}
