import type {
  ExportReadinessSummary,
  FieldReadinessIssuesSummary,
  FieldReliabilityDistributionSummary,
  IntegritySignalsSummary,
  MetadataCoverageSummary,
  HeuristicOutputPresenceSummary,
  CoverageSignalFrequency,
  ScanReviewRecord,
  SignalFrequency,
} from '../domain/contracts.js'
import type { PackageNode, RiskSignal } from '../domain/entities.js'

// Export-readiness exclusions are single-reason buckets. This precedence keeps
// counts deterministic even when one row fails multiple readiness checks.
const EXPORT_EXCLUSION_ORDER = [
  'synthetic_project_root',
  'unresolved_registry_lookup',
  'missing_field_reliability_metadata',
  'placeholder_field_dependency',
  'unavailable_field_dependency',
] as const

const SECURITY_DEPRECATION_PATTERNS = [
  /security vulnerability/i,
  /security issue/i,
  /critical vulnerability/i,
  /cve-/i,
  /cve /i,
] as const

interface EvaluationDatasetSummary {
  signal_frequency: SignalFrequency[]
  metadata_coverage: MetadataCoverageSummary
  field_reliability_distribution: FieldReliabilityDistributionSummary
  integrity_signals: IntegritySignalsSummary
  field_readiness_issues: FieldReadinessIssuesSummary
  heuristic_output_presence: HeuristicOutputPresenceSummary
  export_readiness: ExportReadinessSummary
}

export function buildEvaluationDatasetSummary(scanRecords: ScanReviewRecord[]): EvaluationDatasetSummary {
  const signalCounts = new Map<string, number>()
  const knownDownloadsSignalCounts = new Map<string, number>()
  const missingDownloadsSignalCounts = new Map<string, number>()
  const knownDependentsSignalCounts = new Map<string, number>()
  const missingDependentsSignalCounts = new Map<string, number>()
  const fieldReliabilityDistribution = createTierCountMap()
  let totalNodes = 0
  let nodesMissingWeeklyDownloads = 0
  let nodesMissingDependentsCount = 0
  let syntheticProjectRootCount = 0
  let unresolvedRegistryLookupCount = 0
  let deprecatedWithSecuritySignalCount = 0
  let dependentsCountUnavailableCount = 0
  let hasAdvisoriesPlaceholderCount = 0
  let recordsMissingFieldReliabilityCount = 0
  let recordsWithFieldReliabilityCount = 0
  let nodesWithRiskScore = 0
  let nodesWithRiskLevel = 0
  let nodesWithRecommendation = 0
  let nodesWithSignals = 0
  let recordsTotal = 0
  let recordsExportReady = 0
  let totalPackageRows = 0
  let rowsWithReliabilityMetadata = 0
  let exportReadyRows = 0
  let excludedPlaceholderFields = 0
  let excludedUnavailableFields = 0
  let excludedMissingReliabilityMetadata = 0
  let excludedPackageLevel = 0

  for (const record of scanRecords) {
    recordsTotal += 1
    const unresolvedIssues = new Set<string>()
    const fieldReliability = record.field_reliability
    const recordHasFieldReliability = fieldReliability !== undefined
    const hasPlaceholderPackageNodeFields =
      fieldReliability !== undefined &&
      Object.entries(fieldReliability.fields).some(
        ([fieldId, entry]) => fieldId.startsWith('package_node.') && entry.tier === 'placeholder',
      )
    const hasUnavailablePackageNodeFields =
      fieldReliability !== undefined &&
      Object.entries(fieldReliability.fields).some(
        ([fieldId, entry]) => fieldId.startsWith('package_node.') && entry.tier === 'unavailable',
      )
    let recordHasExportReadyRows = false

    if (!recordHasFieldReliability) {
      recordsMissingFieldReliabilityCount += 1
    } else {
      recordsWithFieldReliabilityCount += 1
      for (const entry of Object.values(fieldReliability.fields)) {
        fieldReliabilityDistribution[entry.tier] += 1
      }
    }

    for (const node of flattenAllNodes(record.root)) {
      totalPackageRows += 1

      if (recordHasFieldReliability) {
        rowsWithReliabilityMetadata += 1
      }

      if (node.metadata_status === 'synthetic_project_root') {
        syntheticProjectRootCount += 1
      }

      if (node.metadata_status === 'unresolved_registry_lookup') {
        unresolvedIssues.add(`${record.record_id}:${node.key}`)
      }

      if (
        node.deprecated_message !== null &&
        isSecurityRelatedDeprecationMessage(node.deprecated_message)
      ) {
        deprecatedWithSecuritySignalCount += 1
      }

      switch (determineExportExclusionReason({
        node,
        recordHasFieldReliability,
        hasPlaceholderPackageNodeFields,
        hasUnavailablePackageNodeFields,
      })) {
        case undefined:
          exportReadyRows += 1
          recordHasExportReadyRows = true
          break
        case 'synthetic_project_root':
          excludedPackageLevel += 1
          break
        case 'unresolved_registry_lookup':
          excludedPackageLevel += 1
          break
        case 'missing_field_reliability_metadata':
          excludedMissingReliabilityMetadata += 1
          break
        case 'placeholder_field_dependency':
          excludedPlaceholderFields += 1
          break
        case 'unavailable_field_dependency':
          excludedUnavailableFields += 1
          break
      }
    }

    if (recordHasFieldReliability && recordHasExportReadyRows) {
      recordsExportReady += 1
    }

    for (const warning of record.warnings) {
      if (warning.kind === 'unresolved_registry_lookup') {
        unresolvedIssues.add(`${record.record_id}:${warning.package_key}`)
      }
    }

    unresolvedRegistryLookupCount += unresolvedIssues.size

    // Feature-surface observability excludes synthetic project roots because
    // they are structural roots rather than real published packages.
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
        dependentsCountUnavailableCount += 1
        collectSignals(node.signals, missingDependentsSignalCounts)
      } else {
        collectSignals(node.signals, knownDependentsSignalCounts)
      }

      if (node.has_advisories === false) {
        hasAdvisoriesPlaceholderCount += 1
      }

      if (node.risk_score !== undefined) {
        nodesWithRiskScore += 1
      }

      if (node.risk_level !== undefined) {
        nodesWithRiskLevel += 1
      }

      if (node.recommendation !== undefined) {
        nodesWithRecommendation += 1
      }

      if (node.signals !== undefined) {
        nodesWithSignals += 1
      }

      collectSignals(node.signals, signalCounts)
    }
  }

  fieldReliabilityDistribution.records_with_field_reliability = recordsWithFieldReliabilityCount
  fieldReliabilityDistribution.records_excluded_missing_field_reliability =
    recordsMissingFieldReliabilityCount

  return {
    signal_frequency: toSortedSignalFrequency(signalCounts),
    metadata_coverage: {
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
    },
    field_reliability_distribution: fieldReliabilityDistribution,
    integrity_signals: {
      synthetic_project_root_count: syntheticProjectRootCount,
      unresolved_registry_lookup_count: unresolvedRegistryLookupCount,
      deprecated_with_security_signal_count: deprecatedWithSecuritySignalCount,
    },
    field_readiness_issues: {
      dependents_count_unavailable_count: dependentsCountUnavailableCount,
      has_advisories_placeholder_count: hasAdvisoriesPlaceholderCount,
      records_missing_field_reliability_count: recordsMissingFieldReliabilityCount,
    },
    heuristic_output_presence: {
      nodes_with_risk_score: nodesWithRiskScore,
      nodes_with_risk_level: nodesWithRiskLevel,
      nodes_with_recommendation: nodesWithRecommendation,
      nodes_with_signals: nodesWithSignals,
    },
    export_readiness: {
      records_total: recordsTotal,
      records_with_field_reliability: recordsWithFieldReliabilityCount,
      records_export_ready: recordsExportReady,
      records_excluded_missing_field_reliability: recordsMissingFieldReliabilityCount,
      rows_total: totalPackageRows,
      rows_with_reliability_metadata: rowsWithReliabilityMetadata,
      rows_export_ready: exportReadyRows,
      rows_excluded_missing_field_reliability: excludedMissingReliabilityMetadata,
      rows_excluded_placeholder_fields: excludedPlaceholderFields,
      rows_excluded_unavailable_fields: excludedUnavailableFields,
      rows_excluded_package_level: excludedPackageLevel,
    },
  }
}

export function isSecurityRelatedDeprecationMessage(message: string): boolean {
  return SECURITY_DEPRECATION_PATTERNS.some((pattern) => pattern.test(message))
}

function determineExportExclusionReason({
  node,
  recordHasFieldReliability,
  hasPlaceholderPackageNodeFields,
  hasUnavailablePackageNodeFields,
}: {
  node: PackageNode
  recordHasFieldReliability: boolean
  hasPlaceholderPackageNodeFields: boolean
  hasUnavailablePackageNodeFields: boolean
}): typeof EXPORT_EXCLUSION_ORDER[number] | undefined {
  for (const reason of EXPORT_EXCLUSION_ORDER) {
    switch (reason) {
      case 'synthetic_project_root':
        if (node.metadata_status === 'synthetic_project_root') {
          return reason
        }
        break
      case 'missing_field_reliability_metadata':
        if (!recordHasFieldReliability) {
          return reason
        }
        break
      case 'unresolved_registry_lookup':
        if (node.metadata_status === 'unresolved_registry_lookup') {
          return reason
        }
        break
      case 'placeholder_field_dependency':
        if (hasPlaceholderPackageNodeFields) {
          return reason
        }
        break
      case 'unavailable_field_dependency':
        if (hasUnavailablePackageNodeFields) {
          return reason
        }
        break
    }
  }

  return undefined
}

function createTierCountMap(): FieldReliabilityDistributionSummary {
  return {
    records_with_field_reliability: 0,
    records_excluded_missing_field_reliability: 0,
    reliable: 0,
    conditionally_reliable: 0,
    unavailable: 0,
    placeholder: 0,
    heuristic_output: 0,
    structural_only: 0,
    scan_context: 0,
  }
}

function flattenAllNodes(root: PackageNode): PackageNode[] {
  return [root, ...root.dependencies.flatMap(flattenAllNodes)]
}

function flattenMetadataNodes(root: PackageNode): PackageNode[] {
  const descendants = root.dependencies.flatMap(flattenMetadataNodes)

  if (root.metadata_status === 'synthetic_project_root' || root.is_project_root) {
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
