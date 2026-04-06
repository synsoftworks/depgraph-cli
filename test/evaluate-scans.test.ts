import assert from 'node:assert/strict'
import test from 'node:test'

import { createEvaluateScansUseCase } from '../src/application/evaluate-scans.js'
import { createResolveReviewStateIndexUseCase } from '../src/application/resolve-review-state-index.js'
import { createFieldReliabilityReport } from '../src/domain/field-reliability-policy.js'
import type { ReviewEvent, ScanReviewRecord } from '../src/domain/contracts.js'
import type { ScanReviewStore } from '../src/domain/ports.js'

class InMemoryReviewStore implements ScanReviewStore {
  constructor(
    private readonly records: ScanReviewRecord[],
    private readonly reviewEvents: ReviewEvent[],
  ) {}

  async appendScanRecord(): Promise<void> {
    throw new Error('not used')
  }

  async findLatestScanByBaseline(): Promise<ScanReviewRecord | null> {
    throw new Error('not used')
  }

  async findScanRecord(): Promise<ScanReviewRecord | null> {
    throw new Error('not used')
  }

  async appendReviewEvent(): Promise<void> {
    throw new Error('not used')
  }

  async listScanRecords(): Promise<ScanReviewRecord[]> {
    return this.records
  }

  async listReviewEvents(): Promise<ReviewEvent[]> {
    return this.reviewEvents
  }
}

test('evaluate scans reports metadata coverage and latest-label counts', async () => {
  const reviewStore = new InMemoryReviewStore(
    [createRecord()],
    [
      createReviewEvent('needs_review', '2026-04-02T00:00:00.000Z'),
      createReviewEvent('benign', '2026-04-03T00:00:00.000Z'),
      createReviewEvent('needs_review', '2026-04-04T00:00:00.000Z'),
    ],
  )
  const evaluateScans = createEvaluateScansUseCase({
    scanRecordSource: reviewStore,
    rawReviewEventSource: reviewStore,
    resolveReviewStateIndex: createResolveReviewStateIndexUseCase({
      reviewEventSource: reviewStore,
    }),
  })

  const summary = await evaluateScans()

  assert.equal(summary.total_scans, 1)
  assert.equal(summary.review_targets.total_targets, 1)
  assert.equal(summary.review_targets.package_finding_targets, 1)
  assert.equal(summary.review_targets.edge_finding_targets, 0)
  assert.equal(summary.raw_review_events.total_events, 3)
  assert.equal(summary.raw_review_events.benign_events, 1)
  assert.equal(summary.raw_review_events.needs_review_events, 2)
  assert.equal(summary.canonical_labels.total_labeled_targets, 1)
  assert.equal(summary.canonical_labels.benign_targets, 1)
  assert.equal(summary.canonical_labels.malicious_targets, 0)
  assert.equal(summary.canonical_labels.unlabeled_targets, 0)
  assert.equal(summary.workflow_status.needs_review_targets, 1)
  assert.equal(summary.workflow_status.resolved_targets, 0)
  assert.equal(summary.workflow_status.unreviewed_targets, 0)
  assert.equal(summary.metadata_coverage.weekly_downloads.missing_count, 1)
  assert.equal(summary.metadata_coverage.weekly_downloads.total_nodes, 2)
  assert.equal(summary.metadata_coverage.weekly_downloads.missing_percent, 50)
  assert.equal(summary.metadata_coverage.dependents_count.missing_count, 1)
  assert.deepEqual(summary.metadata_coverage.signal_frequency_by_weekly_downloads.known, [
    { type: 'root_signal', count: 1 },
  ])
  assert.deepEqual(summary.metadata_coverage.signal_frequency_by_weekly_downloads.missing, [
    { type: 'child_signal', count: 1 },
  ])
  assert.equal(summary.field_reliability_distribution.placeholder, 1)
  assert.equal(summary.field_reliability_distribution.records_with_field_reliability, 1)
  assert.equal(
    summary.field_reliability_distribution.records_excluded_missing_field_reliability,
    0,
  )
  assert.equal(summary.field_readiness_issues.records_missing_field_reliability_count, 0)
  assert.equal(summary.integrity_signals.synthetic_project_root_count, 0)
  assert.equal(summary.heuristic_output_presence.nodes_with_risk_score, 2)
  assert.equal(summary.export_readiness.records_total, 1)
  assert.equal(summary.export_readiness.records_with_field_reliability, 1)
  assert.equal(summary.export_readiness.records_export_ready, 0)
  assert.equal(summary.export_readiness.records_excluded_missing_field_reliability, 0)
  assert.equal(summary.export_readiness.rows_total, 2)
  assert.equal(summary.export_readiness.rows_with_reliability_metadata, 2)
  assert.equal(summary.export_readiness.rows_export_ready, 0)
  assert.equal(summary.export_readiness.rows_excluded_missing_field_reliability, 0)
  assert.equal(summary.export_readiness.rows_excluded_package_level, 0)
  assert.equal(summary.export_readiness.rows_excluded_placeholder_fields, 2)
  assert.equal(summary.export_readiness.rows_excluded_unavailable_fields, 0)
})

test('evaluate scans handles mixed historical records and readiness exclusion precedence deterministically', async () => {
  const reviewStore = new InMemoryReviewStore(
    [
      createRecord({
        recordId: 'record-policy',
        includeFieldReliability: true,
        rootOverrides: {
          is_project_root: true,
          metadata_status: 'synthetic_project_root',
          age_days: null,
          weekly_downloads: null,
          dependents_count: null,
          published_at: null,
          first_published: null,
          last_published: null,
          total_versions: null,
          publish_events_last_30_days: null,
        },
        childOverrides: {
          metadata_status: 'unresolved_registry_lookup',
          metadata_warning: 'Registry metadata unavailable',
          weekly_downloads: null,
          deprecated_message:
            'This package has a critical vulnerability. See CVE-2026-1234 for details.',
        },
        warnings: [
          {
            kind: 'unresolved_registry_lookup',
            package_key: 'child@1.0.0',
            package_name: 'child',
            package_version: '1.0.0',
            message: 'Registry metadata unavailable',
            lockfile_resolved_url: null,
            lockfile_integrity: null,
          },
        ],
      }),
      createRecord({
        recordId: 'record-legacy',
        includeFieldReliability: false,
      }),
    ],
    [],
  )
  const evaluateScans = createEvaluateScansUseCase({
    scanRecordSource: reviewStore,
    rawReviewEventSource: reviewStore,
    resolveReviewStateIndex: createResolveReviewStateIndexUseCase({
      reviewEventSource: reviewStore,
    }),
  })

  const summary = await evaluateScans()
  const expectedDistribution = countReliabilityTiers(createFieldReliabilityReport())
  expectedDistribution.records_excluded_missing_field_reliability = 1

  assert.equal(summary.field_readiness_issues.records_missing_field_reliability_count, 1)
  assert.deepEqual(summary.field_reliability_distribution, expectedDistribution)
  assert.equal(summary.integrity_signals.synthetic_project_root_count, 1)
  assert.equal(summary.integrity_signals.unresolved_registry_lookup_count, 1)
  assert.equal(summary.integrity_signals.deprecated_with_security_signal_count, 1)
  assert.equal(summary.field_readiness_issues.dependents_count_unavailable_count, 1)
  assert.equal(summary.field_readiness_issues.has_advisories_placeholder_count, 3)
  assert.equal(summary.heuristic_output_presence.nodes_with_risk_score, 3)
  assert.equal(summary.heuristic_output_presence.nodes_with_risk_level, 3)
  assert.equal(summary.heuristic_output_presence.nodes_with_recommendation, 3)
  assert.equal(summary.heuristic_output_presence.nodes_with_signals, 3)
  assert.equal(summary.export_readiness.records_total, 2)
  assert.equal(summary.export_readiness.records_with_field_reliability, 1)
  assert.equal(summary.export_readiness.records_export_ready, 0)
  assert.equal(summary.export_readiness.records_excluded_missing_field_reliability, 1)
  assert.equal(summary.export_readiness.rows_total, 4)
  assert.equal(summary.export_readiness.rows_with_reliability_metadata, 2)
  assert.equal(summary.export_readiness.rows_export_ready, 0)
  assert.equal(summary.export_readiness.rows_excluded_missing_field_reliability, 2)
  assert.equal(summary.export_readiness.rows_excluded_package_level, 2)
  assert.equal(summary.export_readiness.rows_excluded_placeholder_fields, 0)
  assert.equal(summary.export_readiness.rows_excluded_unavailable_fields, 0)
})

test('evaluate scans excludes unavailable-tier package fields when placeholder tiers are absent', async () => {
  const report = createFieldReliabilityReport()
  report.fields['package_node.has_advisories'] = {
    tier: 'reliable',
    guidance: 'Test override for unavailable-tier readiness coverage.',
  }
  const reviewStore = new InMemoryReviewStore(
    [
      createRecord({
        fieldReliabilityOverride: report,
      }),
    ],
    [],
  )
  const evaluateScans = createEvaluateScansUseCase({
    scanRecordSource: reviewStore,
    rawReviewEventSource: reviewStore,
    resolveReviewStateIndex: createResolveReviewStateIndexUseCase({
      reviewEventSource: reviewStore,
    }),
  })

  const summary = await evaluateScans()

  assert.equal(summary.export_readiness.records_total, 1)
  assert.equal(summary.export_readiness.records_with_field_reliability, 1)
  assert.equal(summary.export_readiness.records_export_ready, 0)
  assert.equal(summary.export_readiness.rows_total, 2)
  assert.equal(summary.export_readiness.rows_export_ready, 0)
  assert.equal(summary.export_readiness.rows_excluded_placeholder_fields, 0)
  assert.equal(summary.export_readiness.rows_excluded_unavailable_fields, 2)
  assert.equal(summary.export_readiness.rows_excluded_package_level, 0)
})

function createRecord({
  recordId = 'record-1',
  includeFieldReliability = true,
  fieldReliabilityOverride,
  rootOverrides = {},
  childOverrides = {},
  warnings = [],
}: {
  recordId?: string
  includeFieldReliability?: boolean
  fieldReliabilityOverride?: ReturnType<typeof createFieldReliabilityReport>
  rootOverrides?: Partial<ScanReviewRecord['root']>
  childOverrides?: Partial<ScanReviewRecord['root']['dependencies'][number]>
  warnings?: ScanReviewRecord['warnings']
} = {}): ScanReviewRecord {
  const childNode: ScanReviewRecord['root']['dependencies'][number] = {
    name: 'child',
    version: '1.0.0',
    key: 'child@1.0.0',
    depth: 1,
    is_project_root: false,
    metadata_status: 'enriched',
    metadata_warning: null,
    lockfile_resolved_url: null,
    lockfile_integrity: null,
    age_days: 1,
    weekly_downloads: null,
    dependents_count: 42,
    deprecated_message: null,
    is_security_tombstone: false,
    published_at: '2026-04-01T00:00:00.000Z',
    first_published: '2026-04-01T00:00:00.000Z',
    last_published: '2026-04-01T00:00:00.000Z',
    total_versions: 1,
    dependency_count: 0,
    publish_events_last_30_days: 1,
    has_advisories: false,
    risk_score: 0.16,
    risk_level: 'safe',
    signals: [
      {
        type: 'child_signal',
        value: 1,
        weight: 'medium',
        reason: 'child signal',
      },
    ],
    recommendation: 'install',
    dependencies: [],
    ...childOverrides,
  }

  return {
    record_id: recordId,
    created_at: '2026-04-01T00:00:00.000Z',
    scan_mode: 'registry_package',
    package: { name: 'root', version: '1.0.0' },
    package_key: 'root@1.0.0',
    scan_target: 'root',
    baseline_identity: {
      scan_mode: 'registry_package',
      scan_target: 'root',
      requested_depth: 3,
      workspace_identity: '/tmp/workspace',
    },
    baseline_key: 'registry_package::root::depth=3::workspace=/tmp/workspace',
    baseline_record_id: null,
    requested_depth: 3,
    threshold: 0.4,
    ...(includeFieldReliability
      ? { field_reliability: fieldReliabilityOverride ?? createFieldReliabilityReport() }
      : {}),
    raw_score: 0.48,
    risk_level: 'review',
    signals: [
      {
        type: 'root_signal',
        value: 1,
        weight: 'medium',
        reason: 'root signal',
      },
    ],
    findings: [
      {
        key: 'root@1.0.0',
        name: 'root',
        version: '1.0.0',
        depth: 0,
        review_target: {
          kind: 'package_finding',
          record_id: 'record-1',
          target_id: 'package_finding:root@1.0.0',
          finding_key: 'package_finding:root@1.0.0',
          package_key: 'root@1.0.0',
        },
        path: {
          packages: [{ name: 'root', version: '1.0.0' }],
        },
        risk_score: 0.48,
        risk_level: 'review',
        recommendation: 'review',
        signals: [
          {
            type: 'root_signal',
            value: 1,
            weight: 'medium',
            reason: 'root signal',
          },
        ],
        explanation: 'root signal',
      },
    ],
    root: {
      name: 'root',
      version: '1.0.0',
      key: 'root@1.0.0',
      depth: 0,
      is_project_root: false,
      metadata_status: 'enriched',
      metadata_warning: null,
      lockfile_resolved_url: null,
      lockfile_integrity: null,
      age_days: 1,
      weekly_downloads: 1000,
      dependents_count: null,
      deprecated_message: null,
      is_security_tombstone: false,
      published_at: '2026-04-01T00:00:00.000Z',
      first_published: '2026-04-01T00:00:00.000Z',
      last_published: '2026-04-01T00:00:00.000Z',
      total_versions: 1,
      dependency_count: 1,
      publish_events_last_30_days: 1,
      has_advisories: false,
      risk_score: 0.48,
      risk_level: 'review',
      signals: [
        {
          type: 'root_signal',
          value: 1,
          weight: 'medium',
          reason: 'root signal',
        },
      ],
      recommendation: 'review',
      dependencies: [childNode],
      ...rootOverrides,
    },
    total_scanned: 2,
    suspicious_count: 1,
    safe_count: 1,
    scan_duration_ms: 1,
    dependency_edges: [{ from: 'root@1.0.0', to: 'child@1.0.0', child_depth: 1 }],
    edge_findings: [],
    warnings,
  }
}

test('evaluate scans excludes synthetic project roots from metadata coverage stats', async () => {
  const reviewStore = new InMemoryReviewStore(
    [
      {
        ...createRecord(),
        scan_mode: 'package_lock',
        root: {
          ...createRecord().root,
          is_project_root: true,
          metadata_status: 'synthetic_project_root',
          age_days: null,
          weekly_downloads: null,
          dependents_count: null,
          published_at: null,
          first_published: null,
          last_published: null,
          total_versions: null,
          publish_events_last_30_days: null,
        },
        total_scanned: 2,
      },
    ],
    [],
  )
  const evaluateScans = createEvaluateScansUseCase({
    scanRecordSource: reviewStore,
    rawReviewEventSource: reviewStore,
    resolveReviewStateIndex: createResolveReviewStateIndexUseCase({
      reviewEventSource: reviewStore,
    }),
  })

  const summary = await evaluateScans()

  assert.equal(summary.metadata_coverage.weekly_downloads.total_nodes, 1)
  assert.equal(summary.metadata_coverage.weekly_downloads.missing_count, 1)
  assert.equal(summary.metadata_coverage.dependents_count.total_nodes, 1)
  assert.deepEqual(summary.metadata_coverage.signal_frequency_by_weekly_downloads.known, [])
  assert.deepEqual(summary.metadata_coverage.signal_frequency_by_weekly_downloads.missing, [
    { type: 'child_signal', count: 1 },
  ])
})

function createReviewEvent(outcome: ReviewEvent['outcome'], createdAt: string): ReviewEvent {
  return {
    event_id: `${createdAt}:package_finding:root@1.0.0:${outcome}`,
    record_id: 'record-1',
    review_target: {
      kind: 'package_finding',
      record_id: 'record-1',
      target_id: 'package_finding:root@1.0.0',
      finding_key: 'package_finding:root@1.0.0',
      package_key: 'root@1.0.0',
    },
    created_at: createdAt,
    outcome,
    notes: null,
    resolution_timestamp: outcome === 'needs_review' ? null : createdAt,
    review_source: 'human',
    confidence: 0.9,
  }
}

function countReliabilityTiers(
  report: ReturnType<typeof createFieldReliabilityReport>,
): {
  records_with_field_reliability: number
  records_excluded_missing_field_reliability: number
  reliable: number
  conditionally_reliable: number
  unavailable: number
  placeholder: number
  heuristic_output: number
  structural_only: number
  scan_context: number
} {
  const counts = {
    records_with_field_reliability: 1,
    records_excluded_missing_field_reliability: 0,
    reliable: 0,
    conditionally_reliable: 0,
    unavailable: 0,
    placeholder: 0,
    heuristic_output: 0,
    structural_only: 0,
    scan_context: 0,
  }

  for (const entry of Object.values(report.fields)) {
    counts[entry.tier] += 1
  }

  return counts
}
