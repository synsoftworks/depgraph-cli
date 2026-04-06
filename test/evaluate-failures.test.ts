import assert from 'node:assert/strict'
import test from 'node:test'

import { createEvaluateFailuresUseCase } from '../src/application/evaluate-failures.js'
import type { ReviewEvent, ScanReviewRecord } from '../src/domain/contracts.js'
import { createFieldReliabilityReport } from '../src/domain/field-reliability-policy.js'
import type { ScanReviewStore } from '../src/domain/ports.js'
import { renderFailureSurfacingJson, renderFailureSurfacingPlainText } from '../src/interface/evaluation-failure-renderer.js'

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

test('historical BM-001-style records are surfaced from scan history', async () => {
  const reviewStore = new InMemoryReviewStore(
    [
      createRecord({
        recordId: 'record-next',
        rootOverrides: {
          dependencies: [
            createNode({
              name: 'next',
              version: '15.1.7',
              key: 'next@15.1.7',
              depth: 1,
              deprecated_message:
                'This version has a security vulnerability. Please upgrade. See CVE-2025-66478.',
              risk_score: 0.32,
              risk_level: 'safe',
            }),
          ],
        },
      }),
    ],
    [],
  )
  const evaluateFailures = createEvaluateFailuresUseCase({
    scanRecordSource: reviewStore,
  })

  const summary = await evaluateFailures()

  assert.equal(summary.total_records_scanned, 1)
  assert.equal(summary.total_matches, 1)
  assert.deepEqual(summary.failures, [
    {
      package: 'next',
      version: '15.1.7',
      failure_class: 'underweighted_signal',
      status: 'historical_match',
      record_ids: ['record-next'],
      reason:
        'Security-related deprecation language was present, but the package remained below the review threshold in persisted scan history.',
    },
  ])
})

test('failure surfacing deduplicates and sorts record ids deterministically', async () => {
  const duplicatedNextNode = createNode({
    name: 'next',
    version: '15.1.7',
    key: 'next@15.1.7',
    depth: 1,
    deprecated_message:
      'This version has a security vulnerability. Please upgrade. See CVE-2025-66478.',
    risk_score: 0.32,
    risk_level: 'safe',
  })
  const reviewStore = new InMemoryReviewStore(
    [
      createRecord({
        recordId: 'record-b',
        rootOverrides: {
          dependencies: [duplicatedNextNode, { ...duplicatedNextNode }],
        },
      }),
      createRecord({
        recordId: 'record-a',
        rootOverrides: {
          dependencies: [{ ...duplicatedNextNode }],
        },
      }),
    ],
    [],
  )
  const evaluateFailures = createEvaluateFailuresUseCase({
    scanRecordSource: reviewStore,
  })

  const summary = await evaluateFailures()

  assert.deepEqual(summary.failures, [
    {
      package: 'next',
      version: '15.1.7',
      failure_class: 'underweighted_signal',
      status: 'historical_match',
      record_ids: ['record-a', 'record-b'],
      reason:
        'Security-related deprecation language was present, but the package remained below the review threshold in persisted scan history.',
    },
  ])
})

test('isite boundary cases are surfaced as known metadata limits', async () => {
  const reviewStore = new InMemoryReviewStore(
    [
      createRecord({
        recordId: 'record-isite',
        packageName: 'isite',
        packageVersion: '2024.8.19',
        rootOverrides: {
          name: 'isite',
          version: '2024.8.19',
          key: 'isite@2024.8.19',
          age_days: 561,
          weekly_downloads: 23935,
          total_versions: 409,
          publish_events_last_30_days: 0,
          risk_score: 0,
          risk_level: 'safe',
          signals: [],
          dependencies: [],
        },
      }),
    ],
    [],
  )
  const evaluateFailures = createEvaluateFailuresUseCase({
    scanRecordSource: reviewStore,
  })

  const summary = await evaluateFailures()

  assert.equal(summary.total_matches, 1)
  assert.deepEqual(summary.failures, [
    {
      package: 'isite',
      version: '2024.8.19',
      failure_class: 'missing_signal',
      status: 'known_boundary_case',
      record_ids: ['record-isite'],
      reason:
        'Known metadata boundary case (BM-003/FN-002): registry metadata can look normal while malicious behavior exists only in the tarball.',
    },
  ])
})

test('benign packages are not surfaced by failure matching', async () => {
  const reviewStore = new InMemoryReviewStore([createRecord()], [])
  const evaluateFailures = createEvaluateFailuresUseCase({
    scanRecordSource: reviewStore,
  })

  const summary = await evaluateFailures()

  assert.equal(summary.total_matches, 0)
  assert.deepEqual(summary.failures, [])
})

test('empty history renders a deterministic no-match result', async () => {
  const reviewStore = new InMemoryReviewStore([], [])
  const evaluateFailures = createEvaluateFailuresUseCase({
    scanRecordSource: reviewStore,
  })

  const summary = await evaluateFailures()
  const plainText = renderFailureSurfacingPlainText(summary)
  const json = renderFailureSurfacingJson(summary)

  assert.match(plainText, /Total scans: 0/)
  assert.match(plainText, /Matched failure patterns: 0/)
  assert.match(plainText, /Known failure matches:\n- none/)
  assert.deepEqual(JSON.parse(json), {
    total_records_scanned: 0,
    total_matches: 0,
    failures: [],
  })
})

function createRecord({
  recordId = 'record-1',
  packageName = 'root',
  packageVersion = '1.0.0',
  rootOverrides = {},
}: {
  recordId?: string
  packageName?: string
  packageVersion?: string
  rootOverrides?: Partial<ScanReviewRecord['root']>
} = {}): ScanReviewRecord {
  return {
    record_id: recordId,
    created_at: '2026-04-01T00:00:00.000Z',
    scan_mode: 'registry_package',
    package: { name: packageName, version: packageVersion },
    package_key: `${packageName}@${packageVersion}`,
    scan_target: `${packageName}@${packageVersion}`,
    baseline_identity: {
      scan_mode: 'registry_package',
      scan_target: `${packageName}@${packageVersion}`,
      requested_depth: 3,
      workspace_identity: '/tmp/workspace',
    },
    baseline_key: `registry_package::${packageName}@${packageVersion}::depth=3::workspace=/tmp/workspace`,
    baseline_record_id: null,
    requested_depth: 3,
    threshold: 0.4,
    field_reliability: createFieldReliabilityReport(),
    raw_score: 0.1,
    risk_level: 'safe',
    signals: [],
    findings: [],
    root: {
      name: packageName,
      version: packageVersion,
      key: `${packageName}@${packageVersion}`,
      depth: 0,
      is_project_root: false,
      metadata_status: 'enriched',
      metadata_warning: null,
      lockfile_resolved_url: null,
      lockfile_integrity: null,
      age_days: 100,
      weekly_downloads: 10000,
      dependents_count: null,
      deprecated_message: null,
      is_security_tombstone: false,
      published_at: '2026-01-01T00:00:00.000Z',
      first_published: '2026-01-01T00:00:00.000Z',
      last_published: '2026-03-01T00:00:00.000Z',
      total_versions: 10,
      dependency_count: 0,
      publish_events_last_30_days: 0,
      has_advisories: false,
      risk_score: 0.1,
      risk_level: 'safe',
      signals: [],
      recommendation: 'install',
      dependencies: [],
      ...rootOverrides,
    },
    total_scanned: 1,
    suspicious_count: 0,
    safe_count: 1,
    scan_duration_ms: 1,
    dependency_edges: [],
    edge_findings: [],
    warnings: [],
  }
}

function createNode(overrides: Partial<ScanReviewRecord['root']>): ScanReviewRecord['root'] {
  return {
    name: 'child',
    version: '1.0.0',
    key: 'child@1.0.0',
    depth: 1,
    is_project_root: false,
    metadata_status: 'enriched',
    metadata_warning: null,
    lockfile_resolved_url: null,
    lockfile_integrity: null,
    age_days: 100,
    weekly_downloads: 10000,
    dependents_count: null,
    deprecated_message: null,
    is_security_tombstone: false,
    published_at: '2026-01-01T00:00:00.000Z',
    first_published: '2026-01-01T00:00:00.000Z',
    last_published: '2026-03-01T00:00:00.000Z',
    total_versions: 10,
    dependency_count: 0,
    publish_events_last_30_days: 0,
    has_advisories: false,
    risk_score: 0.1,
    risk_level: 'safe',
    signals: [],
    recommendation: 'install',
    dependencies: [],
    ...overrides,
  }
}
