import assert from 'node:assert/strict'
import test from 'node:test'

import { createEvaluateScansUseCase } from '../src/application/evaluate-scans.js'
import { createResolveReviewStateIndexUseCase } from '../src/application/resolve-review-state-index.js'
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
  assert.equal(summary.raw_review_events.total_events, 3)
  assert.equal(summary.raw_review_events.benign_events, 1)
  assert.equal(summary.raw_review_events.needs_review_events, 2)
  assert.equal(summary.canonical_labels.total_labeled_records, 1)
  assert.equal(summary.canonical_labels.benign_records, 1)
  assert.equal(summary.canonical_labels.malicious_records, 0)
  assert.equal(summary.canonical_labels.unlabeled_records, 0)
  assert.equal(summary.workflow_status.needs_review_records, 1)
  assert.equal(summary.workflow_status.resolved_records, 0)
  assert.equal(summary.workflow_status.unreviewed_records, 0)
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
})

function createRecord(): ScanReviewRecord {
  return {
    record_id: 'record-1',
    created_at: '2026-04-01T00:00:00.000Z',
    package: { name: 'root', version: '1.0.0' },
    package_key: 'root@1.0.0',
    scan_target: 'root',
    baseline_identity: {
      scan_target: 'root',
      requested_depth: 3,
      workspace_identity: '/tmp/workspace',
    },
    baseline_key: 'root::depth=3::workspace=/tmp/workspace',
    baseline_record_id: null,
    requested_depth: 3,
    threshold: 0.4,
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
    findings: [],
    root: {
      name: 'root',
      version: '1.0.0',
      key: 'root@1.0.0',
      depth: 0,
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
      dependencies: [
        {
          name: 'child',
          version: '1.0.0',
          key: 'child@1.0.0',
          depth: 1,
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
        },
      ],
    },
    total_scanned: 2,
    suspicious_count: 1,
    safe_count: 1,
    scan_duration_ms: 1,
    dependency_edges: [{ from: 'root@1.0.0', to: 'child@1.0.0', child_depth: 1 }],
    edge_findings: [],
  }
}

function createReviewEvent(outcome: ReviewEvent['outcome'], createdAt: string): ReviewEvent {
  return {
    event_id: `${createdAt}:record-1:${outcome}`,
    record_id: 'record-1',
    package_key: 'root@1.0.0',
    created_at: createdAt,
    outcome,
    notes: null,
    resolution_timestamp: outcome === 'needs_review' ? null : createdAt,
    review_source: 'human',
    confidence: 0.9,
  }
}
