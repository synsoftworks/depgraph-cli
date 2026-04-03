import assert from 'node:assert/strict'
import { mkdtemp, readFile } from 'node:fs/promises'
import { join } from 'node:path'
import { tmpdir } from 'node:os'
import test from 'node:test'

import {
  JsonlScanReviewStore,
  defaultScanReviewStorePaths,
} from '../src/adapters/jsonl-scan-review-store.js'
import type { DependencyGraphEdge, ReviewEvent, ScanReviewRecord } from '../src/domain/contracts.js'

test('JSONL scan review store appends records and retrieves the latest matching baseline', async () => {
  const workingDirectory = await mkdtemp(join(tmpdir(), 'depgraph-jsonl-'))
  const paths = defaultScanReviewStorePaths(workingDirectory)
  const store = new JsonlScanReviewStore(paths)

  await store.appendScanRecord(
    createRecord({
      recordId: '1',
      createdAt: '2026-04-01T00:00:00.000Z',
      scanTarget: 'root',
      packageKey: 'root@1.0.0',
      workspaceIdentity: workingDirectory,
      dependencyEdges: [{ from: 'root@1.0.0', to: 'child@1.0.0', child_depth: 1 }],
    }),
  )
  await store.appendScanRecord(
    createRecord({
      recordId: '2',
      createdAt: '2026-04-02T00:00:00.000Z',
      scanTarget: 'root',
      packageKey: 'root@1.1.0',
      workspaceIdentity: workingDirectory,
      dependencyEdges: [
        { from: 'root@1.1.0', to: 'child@1.0.0', child_depth: 1 },
        { from: 'child@1.0.0', to: 'grandchild@1.0.0', child_depth: 2 },
      ],
    }),
  )

  const latest = await store.findLatestScanByBaseline({
    scan_mode: 'registry_package',
    scan_target: 'root',
    requested_depth: 3,
    workspace_identity: workingDirectory,
  })
  const contents = await readFile(paths.scanRecordsPath, 'utf8')

  assert.equal(contents.trim().split('\n').length, 2)
  assert.equal(latest?.record_id, '2')
  assert.equal(latest?.dependency_edges.length, 2)
})

test('JSONL scan review store appends review events without rewriting scan records', async () => {
  const workingDirectory = await mkdtemp(join(tmpdir(), 'depgraph-jsonl-'))
  const paths = defaultScanReviewStorePaths(workingDirectory)
  const store = new JsonlScanReviewStore(paths)

  await store.appendScanRecord(
    createRecord({
      recordId: 'scan-1',
      createdAt: '2026-04-01T00:00:00.000Z',
      scanTarget: 'root',
      packageKey: 'root@1.0.0',
      workspaceIdentity: workingDirectory,
      dependencyEdges: [{ from: 'root@1.0.0', to: 'child@1.0.0', child_depth: 1 }],
    }),
  )
  await store.appendReviewEvent(createReviewEvent('scan-1'))

  const scanContents = await readFile(paths.scanRecordsPath, 'utf8')
  const reviewContents = await readFile(paths.reviewEventsPath, 'utf8')
  const reviewEvents = await store.listReviewEvents()

  assert.equal(scanContents.trim().split('\n').length, 1)
  assert.equal(reviewContents.trim().split('\n').length, 1)
  assert.equal(reviewEvents[0]?.record_id, 'scan-1')
  assert.equal(reviewEvents[0]?.outcome, 'benign')
  assert.equal(reviewEvents[0]?.review_target.target_id, 'package_finding:root@1.0.0')
})

test('JSONL scan review store keeps baseline lookup separated by scan_mode', async () => {
  const workingDirectory = await mkdtemp(join(tmpdir(), 'depgraph-jsonl-'))
  const paths = defaultScanReviewStorePaths(workingDirectory)
  const store = new JsonlScanReviewStore(paths)

  await store.appendScanRecord(
    createRecord({
      recordId: 'registry-record',
      createdAt: '2026-04-01T00:00:00.000Z',
      scanTarget: 'root',
      packageKey: 'root@1.0.0',
      workspaceIdentity: workingDirectory,
      dependencyEdges: [],
      scanMode: 'registry_package',
    }),
  )
  await store.appendScanRecord(
    createRecord({
      recordId: 'lock-record',
      createdAt: '2026-04-02T00:00:00.000Z',
      scanTarget: 'root',
      packageKey: 'root@1.0.0',
      workspaceIdentity: workingDirectory,
      dependencyEdges: [],
      scanMode: 'package_lock',
    }),
  )

  const latestPackageLock = await store.findLatestScanByBaseline({
    scan_mode: 'package_lock',
    scan_target: 'root',
    requested_depth: 3,
    workspace_identity: workingDirectory,
  })

  assert.equal(latestPackageLock?.record_id, 'lock-record')
})

test('JSONL scan review store upgrades legacy review events into explicit package-finding targets', async () => {
  const workingDirectory = await mkdtemp(join(tmpdir(), 'depgraph-jsonl-'))
  const paths = defaultScanReviewStorePaths(workingDirectory)
  const store = new JsonlScanReviewStore(paths)

  await store.appendScanRecord(
    createRecord({
      recordId: 'scan-1',
      createdAt: '2026-04-01T00:00:00.000Z',
      scanTarget: 'root',
      packageKey: 'root@1.0.0',
      workspaceIdentity: workingDirectory,
      dependencyEdges: [],
    }),
  )
  await readFile(paths.scanRecordsPath, 'utf8')
  await writeLegacyReviewEvent(paths.reviewEventsPath)

  const reviewEvents = await store.listReviewEvents()

  assert.equal(reviewEvents[0]?.review_target.kind, 'package_finding')
  assert.equal(reviewEvents[0]?.review_target.target_id, 'package_finding:root@1.0.0')
})

function createRecord({
  recordId,
  createdAt,
  scanTarget,
  packageKey,
  workspaceIdentity,
  dependencyEdges,
  scanMode = 'registry_package',
}: {
  recordId: string
  createdAt: string
  scanTarget: string
  packageKey: string
  workspaceIdentity: string
  dependencyEdges: DependencyGraphEdge[]
  scanMode?: ScanReviewRecord['scan_mode']
}): ScanReviewRecord {
  return {
    record_id: recordId,
    created_at: createdAt,
    scan_mode: scanMode,
    package: { name: 'root', version: packageKey.split('@').at(-1) ?? '1.0.0' },
    package_key: packageKey,
    scan_target: scanTarget,
    baseline_identity: {
      scan_mode: scanMode,
      scan_target: scanTarget,
      requested_depth: 3,
      workspace_identity: workspaceIdentity,
    },
    baseline_key: `${scanMode}::${scanTarget}::depth=3::workspace=${workspaceIdentity}`,
    baseline_record_id: null,
    requested_depth: 3,
    threshold: 0.4,
    raw_score: 0.32,
    risk_level: 'safe',
    signals: [],
    findings: [],
    root: {
      name: 'root',
      version: packageKey.split('@').at(-1) ?? '1.0.0',
      key: packageKey,
      depth: 0,
      is_project_root: false,
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
      risk_score: 0.32,
      risk_level: 'safe',
      signals: [],
      recommendation: 'install',
      dependencies: [],
    },
    total_scanned: 2,
    suspicious_count: 0,
    safe_count: 2,
    scan_duration_ms: 1,
    dependency_edges: dependencyEdges,
    edge_findings: [],
  }
}

function createReviewEvent(recordId: string): ReviewEvent {
  return {
    event_id: `2026-04-03T00:00:00.000Z:package_finding:root@1.0.0:benign`,
    record_id: recordId,
    review_target: {
      kind: 'package_finding',
      record_id: recordId,
      target_id: 'package_finding:root@1.0.0',
      finding_key: 'package_finding:root@1.0.0',
      package_key: 'root@1.0.0',
    },
    created_at: '2026-04-03T00:00:00.000Z',
    outcome: 'benign',
    notes: 'verified expansion',
    resolution_timestamp: '2026-04-03T00:00:00.000Z',
    review_source: 'human',
    confidence: 0.95,
  }
}

async function writeLegacyReviewEvent(path: string): Promise<void> {
  const { appendFile } = await import('node:fs/promises')

  await appendFile(
    path,
    `${JSON.stringify({
      event_id: '2026-04-03T00:00:00.000Z:legacy:benign',
      record_id: 'scan-1',
      package_key: 'root@1.0.0',
      created_at: '2026-04-03T00:00:00.000Z',
      outcome: 'benign',
      notes: 'legacy',
      resolution_timestamp: '2026-04-03T00:00:00.000Z',
      review_source: 'human',
      confidence: 0.95,
    })}\n`,
    'utf8',
  )
}
