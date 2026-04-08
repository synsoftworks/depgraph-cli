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
      primaryFindingKey: 'grandchild@1.0.0',
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
  assert.equal(latest?.primary_finding_key, 'grandchild@1.0.0')
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

test('JSONL scan review store normalizes legacy scan records without baseline identity metadata', async () => {
  const workingDirectory = await mkdtemp(join(tmpdir(), 'depgraph-jsonl-'))
  const paths = defaultScanReviewStorePaths(workingDirectory)
  const store = new JsonlScanReviewStore(paths)

  await writeLegacyScanRecord(paths.scanRecordsPath)

  const records = await store.listScanRecords()
  const record = records[0]

  assert.equal(record?.scan_mode, 'registry_package')
  assert.deepEqual(record?.baseline_identity, {
    scan_mode: 'registry_package',
    scan_target: 'legacy-root',
    requested_depth: 2,
    workspace_identity: 'local',
  })
  assert.equal(record?.baseline_key, 'registry_package::legacy-root::depth=2::workspace=local')
  assert.equal(record?.edge_findings.length, 1)
  assert.equal(record?.warnings.length, 0)
})

test('JSONL scan review store backfills primary_finding_key for legacy transitive findings', async () => {
  const workingDirectory = await mkdtemp(join(tmpdir(), 'depgraph-jsonl-'))
  const paths = defaultScanReviewStorePaths(workingDirectory)
  const store = new JsonlScanReviewStore(paths)

  await writeLegacyTransitiveFindingScanRecord(paths.scanRecordsPath)

  const records = await store.listScanRecords()

  assert.equal(records[0]?.primary_finding_key, 'legacy-child@1.0.0')
  assert.equal(records[0]?.findings[0]?.depth, 1)
})

function createRecord({
  recordId,
  createdAt,
  scanTarget,
  packageKey,
  workspaceIdentity,
  dependencyEdges,
  scanMode = 'registry_package',
  primaryFindingKey,
}: {
  recordId: string
  createdAt: string
  scanTarget: string
  packageKey: string
  workspaceIdentity: string
  dependencyEdges: DependencyGraphEdge[]
  scanMode?: ScanReviewRecord['scan_mode']
  primaryFindingKey?: string
}): ScanReviewRecord {
  return {
    record_id: recordId,
    created_at: createdAt,
    scan_mode: scanMode,
    package: { name: 'root', version: packageKey.split('@').at(-1) ?? '1.0.0' },
    package_key: packageKey,
    scan_target: scanTarget,
    ...(primaryFindingKey !== undefined ? { primary_finding_key: primaryFindingKey } : {}),
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
    warnings: [],
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

async function writeLegacyScanRecord(path: string): Promise<void> {
  const { appendFile, mkdir } = await import('node:fs/promises')
  const { dirname } = await import('node:path')

  await mkdir(dirname(path), { recursive: true })

  await appendFile(
    path,
    `${JSON.stringify({
      record_id: 'legacy-scan-1',
      created_at: '2026-04-01T00:00:00.000Z',
      package: { name: 'legacy-root', version: '1.0.0' },
      package_key: 'legacy-root@1.0.0',
      scan_target: 'legacy-root',
      baseline_key: 'legacy-root::depth=2',
      baseline_record_id: null,
      requested_depth: 2,
      threshold: 0.4,
      raw_score: 0,
      risk_level: 'safe',
      signals: [],
      findings: [],
      root: {
        name: 'legacy-root',
        version: '1.0.0',
        key: 'legacy-root@1.0.0',
        depth: 0,
        age_days: 10,
        weekly_downloads: 1000,
        dependents_count: null,
        deprecated_message: null,
        is_security_tombstone: false,
        published_at: '2026-03-22T00:00:00.000Z',
        first_published: '2026-03-22T00:00:00.000Z',
        last_published: '2026-03-22T00:00:00.000Z',
        total_versions: 1,
        dependency_count: 0,
        publish_events_last_30_days: 1,
        has_advisories: false,
        risk_score: 0,
        risk_level: 'safe',
        signals: [],
        recommendation: 'install',
        dependencies: [],
      },
      total_scanned: 1,
      suspicious_count: 0,
      safe_count: 1,
      scan_duration_ms: 1,
      dependency_edges: [],
      new_dependency_edge_findings: [
        {
          parent_key: 'legacy-root@1.0.0',
          child_key: 'child@1.0.0',
          path: ['legacy-root@1.0.0', 'child@1.0.0'],
          depth: 1,
          edge_type: 'direct',
          baseline_record_id: null,
          baseline_identity: {
            scan_mode: 'registry_package',
            scan_target: 'legacy-root',
            requested_depth: 2,
            workspace_identity: 'local',
          },
          reason: 'legacy edge finding',
          recommendation: 'review',
        },
      ],
    })}\n`,
    'utf8',
  )
}

async function writeLegacyTransitiveFindingScanRecord(path: string): Promise<void> {
  const { appendFile, mkdir } = await import('node:fs/promises')
  const { dirname } = await import('node:path')

  await mkdir(dirname(path), { recursive: true })

  await appendFile(
    path,
    `${JSON.stringify({
      record_id: 'legacy-scan-2',
      created_at: '2026-04-02T00:00:00.000Z',
      package: { name: 'legacy-root', version: '1.0.0' },
      package_key: 'legacy-root@1.0.0',
      scan_target: 'legacy-root',
      baseline_key: 'legacy-root::depth=2',
      baseline_record_id: null,
      requested_depth: 2,
      threshold: 0.4,
      raw_score: 0.48,
      risk_level: 'review',
      signals: [],
      findings: [
        {
          key: 'legacy-child@1.0.0',
          name: 'legacy-child',
          version: '1.0.0',
          depth: 1,
          path: {
            packages: [
              { name: 'legacy-root', version: '1.0.0' },
              { name: 'legacy-child', version: '1.0.0' },
            ],
          },
          risk_score: 0.48,
          risk_level: 'review',
          recommendation: 'review',
          signals: [],
          explanation: 'legacy transitive finding',
        },
      ],
      root: {
        name: 'legacy-root',
        version: '1.0.0',
        key: 'legacy-root@1.0.0',
        depth: 0,
        age_days: 10,
        weekly_downloads: 1000,
        dependents_count: null,
        deprecated_message: null,
        is_security_tombstone: false,
        published_at: '2026-03-22T00:00:00.000Z',
        first_published: '2026-03-22T00:00:00.000Z',
        last_published: '2026-03-22T00:00:00.000Z',
        total_versions: 1,
        dependency_count: 1,
        publish_events_last_30_days: 1,
        has_advisories: false,
        risk_score: 0.08,
        risk_level: 'safe',
        signals: [],
        recommendation: 'install',
        dependencies: [],
      },
      total_scanned: 2,
      suspicious_count: 1,
      safe_count: 1,
      scan_duration_ms: 1,
      dependency_edges: [],
      warnings: [],
    })}\n`,
    'utf8',
  )
}
