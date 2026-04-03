import assert from 'node:assert/strict'
import test from 'node:test'

import { createScanPackageUseCase } from '../src/application/scan-package.js'
import type {
  BaselineIdentity,
  DependencyGraphEdge,
  EdgeFinding,
  PackageMetadata,
  ReviewEvent,
  ScanReviewRecord,
} from '../src/domain/contracts.js'
import type { PackageNode } from '../src/domain/entities.js'
import type {
  DependencyTraverser,
  RiskScorer,
  ScanReviewStore,
  TraversedDependencyGraph,
} from '../src/domain/ports.js'

class StubTraverser implements DependencyTraverser {
  constructor(private readonly graph: TraversedDependencyGraph) {}

  async traverse(): Promise<TraversedDependencyGraph> {
    return this.graph
  }
}

class StubScorer implements RiskScorer {
  constructor(private readonly scores: Record<string, number>) {}

  assessPackage(metadata: PackageMetadata) {
    const score = this.scores[`${metadata.package.name}@${metadata.package.version}`] ?? 0
    const riskLevel = score > 0.7 ? 'critical' : score >= 0.4 ? 'review' : 'safe'

    return {
      risk_score: score,
      risk_level: riskLevel,
      recommendation:
        riskLevel === 'critical' ? 'do_not_install' : riskLevel === 'review' ? 'review' : 'install',
      signals:
        score >= 0.4
          ? [
              {
                type: 'test_signal',
                value: score,
                weight: 'medium' as const,
                reason: `score ${score}`,
              },
            ]
          : [],
    }
  }
}

class InMemoryReviewStore implements ScanReviewStore {
  records: ScanReviewRecord[]
  reviewEvents: ReviewEvent[] = []
  failLookup = false

  constructor(initialRecords: ScanReviewRecord[] = []) {
    this.records = [...initialRecords]
  }

  async appendScanRecord(record: ScanReviewRecord): Promise<void> {
    this.records.push(record)
  }

  async findLatestScanByBaseline(baselineIdentity: BaselineIdentity): Promise<ScanReviewRecord | null> {
    if (this.failLookup) {
      throw new Error('history unavailable')
    }

    for (let index = this.records.length - 1; index >= 0; index -= 1) {
      const record = this.records[index]

      if (
        record?.baseline_identity.scan_target === baselineIdentity.scan_target &&
        record.baseline_identity.requested_depth === baselineIdentity.requested_depth &&
        record.baseline_identity.workspace_identity === baselineIdentity.workspace_identity
      ) {
        return record
      }
    }

    return null
  }

  async findScanRecord(recordId: string): Promise<ScanReviewRecord | null> {
    return this.records.find((record) => record.record_id === recordId) ?? null
  }

  async appendReviewEvent(event: ReviewEvent): Promise<void> {
    this.reviewEvents.push(event)
  }

  async listScanRecords(): Promise<ScanReviewRecord[]> {
    return this.records
  }

  async listReviewEvents(): Promise<ReviewEvent[]> {
    return this.reviewEvents
  }
}

function createMetadata(name: string, version: string): PackageMetadata {
  return {
    package: { name, version },
    dependencies: {},
    published_at: '2026-03-01T00:00:00.000Z',
    first_published_at: '2026-01-01T00:00:00.000Z',
    last_published_at: '2026-03-01T00:00:00.000Z',
    total_versions: 3,
    publish_events_last_30_days: 1,
    weekly_downloads: 1000,
    deprecated_message: null,
    is_security_tombstone: false,
    has_advisories: false,
    dependents_count: null,
  }
}

test('scan use case orders findings by depth, score, then lexical key', async () => {
  const reviewStore = new InMemoryReviewStore()
  const scanPackage = createScanPackageUseCase({
    traverser: new StubTraverser({
      root_key: 'root@1.0.0',
      nodes: [
        {
          key: 'root@1.0.0',
          package: { name: 'root', version: '1.0.0' },
          metadata: createMetadata('root', '1.0.0'),
          depth: 0,
          parent_key: null,
          path: {
            packages: [{ name: 'root', version: '1.0.0' }],
          },
        },
        {
          key: 'beta@1.0.0',
          package: { name: 'beta', version: '1.0.0' },
          metadata: createMetadata('beta', '1.0.0'),
          depth: 1,
          parent_key: 'root@1.0.0',
          path: {
            packages: [
              { name: 'root', version: '1.0.0' },
              { name: 'beta', version: '1.0.0' },
            ],
          },
        },
        {
          key: 'alpha@1.0.0',
          package: { name: 'alpha', version: '1.0.0' },
          metadata: createMetadata('alpha', '1.0.0'),
          depth: 1,
          parent_key: 'root@1.0.0',
          path: {
            packages: [
              { name: 'root', version: '1.0.0' },
              { name: 'alpha', version: '1.0.0' },
            ],
          },
        },
        {
          key: 'gamma@1.0.0',
          package: { name: 'gamma', version: '1.0.0' },
          metadata: createMetadata('gamma', '1.0.0'),
          depth: 2,
          parent_key: 'beta@1.0.0',
          path: {
            packages: [
              { name: 'root', version: '1.0.0' },
              { name: 'beta', version: '1.0.0' },
              { name: 'gamma', version: '1.0.0' },
            ],
          },
        },
      ],
    }),
    scorer: new StubScorer({
      'root@1.0.0': 0.1,
      'alpha@1.0.0': 0.8,
      'beta@1.0.0': 0.8,
      'gamma@1.0.0': 0.9,
    }),
    reviewStore,
    now: () => new Date('2026-04-01T00:00:00.000Z'),
  })

  const result = await scanPackage({
    package_spec: 'root',
    max_depth: 3,
    threshold: 0.4,
    verbose: false,
  })

  assert.deepEqual(
    result.findings.map((finding) => finding.key),
    ['alpha@1.0.0', 'beta@1.0.0', 'gamma@1.0.0'],
  )
  assert.equal(result.suspicious_count, 3)
  assert.equal(result.safe_count, 1)
  assert.deepEqual(result.edge_findings, [])
  assert.equal(reviewStore.records.length, 1)
})

test('threshold changes suspicious classification without changing raw scores', async () => {
  const reviewStore = new InMemoryReviewStore()
  const scanPackage = createScanPackageUseCase({
    traverser: new StubTraverser({
      root_key: 'root@1.0.0',
      nodes: [
        {
          key: 'root@1.0.0',
          package: { name: 'root', version: '1.0.0' },
          metadata: createMetadata('root', '1.0.0'),
          depth: 0,
          parent_key: null,
          path: {
            packages: [{ name: 'root', version: '1.0.0' }],
          },
        },
        {
          key: 'child@1.0.0',
          package: { name: 'child', version: '1.0.0' },
          metadata: createMetadata('child', '1.0.0'),
          depth: 1,
          parent_key: 'root@1.0.0',
          path: {
            packages: [
              { name: 'root', version: '1.0.0' },
              { name: 'child', version: '1.0.0' },
            ],
          },
        },
      ],
    }),
    scorer: new StubScorer({
      'root@1.0.0': 0.1,
      'child@1.0.0': 0.5,
    }),
    reviewStore,
    now: () => new Date('2026-04-01T00:00:00.000Z'),
  })

  const reviewThreshold = await scanPackage({
    package_spec: 'root',
    max_depth: 3,
    threshold: 0.4,
    verbose: false,
  })
  const stricterThreshold = await scanPackage({
    package_spec: 'root',
    max_depth: 3,
    threshold: 0.6,
    verbose: false,
  })

  assert.equal(reviewThreshold.findings[0]?.risk_score, 0.5)
  assert.equal(stricterThreshold.findings.length, 0)
  assert.equal(reviewThreshold.root.dependencies[0]?.risk_score, 0.5)
  assert.equal(stricterThreshold.root.dependencies[0]?.risk_score, 0.5)
  assert.deepEqual(reviewThreshold.edge_findings, [])
})

test('scan use case persists a durable scan review record after the scan completes', async () => {
  const reviewStore = new InMemoryReviewStore()
  const scanPackage = createScanPackageUseCase({
    traverser: new StubTraverser({
      root_key: 'root@1.0.0',
      nodes: [
        {
          key: 'root@1.0.0',
          package: { name: 'root', version: '1.0.0' },
          metadata: createMetadata('root', '1.0.0'),
          depth: 0,
          parent_key: null,
          path: {
            packages: [{ name: 'root', version: '1.0.0' }],
          },
        },
        {
          key: 'child@1.0.0',
          package: { name: 'child', version: '1.0.0' },
          metadata: createMetadata('child', '1.0.0'),
          depth: 1,
          parent_key: 'root@1.0.0',
          path: {
            packages: [
              { name: 'root', version: '1.0.0' },
              { name: 'child', version: '1.0.0' },
            ],
          },
        },
      ],
    }),
    scorer: new StubScorer({
      'root@1.0.0': 0.1,
      'child@1.0.0': 0.8,
    }),
    reviewStore,
    now: () => new Date('2026-04-01T00:00:00.000Z'),
  })

  await scanPackage({
    package_spec: 'root',
    max_depth: 3,
    threshold: 0.4,
    verbose: false,
  })

  assert.equal(reviewStore.records.length, 1)
  assert.deepEqual(reviewStore.records[0], {
    record_id: '2026-04-01T00:00:00.000Z:root@1.0.0:depth=3',
    created_at: '2026-04-01T00:00:00.000Z',
    package: { name: 'root', version: '1.0.0' },
    package_key: 'root@1.0.0',
    scan_target: 'root',
    baseline_identity: {
      scan_target: 'root',
      requested_depth: 3,
      workspace_identity: 'local',
    },
    baseline_key: 'root::depth=3::workspace=local',
    baseline_record_id: null,
    requested_depth: 3,
    threshold: 0.4,
    raw_score: 0.8,
    risk_level: 'critical',
    signals: [],
    findings: [
      {
        key: 'child@1.0.0',
        name: 'child',
        version: '1.0.0',
        depth: 1,
        review_target: {
          kind: 'package_finding',
          record_id: '2026-04-01T00:00:00.000Z:root@1.0.0:depth=3',
          target_id: 'package_finding:child@1.0.0',
          finding_key: 'package_finding:child@1.0.0',
          package_key: 'child@1.0.0',
        },
        path: {
          packages: [
            { name: 'root', version: '1.0.0' },
            { name: 'child', version: '1.0.0' },
          ],
        },
        risk_score: 0.8,
        risk_level: 'critical',
        recommendation: 'do_not_install',
        signals: [
          {
            type: 'test_signal',
            value: 0.8,
            weight: 'medium',
            reason: 'score 0.8',
          },
        ],
        explanation: 'score 0.8',
      },
    ],
    root: {
      name: 'root',
      version: '1.0.0',
      key: 'root@1.0.0',
      depth: 0,
      age_days: 31,
      weekly_downloads: 1000,
      dependents_count: null,
      deprecated_message: null,
      is_security_tombstone: false,
      published_at: '2026-03-01T00:00:00.000Z',
      first_published: '2026-01-01T00:00:00.000Z',
      last_published: '2026-03-01T00:00:00.000Z',
      total_versions: 3,
      dependency_count: 0,
      publish_events_last_30_days: 1,
      has_advisories: false,
      risk_score: 0.1,
      risk_level: 'safe',
      signals: [],
      recommendation: 'install',
      dependencies: [
        {
          name: 'child',
          version: '1.0.0',
          key: 'child@1.0.0',
          depth: 1,
          age_days: 31,
          weekly_downloads: 1000,
          dependents_count: null,
          deprecated_message: null,
          is_security_tombstone: false,
          published_at: '2026-03-01T00:00:00.000Z',
          first_published: '2026-01-01T00:00:00.000Z',
          last_published: '2026-03-01T00:00:00.000Z',
          total_versions: 3,
          dependency_count: 0,
          publish_events_last_30_days: 1,
          has_advisories: false,
          risk_score: 0.8,
          risk_level: 'critical',
          signals: [
            {
              type: 'test_signal',
              value: 0.8,
              weight: 'medium',
              reason: 'score 0.8',
            },
          ],
          recommendation: 'do_not_install',
          dependencies: [],
        },
      ],
    },
    total_scanned: 2,
    suspicious_count: 1,
    safe_count: 1,
    scan_duration_ms: 0,
    dependency_edges: [
      {
        from: 'root@1.0.0',
        to: 'child@1.0.0',
        child_depth: 1,
      },
    ],
    edge_findings: [],
  })
})

test('dependency graph delta is omitted when there is no prior scan', async () => {
  const reviewStore = new InMemoryReviewStore()
  const scanPackage = createScanPackageUseCase({
    traverser: new StubTraverser(createLinearGraph()),
    scorer: new StubScorer({
      'root@1.0.0': 0.1,
      'child@1.0.0': 0,
    }),
    reviewStore,
    now: () => new Date('2026-04-01T00:00:00.000Z'),
  })

  const result = await scanPackage({
    package_spec: 'root',
    max_depth: 3,
    threshold: 0.4,
    verbose: false,
  })

  assert.equal(result.root.signals.length, 0)
  assert.deepEqual(result.edge_findings, [])
  assert.deepEqual(reviewStore.records[0]?.signals, [])
  assert.deepEqual(reviewStore.records[0]?.edge_findings, [])
})

test('dependency graph delta is omitted when the prior scan has identical edges', async () => {
  const reviewStore = new InMemoryReviewStore([
    createStoredRecord({
      dependencyEdges: [
        { from: 'root@1.0.0', to: 'child@1.0.0', child_depth: 1 },
      ],
    }),
  ])
  const scanPackage = createScanPackageUseCase({
    traverser: new StubTraverser(createLinearGraph()),
    scorer: new StubScorer({
      'root@1.0.0': 0.1,
      'child@1.0.0': 0,
    }),
    reviewStore,
    now: () => new Date('2026-04-01T00:00:00.000Z'),
  })

  const result = await scanPackage({
    package_spec: 'root',
    max_depth: 3,
    threshold: 0.4,
    verbose: false,
  })

  assert.equal(result.root.signals.length, 0)
  assert.deepEqual(result.edge_findings, [])
  assert.deepEqual(reviewStore.records.at(-1)?.signals, [])
  assert.deepEqual(reviewStore.records.at(-1)?.edge_findings, [])
})

test('dependency graph delta records newly introduced edges against the latest prior scan', async () => {
  const reviewStore = new InMemoryReviewStore([
    createStoredRecord({
      dependencyEdges: [
        { from: 'root@1.0.0', to: 'child@1.0.0', child_depth: 1 },
      ],
    }),
  ])
  const scanPackage = createScanPackageUseCase({
    traverser: new StubTraverser({
      root_key: 'root@1.0.0',
      nodes: [
        {
          key: 'root@1.0.0',
          package: { name: 'root', version: '1.0.0' },
          metadata: createMetadata('root', '1.0.0'),
          depth: 0,
          parent_key: null,
          path: {
            packages: [{ name: 'root', version: '1.0.0' }],
          },
        },
        {
          key: 'child@1.0.0',
          package: { name: 'child', version: '1.0.0' },
          metadata: createMetadata('child', '1.0.0'),
          depth: 1,
          parent_key: 'root@1.0.0',
          path: {
            packages: [
              { name: 'root', version: '1.0.0' },
              { name: 'child', version: '1.0.0' },
            ],
          },
        },
        {
          key: 'grandchild@1.0.0',
          package: { name: 'grandchild', version: '1.0.0' },
          metadata: createMetadata('grandchild', '1.0.0'),
          depth: 2,
          parent_key: 'child@1.0.0',
          path: {
            packages: [
              { name: 'root', version: '1.0.0' },
              { name: 'child', version: '1.0.0' },
              { name: 'grandchild', version: '1.0.0' },
            ],
          },
        },
      ],
    }),
    scorer: new StubScorer({
      'root@1.0.0': 0.1,
      'child@1.0.0': 0,
      'grandchild@1.0.0': 0,
    }),
    reviewStore,
    now: () => new Date('2026-04-02T00:00:00.000Z'),
  })

  const result = await scanPackage({
    package_spec: 'root',
    max_depth: 3,
    threshold: 0.4,
    verbose: false,
  })

  assert.equal(result.root.signals.length, 1)
  assert.equal(result.root.signals[0]?.type, 'new_transitive_dependency_edge')
  assert.equal(result.root.signals[0]?.value, 'child@1.0.0->grandchild@1.0.0')
  assert.match(
    result.root.signals[0]?.reason ?? '',
    /child@1\.0\.0 -> grandchild@1\.0\.0/,
  )
  assert.deepEqual(reviewStore.records.at(-1)?.signals, result.root.signals)
  assert.deepEqual(result.edge_findings, [
    createEdgeFinding({
      parentKey: 'child@1.0.0',
      childKey: 'grandchild@1.0.0',
      path: ['root@1.0.0', 'child@1.0.0', 'grandchild@1.0.0'],
      depth: 2,
      edgeType: 'transitive',
      baselineRecordId: '2026-03-31T00:00:00.000Z:root@1.0.0:depth=3',
    }),
  ])
  assert.deepEqual(reviewStore.records.at(-1)?.edge_findings, result.edge_findings)
})

test('dependency graph delta lookup degrades gracefully when history lookup fails', async () => {
  const reviewStore = new InMemoryReviewStore()
  reviewStore.failLookup = true

  const scanPackage = createScanPackageUseCase({
    traverser: new StubTraverser(createLinearGraph()),
    scorer: new StubScorer({
      'root@1.0.0': 0.1,
      'child@1.0.0': 0,
    }),
    reviewStore,
    now: () => new Date('2026-04-01T00:00:00.000Z'),
  })

  const result = await scanPackage({
    package_spec: 'root',
    max_depth: 3,
    threshold: 0.4,
    verbose: false,
  })

  assert.equal(result.root.signals.length, 0)
  assert.equal(reviewStore.records.length, 1)
})

test('baseline identity requires matching workspace identity before applying delta', async () => {
  const reviewStore = new InMemoryReviewStore([
    createStoredRecord({
      dependencyEdges: [],
      workspaceIdentity: '/tmp/other-workspace',
    }),
  ])
  const scanPackage = createScanPackageUseCase({
    traverser: new StubTraverser(createLinearGraph()),
    scorer: new StubScorer({
      'root@1.0.0': 0.1,
      'child@1.0.0': 0,
    }),
    reviewStore,
    now: () => new Date('2026-04-01T00:00:00.000Z'),
  })

  const result = await scanPackage({
    package_spec: 'root',
    max_depth: 3,
    threshold: 0.4,
    verbose: false,
    workspace_identity: '/tmp/current-workspace',
  })

  assert.equal(result.baseline_record_id, null)
  assert.deepEqual(result.edge_findings, [])
})

function createLinearGraph(): TraversedDependencyGraph {
  return {
    root_key: 'root@1.0.0',
    nodes: [
      {
        key: 'root@1.0.0',
        package: { name: 'root', version: '1.0.0' },
        metadata: createMetadata('root', '1.0.0'),
        depth: 0,
        parent_key: null,
        path: {
          packages: [{ name: 'root', version: '1.0.0' }],
        },
      },
      {
        key: 'child@1.0.0',
        package: { name: 'child', version: '1.0.0' },
        metadata: createMetadata('child', '1.0.0'),
        depth: 1,
        parent_key: 'root@1.0.0',
        path: {
          packages: [
            { name: 'root', version: '1.0.0' },
            { name: 'child', version: '1.0.0' },
          ],
        },
      },
    ],
  }
}

function createStoredRecord({
  dependencyEdges,
  workspaceIdentity = 'local',
}: {
  dependencyEdges: DependencyGraphEdge[]
  workspaceIdentity?: string
}): ScanReviewRecord {
  const root = createStoredPackageNode()

  return {
    record_id: '2026-03-31T00:00:00.000Z:root@1.0.0:depth=3',
    created_at: '2026-03-31T00:00:00.000Z',
    package: { name: 'root', version: '1.0.0' },
    package_key: 'root@1.0.0',
    scan_target: 'root',
    baseline_identity: {
      scan_target: 'root',
      requested_depth: 3,
      workspace_identity: workspaceIdentity,
    },
    baseline_key: `root::depth=3::workspace=${workspaceIdentity}`,
    baseline_record_id: null,
    requested_depth: 3,
    threshold: 0.4,
    raw_score: 0.1,
    risk_level: 'safe',
    signals: [],
    findings: [],
    root,
    total_scanned: 2,
    suspicious_count: 0,
    safe_count: 2,
    scan_duration_ms: 0,
    dependency_edges: dependencyEdges,
    edge_findings: [],
  }
}

function createEdgeFinding({
  parentKey,
  childKey,
  path,
  depth,
  edgeType,
  baselineRecordId,
}: {
  parentKey: string
  childKey: string
  path: string[]
  depth: number
  edgeType: 'direct' | 'transitive'
  baselineRecordId: string
}): EdgeFinding {
  return {
    parent_key: parentKey,
    child_key: childKey,
    path,
    depth,
    edge_type: edgeType,
    review_target: {
      kind: 'edge_finding',
      record_id: '2026-04-02T00:00:00.000Z:root@1.0.0:depth=3',
      target_id: `edge_finding:${edgeType}:${parentKey}->${childKey}`,
      edge_finding_key: `edge_finding:${edgeType}:${parentKey}->${childKey}`,
      parent_key: parentKey,
      child_key: childKey,
      edge_type: edgeType,
    },
    baseline_record_id: baselineRecordId,
    baseline_identity: {
      scan_target: 'root',
      requested_depth: 3,
      workspace_identity: 'local',
    },
    reason: `new ${edgeType} dependency edge ${parentKey} -> ${childKey} via ${path.join(' > ')} compared with baseline 2026-03-31T00:00:00.000Z`,
    recommendation: 'review',
  }
}

function createStoredPackageNode(): PackageNode {
  return {
    name: 'root',
    version: '1.0.0',
    key: 'root@1.0.0',
    depth: 0,
    age_days: 31,
    weekly_downloads: 1000,
    dependents_count: null,
    deprecated_message: null,
    is_security_tombstone: false,
    published_at: '2026-03-01T00:00:00.000Z',
    first_published: '2026-01-01T00:00:00.000Z',
    last_published: '2026-03-01T00:00:00.000Z',
    total_versions: 3,
    dependency_count: 0,
    publish_events_last_30_days: 1,
    has_advisories: false,
    risk_score: 0.1,
    risk_level: 'safe',
    signals: [],
    recommendation: 'install',
    dependencies: [],
  }
}
