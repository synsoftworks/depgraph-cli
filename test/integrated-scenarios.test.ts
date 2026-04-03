import assert from 'node:assert/strict'
import { mkdtemp, readFile } from 'node:fs/promises'
import { join } from 'node:path'
import { tmpdir } from 'node:os'
import test from 'node:test'

import {
  JsonlScanReviewStore,
  defaultScanReviewStorePaths,
} from '../src/adapters/jsonl-scan-review-store.js'
import { createEvaluateScansUseCase } from '../src/application/evaluate-scans.js'
import { createResolveReviewStateIndexUseCase } from '../src/application/resolve-review-state-index.js'
import { createReviewScanUseCase } from '../src/application/review-scan.js'
import { createScanPackageUseCase } from '../src/application/scan-package.js'
import type { PackageMetadata } from '../src/domain/contracts.js'
import type { DependencyTraverser, RiskScorer, TraversedDependencyGraph } from '../src/domain/ports.js'
import { reviewTargetScopeKey } from '../src/domain/review-targets.js'

class MutableTraverser implements DependencyTraverser {
  constructor(private graph: TraversedDependencyGraph) {}

  setGraph(graph: TraversedDependencyGraph): void {
    this.graph = graph
  }

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

test('Scenario A: repeat scan with the same projected structure does not create diff escalation', async () => {
  const workingDirectory = await mkdtemp(join(tmpdir(), 'depgraph-scenario-a-'))
  const store = new JsonlScanReviewStore(defaultScanReviewStorePaths(workingDirectory))
  const traverser = new MutableTraverser(createGraph(['child@1.0.0']))
  const scorer = new StubScorer({
    'root@1.0.0': 0.1,
    'child@1.0.0': 0,
  })

  const baselineScan = createScanPackageUseCase({
    traverser,
    scorer,
    reviewStore: store,
    now: () => new Date('2026-04-01T00:00:00.000Z'),
  })
  const repeatScan = createScanPackageUseCase({
    traverser,
    scorer,
    reviewStore: store,
    now: () => new Date('2026-04-02T00:00:00.000Z'),
  })

  const firstResult = await baselineScan({
    package_spec: 'root',
    max_depth: 3,
    threshold: 0.4,
    verbose: false,
    workspace_identity: workingDirectory,
  })
  const secondResult = await repeatScan({
    package_spec: 'root',
    max_depth: 3,
    threshold: 0.4,
    verbose: false,
    workspace_identity: workingDirectory,
  })
  const scanHistory = await readFile(defaultScanReviewStorePaths(workingDirectory).scanRecordsPath, 'utf8')

  assert.deepEqual(firstResult.edge_findings, [])
  assert.deepEqual(secondResult.edge_findings, [])
  assert.equal(firstResult.overall_risk_level, secondResult.overall_risk_level)
  assert.deepEqual(secondResult.root.signals, [])
  assert.equal(scanHistory.trim().split('\n').length, 2)
})

test('Scenario B: a suspicious new direct projected edge is captured as both an edge event and package finding', async () => {
  const workingDirectory = await mkdtemp(join(tmpdir(), 'depgraph-scenario-b-'))
  const store = new JsonlScanReviewStore(defaultScanReviewStorePaths(workingDirectory))
  const traverser = new MutableTraverser(createGraph(['trusted@1.0.0']))
  const scorer = new StubScorer({
    'root@1.0.0': 0.1,
    'trusted@1.0.0': 0,
    'new-child@1.0.0': 0.8,
  })

  const baselineScan = createScanPackageUseCase({
    traverser,
    scorer,
    reviewStore: store,
    now: () => new Date('2026-04-01T00:00:00.000Z'),
  })
  const changedScan = createScanPackageUseCase({
    traverser,
    scorer,
    reviewStore: store,
    now: () => new Date('2026-04-02T00:00:00.000Z'),
  })

  const baselineResult = await baselineScan({
    package_spec: 'root',
    max_depth: 3,
    threshold: 0.4,
    verbose: false,
    workspace_identity: workingDirectory,
  })

  traverser.setGraph(createGraph(['trusted@1.0.0', 'new-child@1.0.0']))

  const changedResult = await changedScan({
    package_spec: 'root',
    max_depth: 3,
    threshold: 0.4,
    verbose: false,
    workspace_identity: workingDirectory,
  })
  const scanHistory = await readFile(defaultScanReviewStorePaths(workingDirectory).scanRecordsPath, 'utf8')

  assert.equal(baselineResult.overall_risk_level, 'safe')
  assert.equal(changedResult.edge_findings.length, 1)
  assert.deepEqual(changedResult.edge_findings[0], {
    parent_key: 'root@1.0.0',
    child_key: 'new-child@1.0.0',
    path: ['root@1.0.0', 'new-child@1.0.0'],
    depth: 1,
    edge_type: 'direct',
    review_target: {
      kind: 'edge_finding',
      record_id: changedResult.record_id,
      target_id: 'edge_finding:direct:root@1.0.0->new-child@1.0.0',
      edge_finding_key: 'edge_finding:direct:root@1.0.0->new-child@1.0.0',
      parent_key: 'root@1.0.0',
      child_key: 'new-child@1.0.0',
      edge_type: 'direct',
    },
    baseline_record_id: baselineResult.record_id,
    baseline_identity: {
      scan_target: 'root',
      requested_depth: 3,
      workspace_identity: workingDirectory,
    },
    reason:
      `new direct dependency edge root@1.0.0 -> new-child@1.0.0 via root@1.0.0 > new-child@1.0.0 compared with baseline 2026-04-01T00:00:00.000Z`,
    recommendation: 'review',
  })
  assert.deepEqual(
    changedResult.findings.map((finding) => finding.key),
    ['new-child@1.0.0'],
  )
  assert.equal(changedResult.overall_risk_level, 'critical')
  assert.equal(changedResult.root.signals[0]?.type, 'new_direct_dependency_edge')
  assert.equal(changedResult.root.signals[0]?.value, 'root@1.0.0->new-child@1.0.0')
  assert.equal(scanHistory.trim().split('\n').length, 2)
})

test('Scenario C: review progression preserves append-only history and canonical label resolution', async () => {
  const workingDirectory = await mkdtemp(join(tmpdir(), 'depgraph-scenario-c-'))
  const store = new JsonlScanReviewStore(defaultScanReviewStorePaths(workingDirectory))
  const traverser = new MutableTraverser(createGraph(['child@1.0.0']))
  const scorer = new StubScorer({
    'root@1.0.0': 0.1,
    'child@1.0.0': 0.8,
  })
  const scanPackage = createScanPackageUseCase({
    traverser,
    scorer,
    reviewStore: store,
    now: () => new Date('2026-04-01T00:00:00.000Z'),
  })
  const reviewBenign = createReviewScanUseCase({
    reviewStore: store,
    now: () => new Date('2026-04-02T00:00:00.000Z'),
  })
  const reviewNeedsReview = createReviewScanUseCase({
    reviewStore: store,
    now: () => new Date('2026-04-03T00:00:00.000Z'),
  })
  const reviewMalicious = createReviewScanUseCase({
    reviewStore: store,
    now: () => new Date('2026-04-04T00:00:00.000Z'),
  })
  const resolveReviewStateIndex = createResolveReviewStateIndexUseCase({
    reviewEventSource: store,
  })
  const evaluateScans = createEvaluateScansUseCase({
    scanRecordSource: store,
    rawReviewEventSource: store,
    resolveReviewStateIndex,
  })

  const scanResult = await scanPackage({
    package_spec: 'root',
    max_depth: 3,
    threshold: 0.4,
    verbose: false,
    workspace_identity: workingDirectory,
  })
  const reviewTarget = scanResult.findings[0]?.review_target

  assert.ok(reviewTarget)

  await reviewBenign({
    record_id: scanResult.record_id,
    outcome: 'benign',
    notes: 'manual validation',
    review_source: 'human',
    confidence: 0.9,
  })
  let resolvedReviewStateIndex = await resolveReviewStateIndex()
  assert.equal(resolvedReviewStateIndex.get(reviewTargetScopeKey(reviewTarget!))?.canonical_label, 'benign')
  assert.equal(resolvedReviewStateIndex.get(reviewTargetScopeKey(reviewTarget!))?.workflow_status, 'resolved')

  await reviewNeedsReview({
    record_id: scanResult.record_id,
    outcome: 'needs_review',
    notes: 're-check requested',
    review_source: 'human',
    confidence: 0.8,
  })
  resolvedReviewStateIndex = await resolveReviewStateIndex()
  assert.equal(resolvedReviewStateIndex.get(reviewTargetScopeKey(reviewTarget!))?.canonical_label, 'benign')
  assert.equal(resolvedReviewStateIndex.get(reviewTargetScopeKey(reviewTarget!))?.workflow_status, 'needs_review')

  await reviewMalicious({
    record_id: scanResult.record_id,
    outcome: 'malicious',
    notes: 'confirmed compromise',
    review_source: 'human',
    confidence: 0.95,
  })

  const summary = await evaluateScans()
  const reviewEventLines = (
    await readFile(defaultScanReviewStorePaths(workingDirectory).reviewEventsPath, 'utf8')
  )
    .trim()
    .split('\n')
    .map((line) => JSON.parse(line) as { outcome: string })

  assert.deepEqual(reviewEventLines.map((event) => event.outcome), [
    'benign',
    'needs_review',
    'malicious',
  ])
  assert.equal(summary.raw_review_events.total_events, 3)
  assert.equal(summary.raw_review_events.benign_events, 1)
  assert.equal(summary.raw_review_events.needs_review_events, 1)
  assert.equal(summary.raw_review_events.malicious_events, 1)
  assert.equal(summary.review_targets.total_targets, 1)
  assert.equal(summary.canonical_labels.total_labeled_targets, 1)
  assert.equal(summary.canonical_labels.malicious_targets, 1)
  assert.equal(summary.canonical_labels.benign_targets, 0)
  assert.equal(summary.workflow_status.resolved_targets, 1)
  assert.equal(summary.workflow_status.needs_review_targets, 0)
})

function createGraph(children: string[]): TraversedDependencyGraph {
  return {
    root_key: 'root@1.0.0',
    nodes: [
      createTraversedNode('root@1.0.0', 0, null, ['root@1.0.0']),
      ...children.map((child) => createTraversedNode(child, 1, 'root@1.0.0', ['root@1.0.0', child])),
    ],
  }
}

function createTraversedNode(
  key: string,
  depth: number,
  parentKey: string | null,
  path: string[],
) {
  const [name, version] = key.split('@')

  return {
    key,
    package: { name, version },
    metadata: createMetadata(name, version),
    depth,
    parent_key: parentKey,
    path: {
      packages: path.map((packageKey) => {
        const [pathName, pathVersion] = packageKey.split('@')

        return { name: pathName, version: pathVersion }
      }),
    },
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
