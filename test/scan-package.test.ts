import assert from 'node:assert/strict'
import test from 'node:test'

import { createScanPackageUseCase } from '../src/application/scan-package.js'
import type { PackageMetadata } from '../src/domain/contracts.js'
import type {
  DependencyTraverser,
  RiskScorer,
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
    has_advisories: false,
  }
}

test('scan use case orders findings by depth, score, then lexical key', async () => {
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
})

test('threshold changes suspicious classification without changing raw scores', async () => {
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
})
