import assert from 'node:assert/strict'
import test from 'node:test'

import { HeuristicRiskScorer } from '../src/adapters/heuristic-risk-scorer.js'
import type { PackageMetadata } from '../src/domain/contracts.js'

const NOW = new Date('2026-04-01T00:00:00.000Z')

function createMetadata(overrides: Partial<PackageMetadata> = {}): PackageMetadata {
  return {
    package: {
      name: 'risky-package',
      version: '1.0.0',
    },
    dependencies: {},
    published_at: '2026-03-29T00:00:00.000Z',
    first_published_at: '2026-03-29T00:00:00.000Z',
    last_published_at: '2026-03-29T00:00:00.000Z',
    total_versions: 1,
    publish_events_last_30_days: 4,
    weekly_downloads: 50,
    deprecated_message: null,
    is_security_tombstone: false,
    has_advisories: false,
    dependents_count: null,
    ...overrides,
  }
}

test('heuristic scorer is deterministic for the same metadata', () => {
  const scorer = new HeuristicRiskScorer(() => NOW)
  const metadata = createMetadata()

  const first = scorer.assessPackage(metadata, {
    depth: 1,
    path: {
      packages: [
        { name: 'root', version: '1.0.0' },
        { name: 'risky-package', version: '1.0.0' },
      ],
    },
    dependency_count: 0,
  })
  const second = scorer.assessPackage(metadata, {
    depth: 1,
    path: {
      packages: [
        { name: 'root', version: '1.0.0' },
        { name: 'risky-package', version: '1.0.0' },
      ],
    },
    dependency_count: 0,
  })

  assert.deepEqual(first, second)
  assert.equal(first.risk_level, 'critical')
  assert.ok(first.signals.length >= 4)
})

test('heuristic scorer flags zero-download injection pattern aggressively', () => {
  const scorer = new HeuristicRiskScorer(() => NOW)
  const metadata = createMetadata({
    weekly_downloads: 0,
    total_versions: 1,
    published_at: '2026-03-31T00:00:00.000Z',
  })

  const result = scorer.assessPackage(metadata, {
    depth: 1,
    path: {
      packages: [
        { name: 'root', version: '1.0.0' },
        { name: 'risky-package', version: '1.0.0' },
      ],
    },
    dependency_count: 0,
  })

  assert.equal(result.risk_level, 'critical')
  assert.equal(result.risk_score, 1)
  assert.ok(result.signals.some((signal) => signal.type === 'zero_downloads'))
  assert.ok(result.signals.some((signal) => signal.type === 'new_and_unproven'))
})

test('heuristic scorer treats security tombstones as critical regardless of inherited download counts', () => {
  const scorer = new HeuristicRiskScorer(() => NOW)
  const metadata = createMetadata({
    published_at: '2026-03-31T00:00:00.000Z',
    weekly_downloads: null,
    deprecated_message: 'security placeholder package; original package was malicious',
    is_security_tombstone: true,
  })

  const result = scorer.assessPackage(metadata, {
    depth: 0,
    path: {
      packages: [{ name: 'plain-crypto-js', version: '0.0.1-security.0' }],
    },
    dependency_count: 0,
  })

  assert.equal(result.risk_level, 'critical')
  assert.equal(result.risk_score, 1)
  assert.ok(result.signals.some((signal) => signal.type === 'security_tombstone'))
  assert.ok(!result.signals.some((signal) => signal.type === 'low_weekly_downloads'))
})

test('heuristic scorer escalates deprecations with security language to review', () => {
  const scorer = new HeuristicRiskScorer(() => NOW)
  const metadata = createMetadata({
    package: {
      name: 'next',
      version: '15.1.7',
    },
    published_at: '2024-01-01T00:00:00.000Z',
    first_published_at: '2024-01-01T00:00:00.000Z',
    last_published_at: '2026-03-31T00:00:00.000Z',
    total_versions: 50,
    weekly_downloads: 1_000_000,
    publish_events_last_30_days: 0,
    deprecated_message:
      'This version has a security vulnerability. Please upgrade. See CVE-2025-66478.',
  })

  const result = scorer.assessPackage(metadata, {
    depth: 0,
    path: {
      packages: [{ name: 'next', version: '15.1.7' }],
    },
    dependency_count: 0,
  })

  assert.equal(result.risk_level, 'review')
  assert.ok(result.risk_score >= 0.4)
  assert.ok(result.signals.some((signal) => signal.type === 'deprecated_package'))
  assert.ok(result.signals.some((signal) => signal.type === 'security_deprecation_language'))
})

test('heuristic scorer does not escalate routine deprecations without security language', () => {
  const scorer = new HeuristicRiskScorer(() => NOW)
  const metadata = createMetadata({
    published_at: '2024-01-01T00:00:00.000Z',
    first_published_at: '2024-01-01T00:00:00.000Z',
    last_published_at: '2026-03-31T00:00:00.000Z',
    total_versions: 50,
    weekly_downloads: 1_000_000,
    publish_events_last_30_days: 0,
    deprecated_message: 'Package renamed to example-next. Please migrate.',
  })

  const result = scorer.assessPackage(metadata, {
    depth: 0,
    path: {
      packages: [{ name: 'risky-package', version: '1.0.0' }],
    },
    dependency_count: 0,
  })

  assert.equal(result.risk_level, 'safe')
  assert.equal(result.risk_score, 0.16)
  assert.ok(result.signals.some((signal) => signal.type === 'deprecated_package'))
  assert.ok(!result.signals.some((signal) => signal.type === 'security_deprecation_language'))
})
