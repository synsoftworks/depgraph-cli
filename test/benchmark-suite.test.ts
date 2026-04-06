import assert from 'node:assert/strict'
import { mkdtemp, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import test from 'node:test'

import { JsonBenchmarkManifestLoader } from '../src/adapters/benchmark-manifest-loader.js'
import { evaluateBenchmarkCase, mapPriorityFromScan } from '../src/application/evaluate-benchmark-case.js'
import { runBenchmarkSuite } from '../src/application/run-benchmark-suite.js'
import type {
  BenchmarkCase,
  BenchmarkManifestLoader,
  BenchmarkScanRunner,
  BenchmarkSuiteResult,
} from '../src/domain/benchmark.js'
import type { ScanWarning } from '../src/domain/contracts.js'
import type { RiskLevel, RiskSignal, ScanResult } from '../src/domain/entities.js'
import { renderBenchmarkSuite } from '../src/interface/benchmark-renderer.js'

class StubBenchmarkScanRunner implements BenchmarkScanRunner {
  readonly packages: string[] = []

  constructor(private readonly results: Map<string, ScanResult> = new Map()) {}

  async runScan(packageSpec: string): Promise<ScanResult> {
    this.packages.push(packageSpec)
    const result = this.results.get(packageSpec)

    if (result === undefined) {
      throw new Error(`missing stub result for ${packageSpec}`)
    }

    return result
  }
}

class StubBenchmarkManifestLoader implements BenchmarkManifestLoader {
  constructor(private readonly benchmarkCases: BenchmarkCase[]) {}

  async loadManifest(): Promise<BenchmarkCase[]> {
    return this.benchmarkCases
  }
}

test('manifest loader loads benchmark availability and optional benchmark notes', async () => {
  const tempDirectory = await mkdtemp(join(tmpdir(), 'depgraph-benchmark-manifest-'))
  const manifestPath = join(tempDirectory, 'benchmark-manifest.json')

  await writeFile(
    manifestPath,
    JSON.stringify([
      {
        id: 'BM-001',
        package: 'next@15.1.7',
        availability: 'private_registry_only',
        skip_reason: 'Only scannable via project lockfile, not registry spec',
        failure_note: 'Expected permanent FAIL in v1.',
        expected_priority: 'high_priority_review',
        expected_signals: ['deprecated_package'],
      },
    ]),
    'utf8',
  )

  const loader = new JsonBenchmarkManifestLoader(manifestPath)
  const manifest = await loader.loadManifest()

  assert.deepEqual(manifest, [
    {
      id: 'BM-001',
      package: 'next@15.1.7',
      availability: 'private_registry_only',
      skip_reason: 'Only scannable via project lockfile, not registry spec',
      failure_note: 'Expected permanent FAIL in v1.',
      expected_priority: 'high_priority_review',
      expected_signals: ['deprecated_package'],
    },
  ])
})

test('non-live benchmark entries return SKIPPED and prefer explicit skip reasons', async () => {
  const scanRunner = new StubBenchmarkScanRunner()
  const result = await evaluateBenchmarkCase(
    {
      id: 'BM-003',
      package: '@gsap/simply@3.12.7',
      availability: 'private_registry_only',
      skip_reason: 'Only scannable via project lockfile, not registry spec',
      expected_priority: 'normal',
      expected_signals: ['unresolved_registry_lookup'],
    },
    { scanRunner },
  )

  assert.equal(result.status, 'SKIPPED')
  assert.equal(result.skip_reason, 'Only scannable via project lockfile, not registry spec')
  assert.deepEqual(scanRunner.packages, [])
})

test('evaluation priority mapping treats threshold hits as high priority and warnings as normal', () => {
  const highPriorityScan = createScanResult({
    riskScore: 0.4,
    threshold: 0.4,
  })
  const warningOnlyScan = createScanResult({
    riskScore: 0.08,
    warnings: [createUnresolvedRegistryWarning()],
  })

  assert.equal(mapPriorityFromScan(highPriorityScan), 'high_priority_review')
  assert.equal(mapPriorityFromScan(warningOnlyScan), 'normal')
})

test('evaluation fails when expected priority does not match actual priority', async () => {
  const scanRunner = new StubBenchmarkScanRunner(
    new Map([
      [
        'next@15.1.7',
        createScanResult({
          riskScore: 0.32,
          signalTypes: ['deprecated_package'],
        }),
      ],
    ]),
  )

  const result = await evaluateBenchmarkCase(
    {
      id: 'BM-001',
      package: 'next@15.1.7',
      availability: 'live',
      expected_priority: 'high_priority_review',
      expected_signals: ['deprecated_package'],
    },
    { scanRunner },
  )

  assert.equal(result.status, 'FAIL')
  assert.equal(result.actual_priority, 'safe')
  assert.match(result.failure_reason ?? '', /expected priority high_priority_review, got safe/)
})

test('expected signals use subset comparison for live benchmarks', async () => {
  const scanRunner = new StubBenchmarkScanRunner(
    new Map([
      [
        '@gsap/simply@3.12.7',
        createScanResult({
          riskScore: 0.08,
          signalTypes: ['rapid_publish_churn'],
          warnings: [createUnresolvedRegistryWarning()],
        }),
      ],
    ]),
  )

  const result = await evaluateBenchmarkCase(
    {
      id: 'BM-004',
      package: '@gsap/simply@3.12.7',
      availability: 'live',
      expected_priority: 'normal',
      expected_signals: ['unresolved_registry_lookup'],
    },
    { scanRunner },
  )

  assert.equal(result.status, 'PASS')
  assert.deepEqual(result.missing_signals, [])
  assert.deepEqual(result.actual_signals, ['rapid_publish_churn', 'unresolved_registry_lookup'])
})

test('renderer includes PASS FAIL SKIPPED lines and summary counts', async () => {
  const benchmarkCases: BenchmarkCase[] = [
    {
      id: 'BM-001',
      package: 'is-number@7.0.0',
      availability: 'live',
      expected_priority: 'safe',
      expected_signals: [],
    },
    {
      id: 'BM-002',
      package: 'next@15.1.7',
      availability: 'live',
      expected_priority: 'high_priority_review',
      expected_signals: ['deprecated_package'],
    },
    {
      id: 'BM-003',
      package: 'isite@2024.8.19',
      availability: 'removed',
      expected_priority: 'high_priority_review',
      expected_signals: ['security_tombstone'],
    },
    {
      id: 'BM-004',
      package: '@gsap/simply@3.12.7',
      availability: 'private_registry_only',
      skip_reason: 'Only scannable via project lockfile, not registry spec',
      expected_priority: 'normal',
      expected_signals: ['unresolved_registry_lookup'],
    },
  ]
  const scanRunner = new StubBenchmarkScanRunner(
    new Map([
      ['is-number@7.0.0', createScanResult({ riskScore: 0 })],
      [
        'next@15.1.7',
        createScanResult({
          riskScore: 0.32,
          signalTypes: ['deprecated_package'],
        }),
      ],
    ]),
  )

  const suiteResult = await runBenchmarkSuite({
    manifestLoader: new StubBenchmarkManifestLoader(benchmarkCases),
    scanRunner,
  })

  const output = renderBenchmarkSuite(suiteResult)

  assert.match(output, /BM-001\s+is-number@7\.0\.0\s+PASS/)
  assert.match(output, /BM-002\s+next@15\.1\.7\s+FAIL/)
  assert.match(output, /BM-003\s+isite@2024\.8\.19\s+SKIPPED/)
  assert.match(output, /BM-004\s+@gsap\/simply@3\.12\.7\s+SKIPPED/)
  assert.match(output, /Only scannable via project lockfile, not registry spec/)
  assert.match(output, /Summary:\n- PASS: 1\n- FAIL: 1\n- SKIPPED: 2/)
  assert.deepEqual(suiteResult.summary, {
    pass: 1,
    fail: 1,
    skipped: 2,
    total: 4,
  } satisfies BenchmarkSuiteResult['summary'])
})

function createScanResult({
  riskScore = 0,
  threshold = 0.4,
  signalTypes = [],
  warnings = [],
}: {
  riskScore?: number
  threshold?: number
  signalTypes?: string[]
  warnings?: ScanWarning[]
} = {}): ScanResult {
  const riskLevel = riskScore > 0.7 ? 'critical' : riskScore >= 0.4 ? 'review' : 'safe'

  return {
    record_id: 'benchmark-record',
    scan_mode: 'package',
    scan_target: 'fixture@1.0.0',
    baseline_record_id: null,
    requested_depth: 3,
    threshold,
    field_reliability: {
      adr: 'ADR-012',
      fields: {},
    },
    root: {
      name: 'fixture',
      version: '1.0.0',
      key: 'fixture@1.0.0',
      depth: 0,
      is_project_root: false,
      metadata_status: 'enriched',
      metadata_warning: null,
      lockfile_resolved_url: null,
      lockfile_integrity: null,
      age_days: 30,
      weekly_downloads: 10000,
      dependents_count: 10,
      deprecated_message: null,
      is_security_tombstone: false,
      published_at: '2026-01-01T00:00:00.000Z',
      first_published: '2026-01-01T00:00:00.000Z',
      last_published: '2026-01-01T00:00:00.000Z',
      total_versions: 5,
      dependency_count: 0,
      publish_events_last_30_days: 1,
      has_advisories: false,
      risk_score: riskScore,
      risk_level: riskLevel,
      signals: signalTypes.map(createRiskSignal),
      recommendation: recommendationForRiskLevel(riskLevel),
      dependencies: [],
    },
    edge_findings: [],
    findings: [],
    total_scanned: 1,
    suspicious_count: riskScore >= threshold ? 1 : 0,
    safe_count: riskScore >= threshold ? 0 : 1,
    overall_risk_score: riskScore,
    overall_risk_level: riskLevel,
    warnings,
    scan_duration_ms: 1,
    timestamp: '2026-04-06T00:00:00.000Z',
  }
}

function createRiskSignal(type: string): RiskSignal {
  return {
    type,
    value: true,
    weight: 'medium',
    reason: `${type} fired`,
  }
}

function createUnresolvedRegistryWarning(): ScanWarning {
  return {
    kind: 'unresolved_registry_lookup',
    package_key: '@gsap/simply@3.12.7',
    package_name: '@gsap/simply',
    package_version: '3.12.7',
    message: 'Registry metadata unavailable.',
    lockfile_resolved_url: null,
    lockfile_integrity: null,
  }
}

function recommendationForRiskLevel(level: RiskLevel): 'install' | 'review' | 'do_not_install' {
  switch (level) {
    case 'critical':
      return 'do_not_install'
    case 'review':
      return 'review'
    default:
      return 'install'
  }
}
