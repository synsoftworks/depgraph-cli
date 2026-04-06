import assert from 'node:assert/strict'
import { resolve } from 'node:path'
import test from 'node:test'

import { run } from '../src/cli/index.js'
import type { EvaluationSummary, ReviewEvent } from '../src/domain/contracts.js'
import type { FailureSurfacingSummary } from '../src/domain/failure-surfacing.js'
import { createFieldReliabilityReport } from '../src/domain/field-reliability-policy.js'
import { NetworkFailureError } from '../src/domain/errors.js'
import type { ScanResult } from '../src/domain/entities.js'

class MemoryStream {
  buffer = ''

  write(text: string): void {
    this.buffer += text
  }
}

function createResult(suspiciousCount = 0): ScanResult {
  return {
    record_id: '2026-04-01T00:00:00.000Z:root@1.0.0:depth=3',
    scan_mode: 'registry_package',
    scan_target: 'root',
    baseline_record_id: null,
    requested_depth: 3,
    threshold: 0.4,
    field_reliability: createFieldReliabilityReport(),
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
      age_days: 10,
      weekly_downloads: 1000,
      dependents_count: null,
      deprecated_message: null,
      is_security_tombstone: false,
      published_at: '2026-03-01T00:00:00.000Z',
      first_published: '2026-01-01T00:00:00.000Z',
      last_published: '2026-03-01T00:00:00.000Z',
      total_versions: 3,
      dependency_count: 1,
      publish_events_last_30_days: 1,
      has_advisories: false,
      dependents_count: null,
      risk_score: suspiciousCount > 0 ? 0.8 : 0.1,
      risk_level: suspiciousCount > 0 ? 'critical' : 'safe',
      signals: [],
      recommendation: suspiciousCount > 0 ? 'do_not_install' : 'install',
      dependencies: [],
    },
    edge_findings: [],
    findings:
      suspiciousCount > 0
        ? [
            {
              key: 'root@1.0.0',
              name: 'root',
              version: '1.0.0',
              depth: 0,
              review_target: {
                kind: 'package_finding',
                record_id: '2026-04-01T00:00:00.000Z:root@1.0.0:depth=3',
                target_id: 'package_finding:root@1.0.0',
                finding_key: 'package_finding:root@1.0.0',
                package_key: 'root@1.0.0',
              },
              path: {
                packages: [{ name: 'root', version: '1.0.0' }],
              },
              risk_score: 0.8,
              risk_level: 'critical',
              recommendation: 'do_not_install',
              signals: [],
              explanation: 'test',
            },
          ]
        : [],
    total_scanned: 1,
    suspicious_count: suspiciousCount,
    safe_count: suspiciousCount > 0 ? 0 : 1,
    overall_risk_score: suspiciousCount > 0 ? 0.8 : 0.1,
    overall_risk_level: suspiciousCount > 0 ? 'critical' : 'safe',
    warnings: [],
    scan_duration_ms: 0,
    timestamp: '2026-04-01T00:00:00.000Z',
  }
}

async function resolveProjectScan(projectPath: string) {
  return {
    scan_mode: 'package_lock' as const,
    package_lock_path: `${projectPath}/package-lock.json`,
    project_root: projectPath,
    max_depth: 3,
    threshold: 0.4,
    verbose: false,
    workspace_identity: projectPath,
  }
}

async function resolvePnpmProjectScan(projectPath: string) {
  return {
    scan_mode: 'pnpm_lock' as const,
    pnpm_lock_path: `${projectPath}/pnpm-lock.yaml`,
    project_root: projectPath,
    max_depth: 3,
    threshold: 0.4,
    verbose: false,
    workspace_identity: projectPath,
  }
}

function createReviewEvent(): ReviewEvent {
  return {
    event_id: '2026-04-02T00:00:00.000Z:package_finding:root@1.0.0:benign',
    record_id: '2026-04-01T00:00:00.000Z:root@1.0.0:depth=3',
    review_target: {
      kind: 'package_finding',
      record_id: '2026-04-01T00:00:00.000Z:root@1.0.0:depth=3',
      target_id: 'package_finding:root@1.0.0',
      finding_key: 'package_finding:root@1.0.0',
      package_key: 'root@1.0.0',
    },
    created_at: '2026-04-02T00:00:00.000Z',
    outcome: 'benign',
    notes: 'reviewed',
    resolution_timestamp: '2026-04-02T00:00:00.000Z',
    review_source: 'human',
    confidence: 0.91,
  }
}

function createEvaluationSummary(): EvaluationSummary {
  return {
    total_scans: 3,
    review_targets: {
      total_targets: 3,
      package_finding_targets: 2,
      edge_finding_targets: 1,
    },
    raw_review_events: {
      total_events: 3,
      malicious_events: 1,
      benign_events: 1,
      needs_review_events: 1,
    },
    canonical_labels: {
      total_labeled_targets: 2,
      malicious_targets: 1,
      benign_targets: 1,
      unlabeled_targets: 1,
      derived_from: 'source_precedence_then_latest_within_source',
    },
    workflow_status: {
      unreviewed_targets: 1,
      needs_review_targets: 1,
      resolved_targets: 1,
    },
    signal_frequency: [
      { type: 'test_signal', count: 2 },
      { type: 'new_transitive_dependency_edge', count: 1 },
    ],
    metadata_coverage: {
      weekly_downloads: {
        total_nodes: 6,
        missing_count: 2,
        missing_percent: 33.33,
      },
      dependents_count: {
        total_nodes: 6,
        missing_count: 4,
        missing_percent: 66.67,
      },
      signal_frequency_by_weekly_downloads: {
        known: [{ type: 'test_signal', count: 2 }],
        missing: [{ type: 'new_transitive_dependency_edge', count: 1 }],
      },
      signal_frequency_by_dependents_count: {
        known: [],
        missing: [
          { type: 'test_signal', count: 2 },
          { type: 'new_transitive_dependency_edge', count: 1 },
        ],
      },
    },
    field_reliability_distribution: {
      records_with_field_reliability: 1,
      records_excluded_missing_field_reliability: 1,
      reliable: 15,
      conditionally_reliable: 1,
      unavailable: 1,
      placeholder: 1,
      heuristic_output: 15,
      structural_only: 15,
      scan_context: 17,
    },
    integrity_signals: {
      synthetic_project_root_count: 1,
      unresolved_registry_lookup_count: 1,
      deprecated_with_security_signal_count: 1,
    },
    field_readiness_issues: {
      dependents_count_unavailable_count: 4,
      has_advisories_placeholder_count: 4,
      records_missing_field_reliability_count: 1,
    },
    heuristic_output_presence: {
      nodes_with_risk_score: 4,
      nodes_with_risk_level: 4,
      nodes_with_recommendation: 4,
      nodes_with_signals: 4,
    },
    export_readiness: {
      total_package_rows: 5,
      rows_with_reliability_metadata: 3,
      usable_rows: 0,
      excluded_rows: 5,
      excluded_missing_weekly_downloads: 1,
      excluded_unresolved_registry_lookup: 1,
      excluded_placeholder_fields: 1,
      excluded_missing_reliability_metadata: 2,
      package_level_excluded_rows: 3,
    },
  }
}

function createFailureSurfacingSummary(): FailureSurfacingSummary {
  return {
    total_records_scanned: 2,
    total_matches: 1,
    failures: [
      {
        package: 'next',
        version: '15.1.7',
        failure_class: 'underweighted_signal',
        status: 'historical_match',
        record_ids: ['record-1'],
        reason:
          'Security-related deprecation language was present, but the package remained below the review threshold in persisted scan history.',
      },
    ],
  }
}

test('CLI uses plain text renderer for --no-tui and returns suspicious exit code', async () => {
  const stdout = new MemoryStream()
  const stderr = new MemoryStream()
  let inkCalls = 0
  let plainCalls = 0

  const exitCode = await run(['scan', 'root', '--no-tui'], {
    scanPackage: async () => createResult(1),
    resolveProjectScan,
    reviewScan: async () => createReviewEvent(),
    evaluateFailures: async () => createFailureSurfacingSummary(),
    evaluateScans: async () => createEvaluationSummary(),
    renderJson: () => {
      throw new Error('JSON renderer should not be used.')
    },
    renderPlainText: () => {
      plainCalls += 1
      return 'plain text output'
    },
    renderReviewJson: () => '',
    renderReviewPlainText: () => '',
    renderFailureJson: () => '',
    renderFailurePlainText: () => '',
    renderEvaluationJson: () => '',
    renderEvaluationPlainText: () => '',
    renderInk: async () => {
      inkCalls += 1
    },
    stdout,
    stderr,
    isTty: true,
  })

  assert.equal(exitCode, 1)
  assert.equal(plainCalls, 1)
  assert.equal(inkCalls, 0)
  assert.match(stdout.buffer, /plain text output/)
  assert.equal(stderr.buffer, '')
})

test('CLI returns invalid usage exit code for malformed arguments', async () => {
  const stdout = new MemoryStream()
  const stderr = new MemoryStream()

  const exitCode = await run(['scan'], {
    scanPackage: async () => createResult(),
    resolveProjectScan,
    reviewScan: async () => createReviewEvent(),
    evaluateFailures: async () => createFailureSurfacingSummary(),
    evaluateScans: async () => createEvaluationSummary(),
    renderJson: () => '',
    renderPlainText: () => '',
    renderReviewJson: () => '',
    renderReviewPlainText: () => '',
    renderFailureJson: () => '',
    renderFailurePlainText: () => '',
    renderEvaluationJson: () => '',
    renderEvaluationPlainText: () => '',
    renderInk: async () => {},
    stdout,
    stderr,
    isTty: true,
  })

  assert.equal(exitCode, 2)
})

test('CLI maps network failures to exit code 3', async () => {
  const stdout = new MemoryStream()
  const stderr = new MemoryStream()

  const exitCode = await run(['scan', 'root', '--json'], {
    scanPackage: async () => {
      throw new NetworkFailureError('registry down')
    },
    resolveProjectScan,
    reviewScan: async () => createReviewEvent(),
    evaluateFailures: async () => createFailureSurfacingSummary(),
    evaluateScans: async () => createEvaluationSummary(),
    renderJson: () => JSON.stringify(createResult()),
    renderPlainText: () => '',
    renderReviewJson: () => '',
    renderReviewPlainText: () => '',
    renderFailureJson: () => '',
    renderFailurePlainText: () => '',
    renderEvaluationJson: () => '',
    renderEvaluationPlainText: () => '',
    renderInk: async () => {},
    stdout,
    stderr,
    isTty: true,
  })

  assert.equal(exitCode, 3)
  assert.match(stderr.buffer, /registry down/)
})

test('CLI review command forwards explicit target ids deterministically', async () => {
  const stdout = new MemoryStream()
  const stderr = new MemoryStream()
  let reviewCalls = 0

  const exitCode = await run(['review', 'scan-record-id', '--target', 'package_finding:root@1.0.0', '--outcome', 'benign', '--notes', 'checked', '--confidence', '0.8'], {
    scanPackage: async () => createResult(),
    resolveProjectScan,
    reviewScan: async (request) => {
      reviewCalls += 1
      assert.deepEqual(request, {
        record_id: 'scan-record-id',
        target_id: 'package_finding:root@1.0.0',
        outcome: 'benign',
        notes: 'checked',
        review_source: 'human',
        confidence: 0.8,
      })

      return createReviewEvent()
    },
    evaluateFailures: async () => createFailureSurfacingSummary(),
    evaluateScans: async () => createEvaluationSummary(),
    renderJson: () => '',
    renderPlainText: () => '',
    renderReviewJson: () => {
      throw new Error('Review JSON renderer should not be used.')
    },
    renderReviewPlainText: () => 'review output',
    renderFailureJson: () => '',
    renderFailurePlainText: () => '',
    renderEvaluationJson: () => '',
    renderEvaluationPlainText: () => '',
    renderInk: async () => {},
    stdout,
    stderr,
    isTty: true,
  })

  assert.equal(exitCode, 0)
  assert.equal(reviewCalls, 1)
  assert.match(stdout.buffer, /review output/)
  assert.equal(stderr.buffer, '')
})

test('CLI scan forwards explicit package-lock scans as package_lock mode', async () => {
  const stdout = new MemoryStream()
  const stderr = new MemoryStream()
  let scanCalls = 0

  const exitCode = await run(['scan', '--package-lock', './package-lock.json', '--json'], {
    scanPackage: async (request) => {
      scanCalls += 1
      assert.deepEqual(request, {
        scan_mode: 'package_lock',
        package_lock_path: resolve('./package-lock.json'),
        project_root: process.cwd(),
        max_depth: 3,
        threshold: 0.4,
        verbose: false,
        workspace_identity: process.cwd(),
      })

      return createResult()
    },
    resolveProjectScan,
    reviewScan: async () => createReviewEvent(),
    evaluateFailures: async () => createFailureSurfacingSummary(),
    evaluateScans: async () => createEvaluationSummary(),
    renderJson: () => JSON.stringify(createResult()),
    renderPlainText: () => '',
    renderReviewJson: () => '',
    renderReviewPlainText: () => '',
    renderFailureJson: () => '',
    renderFailurePlainText: () => '',
    renderEvaluationJson: () => '',
    renderEvaluationPlainText: () => '',
    renderInk: async () => {},
    stdout,
    stderr,
    isTty: true,
  })

  assert.equal(exitCode, 0)
  assert.equal(scanCalls, 1)
  assert.equal(stderr.buffer, '')
})

test('CLI scan resolves --project through project detection before scanning', async () => {
  const stdout = new MemoryStream()
  const stderr = new MemoryStream()
  let resolverCalls = 0
  let scanCalls = 0

  const exitCode = await run(['scan', '--project', '.'], {
    scanPackage: async (request) => {
      scanCalls += 1
      assert.deepEqual(request, {
        scan_mode: 'package_lock',
        package_lock_path: '/tmp/example-project/package-lock.json',
        project_root: '/tmp/example-project',
        max_depth: 3,
        threshold: 0.4,
        verbose: false,
        workspace_identity: '/tmp/example-project',
      })

      return createResult()
    },
    resolveProjectScan: async () => {
      resolverCalls += 1

      return {
        scan_mode: 'package_lock',
        package_lock_path: '/tmp/example-project/package-lock.json',
        project_root: '/tmp/example-project',
        max_depth: 3,
        threshold: 0.4,
        verbose: false,
        workspace_identity: '/tmp/example-project',
      }
    },
    reviewScan: async () => createReviewEvent(),
    evaluateFailures: async () => createFailureSurfacingSummary(),
    evaluateScans: async () => createEvaluationSummary(),
    renderJson: () => '',
    renderPlainText: () => 'plain text output',
    renderReviewJson: () => '',
    renderReviewPlainText: () => '',
    renderFailureJson: () => '',
    renderFailurePlainText: () => '',
    renderEvaluationJson: () => '',
    renderEvaluationPlainText: () => '',
    renderInk: async () => {},
    stdout,
    stderr,
    isTty: false,
  })

  assert.equal(exitCode, 0)
  assert.equal(resolverCalls, 1)
  assert.equal(scanCalls, 1)
  assert.match(stdout.buffer, /plain text output/)
  assert.equal(stderr.buffer, '')
})

test('CLI scan forwards explicit pnpm-lock scans as pnpm_lock mode', async () => {
  const stdout = new MemoryStream()
  const stderr = new MemoryStream()
  let scanCalls = 0

  const exitCode = await run(['scan', '--pnpm-lock', './pnpm-lock.yaml', '--json'], {
    scanPackage: async (request) => {
      scanCalls += 1
      assert.deepEqual(request, {
        scan_mode: 'pnpm_lock',
        pnpm_lock_path: resolve('./pnpm-lock.yaml'),
        project_root: process.cwd(),
        max_depth: 3,
        threshold: 0.4,
        verbose: false,
        workspace_identity: process.cwd(),
      })

      return createResult()
    },
    resolveProjectScan,
    reviewScan: async () => createReviewEvent(),
    evaluateFailures: async () => createFailureSurfacingSummary(),
    evaluateScans: async () => createEvaluationSummary(),
    renderJson: () => JSON.stringify(createResult()),
    renderPlainText: () => '',
    renderReviewJson: () => '',
    renderReviewPlainText: () => '',
    renderFailureJson: () => '',
    renderFailurePlainText: () => '',
    renderEvaluationJson: () => '',
    renderEvaluationPlainText: () => '',
    renderInk: async () => {},
    stdout,
    stderr,
    isTty: true,
  })

  assert.equal(exitCode, 0)
  assert.equal(scanCalls, 1)
  assert.equal(stderr.buffer, '')
})

test('CLI scan resolves pnpm projects through project detection before scanning', async () => {
  const stdout = new MemoryStream()
  const stderr = new MemoryStream()
  let resolverCalls = 0
  let scanCalls = 0

  const exitCode = await run(['scan', '--project', '.'], {
    scanPackage: async (request) => {
      scanCalls += 1
      assert.deepEqual(request, {
        scan_mode: 'pnpm_lock',
        pnpm_lock_path: '/tmp/example-project/pnpm-lock.yaml',
        project_root: '/tmp/example-project',
        max_depth: 3,
        threshold: 0.4,
        verbose: false,
        workspace_identity: '/tmp/example-project',
      })

      return createResult()
    },
    resolveProjectScan: async () => {
      resolverCalls += 1
      return resolvePnpmProjectScan('/tmp/example-project')
    },
    reviewScan: async () => createReviewEvent(),
    evaluateFailures: async () => createFailureSurfacingSummary(),
    evaluateScans: async () => createEvaluationSummary(),
    renderJson: () => '',
    renderPlainText: () => 'plain text output',
    renderReviewJson: () => '',
    renderReviewPlainText: () => '',
    renderFailureJson: () => '',
    renderFailurePlainText: () => '',
    renderEvaluationJson: () => '',
    renderEvaluationPlainText: () => '',
    renderInk: async () => {},
    stdout,
    stderr,
    isTty: false,
  })

  assert.equal(exitCode, 0)
  assert.equal(resolverCalls, 1)
  assert.equal(scanCalls, 1)
  assert.match(stdout.buffer, /plain text output/)
  assert.equal(stderr.buffer, '')
})

test('CLI eval command renders evaluation summaries deterministically', async () => {
  const stdout = new MemoryStream()
  const stderr = new MemoryStream()
  let evalCalls = 0

  const exitCode = await run(['eval'], {
    scanPackage: async () => createResult(),
    resolveProjectScan,
    reviewScan: async () => createReviewEvent(),
    evaluateFailures: async () => createFailureSurfacingSummary(),
    evaluateScans: async () => {
      evalCalls += 1
      return createEvaluationSummary()
    },
    renderJson: () => '',
    renderPlainText: () => '',
    renderReviewJson: () => '',
    renderReviewPlainText: () => '',
    renderFailureJson: () => '',
    renderFailurePlainText: () => '',
    renderEvaluationJson: () => '',
    renderEvaluationPlainText: () => 'eval output',
    renderInk: async () => {},
    stdout,
    stderr,
    isTty: true,
  })

  assert.equal(exitCode, 0)
  assert.equal(evalCalls, 1)
  assert.match(stdout.buffer, /eval output/)
  assert.equal(stderr.buffer, '')
})

test('CLI eval --failures renders failure surfacing deterministically', async () => {
  const stdout = new MemoryStream()
  const stderr = new MemoryStream()
  let failureCalls = 0
  let evalCalls = 0

  const exitCode = await run(['eval', '--failures'], {
    scanPackage: async () => createResult(),
    resolveProjectScan,
    reviewScan: async () => createReviewEvent(),
    evaluateFailures: async () => {
      failureCalls += 1
      return createFailureSurfacingSummary()
    },
    evaluateScans: async () => {
      evalCalls += 1
      return createEvaluationSummary()
    },
    renderJson: () => '',
    renderPlainText: () => '',
    renderReviewJson: () => '',
    renderReviewPlainText: () => '',
    renderFailureJson: () => '',
    renderFailurePlainText: () => 'failure output',
    renderEvaluationJson: () => '',
    renderEvaluationPlainText: () => 'eval output',
    renderInk: async () => {},
    stdout,
    stderr,
    isTty: true,
  })

  assert.equal(exitCode, 0)
  assert.equal(failureCalls, 1)
  assert.equal(evalCalls, 0)
  assert.match(stdout.buffer, /failure output/)
  assert.equal(stderr.buffer, '')
})

test('CLI eval --json --failures emits failure-only JSON output explicitly', async () => {
  const stdout = new MemoryStream()
  const stderr = new MemoryStream()

  const exitCode = await run(['eval', '--json', '--failures'], {
    scanPackage: async () => createResult(),
    resolveProjectScan,
    reviewScan: async () => createReviewEvent(),
    evaluateFailures: async () => createFailureSurfacingSummary(),
    evaluateScans: async () => createEvaluationSummary(),
    renderJson: () => '',
    renderPlainText: () => '',
    renderReviewJson: () => '',
    renderReviewPlainText: () => '',
    renderFailureJson: (summary) => JSON.stringify(summary),
    renderFailurePlainText: () => '',
    renderEvaluationJson: () => JSON.stringify(createEvaluationSummary()),
    renderEvaluationPlainText: () => '',
    renderInk: async () => {},
    stdout,
    stderr,
    isTty: true,
  })

  assert.equal(exitCode, 0)
  assert.deepEqual(JSON.parse(stdout.buffer), createFailureSurfacingSummary())
  assert.equal(stderr.buffer, '')
})

test('CLI scan help explains the current tree projection semantics', async () => {
  const stdout = new MemoryStream()
  const stderr = new MemoryStream()

  const exitCode = await run(['scan', '--help'], {
    scanPackage: async () => createResult(),
    resolveProjectScan,
    reviewScan: async () => createReviewEvent(),
    evaluateFailures: async () => createFailureSurfacingSummary(),
    evaluateScans: async () => createEvaluationSummary(),
    renderJson: () => '',
    renderPlainText: () => '',
    renderReviewJson: () => '',
    renderReviewPlainText: () => '',
    renderFailureJson: () => '',
    renderFailurePlainText: () => '',
    renderEvaluationJson: () => '',
    renderEvaluationPlainText: () => '',
    renderInk: async () => {},
    stdout,
    stderr,
    isTty: true,
  })

  assert.equal(exitCode, 0)
  assert.match(stdout.buffer, /Package-spec scans use registry metadata/)
  assert.match(stdout.buffer, /Project scans currently support package-lock\.json and pnpm-lock\.yaml/)
  assert.match(stdout.buffer, /--pnpm-lock <path>/)
  assert.equal(stderr.buffer, '')
})
