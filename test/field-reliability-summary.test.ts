import assert from 'node:assert/strict'
import test from 'node:test'

import { createFieldReliabilityReport } from '../src/domain/field-reliability-policy.js'
import type { ScanResult } from '../src/domain/entities.js'
import { getFieldReliabilityPolicySummary } from '../src/interface/field-reliability-summary.js'

test('field reliability summary stays compact and aligned for text and Ink renderers', () => {
  const lines = getFieldReliabilityPolicySummary(createResult())

  assert.deepEqual(lines, [
    'weekly_downloads: conditionally reliable',
    'dependents_count: not populated',
    'has_advisories: placeholder only',
    'risk_score, risk_level, signals, and recommendation are heuristic outputs, not ground truth',
    '"safe" means below the configured threshold, not verified benign',
    'warnings describe scan-time incompleteness and provenance, not package-behavior truth',
  ])
})

function createResult(): ScanResult {
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
      dependency_count: 0,
      publish_events_last_30_days: 1,
      has_advisories: false,
      risk_score: 0.1,
      risk_level: 'safe',
      signals: [],
      recommendation: 'install',
      dependencies: [],
    },
    edge_findings: [],
    findings: [],
    total_scanned: 1,
    suspicious_count: 0,
    safe_count: 1,
    overall_risk_score: 0.1,
    overall_risk_level: 'safe',
    warnings: [],
    scan_duration_ms: 0,
    timestamp: '2026-04-01T00:00:00.000Z',
  }
}
