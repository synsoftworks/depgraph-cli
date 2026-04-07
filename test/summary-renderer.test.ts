import assert from 'node:assert/strict'
import test from 'node:test'

import { createFieldReliabilityReport } from '../src/domain/field-reliability-policy.js'
import type { ScanResult } from '../src/domain/entities.js'
import { renderSummaryText } from '../src/interface/summary-renderer.js'

test('summary renderer outputs the compact summary counts', () => {
  const output = renderSummaryText(createResult())

  assert.match(
    output,
    /^next@15\.1\.7\n\nreview \(0\.64\)\n\n- packages requiring review: 2\n- findings with security-related signals: 1\n- packages that appear safe: 12$/,
  )
})

test('summary renderer excludes the tree and detailed findings', () => {
  const output = renderSummaryText(createResult())

  assert.doesNotMatch(output, /Dependency tree:/)
  assert.doesNotMatch(output, /Priority findings:/)
  assert.doesNotMatch(output, /Routine findings:/)
  assert.doesNotMatch(output, /Warnings:/)
  assert.doesNotMatch(output, /package_finding:/)
})

test('summary renderer is deterministic', () => {
  const first = renderSummaryText(createResult())
  const second = renderSummaryText(createResult())

  assert.equal(first, second)
})

function createResult(): ScanResult {
  return {
    record_id: '2026-04-01T00:00:00.000Z:next@15.1.7:depth=3',
    scan_mode: 'registry_package',
    scan_target: 'next@15.1.7',
    baseline_record_id: null,
    requested_depth: 3,
    threshold: 0.4,
    field_reliability: createFieldReliabilityReport(),
    root: {
      name: 'next',
      version: '15.1.7',
      key: 'next@15.1.7',
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
      dependency_count: 2,
      publish_events_last_30_days: 1,
      has_advisories: false,
      risk_score: 0.64,
      risk_level: 'review',
      signals: [],
      recommendation: 'review',
      dependencies: [],
    },
    edge_findings: [],
    findings: [
      {
        key: 'vulnerable-child@2.0.0',
        name: 'vulnerable-child',
        version: '2.0.0',
        depth: 1,
        review_target: {
          kind: 'package_finding',
          record_id: '2026-04-01T00:00:00.000Z:next@15.1.7:depth=3',
          target_id: 'package_finding:vulnerable-child@2.0.0',
          finding_key: 'package_finding:vulnerable-child@2.0.0',
          package_key: 'vulnerable-child@2.0.0',
        },
        path: {
          packages: [
            { name: 'next', version: '15.1.7' },
            { name: 'vulnerable-child', version: '2.0.0' },
          ],
        },
        risk_score: 0.64,
        risk_level: 'review',
        recommendation: 'review',
        signals: [
          {
            type: 'security_deprecation_language',
            value: 'Security issue detected. See CVE-2025-66478.',
            weight: 'high',
            reason: 'deprecation message contains security-related language',
          },
        ],
        explanation: 'deprecation message contains security-related language',
      },
      {
        key: 'new-child@1.0.0',
        name: 'new-child',
        version: '1.0.0',
        depth: 1,
        review_target: {
          kind: 'package_finding',
          record_id: '2026-04-01T00:00:00.000Z:next@15.1.7:depth=3',
          target_id: 'package_finding:new-child@1.0.0',
          finding_key: 'package_finding:new-child@1.0.0',
          package_key: 'new-child@1.0.0',
        },
        path: {
          packages: [
            { name: 'next', version: '15.1.7' },
            { name: 'new-child', version: '1.0.0' },
          ],
        },
        risk_score: 0.41,
        risk_level: 'review',
        recommendation: 'review',
        signals: [
          {
            type: 'new_package_age',
            value: 2,
            weight: 'high',
            reason: 'package was published 2 day(s) ago',
          },
        ],
        explanation: 'package was published 2 day(s) ago',
      },
    ],
    total_scanned: 14,
    suspicious_count: 2,
    safe_count: 12,
    overall_risk_score: 0.64,
    overall_risk_level: 'review',
    warnings: [],
    scan_duration_ms: 0,
    timestamp: '2026-04-01T00:00:00.000Z',
  }
}
