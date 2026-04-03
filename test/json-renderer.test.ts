import assert from 'node:assert/strict'
import test from 'node:test'

import type { ScanResult } from '../src/domain/entities.js'
import { renderJson } from '../src/interface/json-renderer.js'

function createResult(): ScanResult {
  return {
    record_id: '2026-04-01T00:00:00.000Z:root@1.0.0:depth=3',
    scan_mode: 'registry_package',
    scan_target: 'root',
    baseline_record_id: null,
    requested_depth: 3,
    threshold: 0.4,
    root: {
      name: 'root',
      version: '1.0.0',
      key: 'root@1.0.0',
      depth: 0,
      is_project_root: false,
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
      risk_score: 0.1,
      risk_level: 'safe',
      signals: [],
      recommendation: 'install',
      dependencies: [],
    },
    edge_findings: [
      {
        parent_key: 'root@1.0.0',
        child_key: 'child@1.0.0',
        path: ['root@1.0.0', 'child@1.0.0'],
        depth: 1,
        edge_type: 'direct',
        review_target: {
          kind: 'edge_finding',
          record_id: '2026-04-01T00:00:00.000Z:root@1.0.0:depth=3',
          target_id: 'edge_finding:direct:root@1.0.0->child@1.0.0',
          edge_finding_key: 'edge_finding:direct:root@1.0.0->child@1.0.0',
          parent_key: 'root@1.0.0',
          child_key: 'child@1.0.0',
          edge_type: 'direct',
        },
        baseline_record_id: 'baseline-record',
        baseline_identity: {
          scan_mode: 'registry_package',
          scan_target: 'root',
          requested_depth: 3,
          workspace_identity: '/tmp/workspace',
        },
        reason: 'new direct dependency edge root@1.0.0 -> child@1.0.0',
        recommendation: 'review',
      },
    ],
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
        risk_score: 0.48,
        risk_level: 'review',
        recommendation: 'review',
        signals: [
          {
            type: 'test_signal',
            value: 0.48,
            weight: 'medium',
            reason: 'score 0.48',
          },
        ],
        explanation: 'score 0.48',
      },
    ],
    total_scanned: 1,
    suspicious_count: 1,
    safe_count: 0,
    overall_risk_score: 0.48,
    overall_risk_level: 'review',
    scan_duration_ms: 0,
    timestamp: '2026-04-01T00:00:00.000Z',
  }
}

test('scan JSON contract remains stable and deterministic', () => {
  const first = renderJson(createResult())
  const second = renderJson(createResult())
  const parsed = JSON.parse(first)

  assert.equal(first, second)
  assert.doesNotThrow(() => JSON.parse(first))
  assert.deepEqual(Object.keys(parsed), [
    'record_id',
    'scan_mode',
    'scan_target',
    'baseline_record_id',
    'requested_depth',
    'threshold',
    'root',
    'edge_findings',
    'findings',
    'total_scanned',
    'suspicious_count',
    'safe_count',
    'overall_risk_score',
    'overall_risk_level',
    'scan_duration_ms',
    'timestamp',
  ])
  assert.deepEqual(Object.keys(parsed.edge_findings[0]), [
    'parent_key',
    'child_key',
    'path',
    'depth',
    'edge_type',
    'review_target',
    'baseline_record_id',
    'baseline_identity',
    'reason',
    'recommendation',
  ])
  assert.deepEqual(Object.keys(parsed.findings[0]), [
    'key',
    'name',
    'version',
    'depth',
    'review_target',
    'path',
    'risk_score',
    'risk_level',
    'recommendation',
    'signals',
    'explanation',
  ])
  assert.deepEqual(parsed.edge_findings[0], {
    parent_key: 'root@1.0.0',
    child_key: 'child@1.0.0',
    path: ['root@1.0.0', 'child@1.0.0'],
    depth: 1,
    edge_type: 'direct',
    review_target: {
      kind: 'edge_finding',
      record_id: '2026-04-01T00:00:00.000Z:root@1.0.0:depth=3',
      target_id: 'edge_finding:direct:root@1.0.0->child@1.0.0',
      edge_finding_key: 'edge_finding:direct:root@1.0.0->child@1.0.0',
      parent_key: 'root@1.0.0',
      child_key: 'child@1.0.0',
      edge_type: 'direct',
    },
    baseline_record_id: 'baseline-record',
    baseline_identity: {
      scan_mode: 'registry_package',
      scan_target: 'root',
      requested_depth: 3,
      workspace_identity: '/tmp/workspace',
    },
    reason: 'new direct dependency edge root@1.0.0 -> child@1.0.0',
    recommendation: 'review',
  })
  assert.equal(parsed.findings[0].key, 'child@1.0.0')
  assert.equal(parsed.findings[0].review_target.target_id, 'package_finding:child@1.0.0')
  assert.equal(parsed.findings[0].signals[0].type, 'test_signal')
})
