import assert from 'node:assert/strict'
import test from 'node:test'

import type { ScanResult } from '../src/domain/entities.js'
import { renderPlainText } from '../src/interface/plain-text-renderer.js'

test('plain text renderer surfaces changed edges from the current tree projection before package findings', () => {
  const output = renderPlainText(createResult())

  assert.match(output, /Mode: registry_package/)
  assert.match(output, /Target: root/)
  assert.match(output, /Changed edges in current tree view:/)
  assert.match(output, /root@1\.0\.0 -> child@1\.0\.0 \[direct\] via root@1\.0\.0 > child@1\.0\.0/)
  assert.match(output, /target: edge_finding:direct:root@1\.0\.0->child@1\.0\.0/)
  assert.match(output, /Findings:/)
})

function createResult(): ScanResult {
  return {
    record_id: '2026-04-01T00:00:00.000Z:root@1.0.0:depth=3',
    scan_mode: 'registry_package',
    scan_target: 'root',
    baseline_record_id: 'baseline-record',
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
      risk_score: 0.64,
      risk_level: 'review',
      signals: [
        {
          type: 'new_direct_dependency_edge',
          value: 'root@1.0.0->child@1.0.0',
          weight: 'high',
          reason: 'new direct dependency edge root@1.0.0 -> child@1.0.0',
        },
      ],
      recommendation: 'review',
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
    findings: [],
    total_scanned: 1,
    suspicious_count: 1,
    safe_count: 0,
    overall_risk_score: 0.64,
    overall_risk_level: 'review',
    scan_duration_ms: 0,
    timestamp: '2026-04-01T00:00:00.000Z',
  }
}
