import assert from 'node:assert/strict'
import test from 'node:test'

import type { ScanResult } from '../src/domain/entities.js'
import { renderJson } from '../src/interface/json-renderer.js'

function createResult(): ScanResult {
  return {
    scan_target: 'root',
    requested_depth: 3,
    threshold: 0.4,
    root: {
      name: 'root',
      version: '1.0.0',
      key: 'root@1.0.0',
      depth: 0,
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
    findings: [],
    total_scanned: 1,
    suspicious_count: 0,
    safe_count: 1,
    overall_risk_score: 0.1,
    overall_risk_level: 'safe',
    scan_duration_ms: 0,
    timestamp: '2026-04-01T00:00:00.000Z',
  }
}

test('JSON renderer emits deterministic JSON', () => {
  const first = renderJson(createResult())
  const second = renderJson(createResult())

  assert.equal(first, second)
  assert.doesNotThrow(() => JSON.parse(first))
})
