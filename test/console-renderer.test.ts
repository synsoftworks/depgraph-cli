import assert from 'node:assert/strict'
import test from 'node:test'

import type { ScanFinding } from '../src/domain/entities.js'
import { deriveSignalTags, shouldRenderOverallRisk } from '../src/interface/console-renderer.js'

function createFinding(
  overrides: Partial<ScanFinding> = {},
): ScanFinding {
  return {
    key: 'pkg@1.0.0',
    name: 'pkg',
    version: '1.0.0',
    depth: 2,
    review_target: {
      kind: 'package_finding',
      record_id: 'record-1',
      target_id: 'package_finding:pkg@1.0.0',
      finding_key: 'package_finding:pkg@1.0.0',
      package_key: 'pkg@1.0.0',
    },
    path: {
      packages: [
        { name: 'root', version: '1.0.0' },
        { name: 'pkg', version: '1.0.0' },
      ],
    },
    risk_score: 0.48,
    risk_level: 'review',
    recommendation: 'review',
    signals: [],
    explanation: 'test finding',
    ...overrides,
  }
}

test('TUI signal tags only summarize surfaced findings', () => {
  const tags = deriveSignalTags({
    findings: [],
  })

  assert.deepEqual(tags, [])
})

test('TUI signal tags are derived from finding signals and keep depth-1 context', () => {
  const tags = deriveSignalTags({
    findings: [
      createFinding({
        depth: 1,
        signals: [
          {
            type: 'rapid_publish_churn',
            value: 8,
            weight: 'medium',
            reason: '8 version publish events happened in the last 30 days',
          },
        ],
      }),
    ],
  })

  assert.deepEqual(tags, ['depth-1 threat', 'rapid publish churn'])
})

test('TUI overall risk section is hidden when no findings exceeded threshold', () => {
  assert.equal(shouldRenderOverallRisk({ suspicious_count: 0 }), false)
  assert.equal(shouldRenderOverallRisk({ suspicious_count: 1 }), true)
})
