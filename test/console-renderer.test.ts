import assert from 'node:assert/strict'
import test from 'node:test'

import { formatPresentedRiskLevel, shouldRenderOverallRisk } from '../src/interface/console-renderer.js'

test('TUI overall risk section is hidden when no findings exceeded threshold', () => {
  assert.equal(shouldRenderOverallRisk({ suspicious_count: 0 }), false)
  assert.equal(shouldRenderOverallRisk({ suspicious_count: 1 }), true)
})

test('TUI risk wording uses the public risk vocabulary consistently', () => {
  assert.equal(formatPresentedRiskLevel('safe'), 'safe')
  assert.equal(formatPresentedRiskLevel('review'), 'review')
  assert.equal(formatPresentedRiskLevel('critical'), 'critical')
})
