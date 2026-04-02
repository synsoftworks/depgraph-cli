import assert from 'node:assert/strict'
import test from 'node:test'

import type { ReviewEvent } from '../src/domain/contracts.js'
import { renderReviewJson } from '../src/interface/review-renderer.js'

test('review JSON contract remains stable and deterministic', () => {
  const event = createReviewEvent()
  const first = renderReviewJson(event)
  const second = renderReviewJson(event)
  const parsed = JSON.parse(first)

  assert.equal(first, second)
  assert.deepEqual(Object.keys(parsed), [
    'event_id',
    'record_id',
    'package_key',
    'created_at',
    'outcome',
    'notes',
    'resolution_timestamp',
    'review_source',
    'confidence',
  ])
  assert.deepEqual(parsed, event)
})

function createReviewEvent(): ReviewEvent {
  return {
    event_id: '2026-04-03T00:00:00.000Z:scan-1:benign',
    record_id: 'scan-1',
    package_key: 'root@1.0.0',
    created_at: '2026-04-03T00:00:00.000Z',
    outcome: 'benign',
    notes: 'verified expansion',
    resolution_timestamp: '2026-04-03T00:00:00.000Z',
    review_source: 'human',
    confidence: 0.95,
  }
}
