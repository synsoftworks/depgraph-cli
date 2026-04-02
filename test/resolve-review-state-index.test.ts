import assert from 'node:assert/strict'
import test from 'node:test'

import { createResolveReviewStateIndexUseCase } from '../src/application/resolve-review-state-index.js'
import type { ReviewEvent } from '../src/domain/contracts.js'
import type { ScanReviewStore } from '../src/domain/ports.js'

class InMemoryReviewEventSource implements Pick<ScanReviewStore, 'listReviewEvents'> {
  constructor(private readonly reviewEvents: ReviewEvent[]) {}

  async listReviewEvents(): Promise<ReviewEvent[]> {
    return this.reviewEvents
  }
}

test('resolveReviewStateIndex derives canonical labels from raw review history', async () => {
  const resolveReviewStateIndex = createResolveReviewStateIndexUseCase({
    reviewEventSource: new InMemoryReviewEventSource([
      createReviewEvent('record-1', 'benign', '2026-04-01T00:00:00.000Z'),
      createReviewEvent('record-1', 'needs_review', '2026-04-02T00:00:00.000Z'),
      createReviewEvent('record-2', 'malicious', '2026-04-03T00:00:00.000Z'),
    ]),
  })

  const resolvedReviewStateIndex = await resolveReviewStateIndex()

  assert.equal(resolvedReviewStateIndex.get('record-1')?.workflow_status, 'needs_review')
  assert.equal(resolvedReviewStateIndex.get('record-1')?.canonical_label, 'benign')
  assert.equal(resolvedReviewStateIndex.get('record-2')?.workflow_status, 'resolved')
  assert.equal(resolvedReviewStateIndex.get('record-2')?.canonical_label, 'malicious')
})

function createReviewEvent(
  recordId: string,
  outcome: ReviewEvent['outcome'],
  createdAt: string,
): ReviewEvent {
  return {
    event_id: `${createdAt}:${recordId}:${outcome}`,
    record_id: recordId,
    package_key: `${recordId}@1.0.0`,
    created_at: createdAt,
    outcome,
    notes: null,
    resolution_timestamp: outcome === 'needs_review' ? null : createdAt,
    review_source: 'human',
    confidence: 0.9,
  }
}
