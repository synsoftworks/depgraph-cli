import assert from 'node:assert/strict'
import test from 'node:test'

import { createResolveReviewStateIndexUseCase } from '../src/application/resolve-review-state-index.js'
import type { ReviewEvent, ReviewTarget } from '../src/domain/contracts.js'
import type { ScanReviewStore } from '../src/domain/ports.js'
import { reviewTargetScopeKey } from '../src/domain/review-targets.js'

class InMemoryReviewEventSource implements Pick<ScanReviewStore, 'listReviewEvents'> {
  constructor(private readonly reviewEvents: ReviewEvent[]) {}

  async listReviewEvents(): Promise<ReviewEvent[]> {
    return this.reviewEvents
  }
}

test('resolveReviewStateIndex derives canonical labels from raw review history', async () => {
  const record1Target = createReviewTarget('record-1')
  const record2Target = createReviewTarget('record-2')
  const resolveReviewStateIndex = createResolveReviewStateIndexUseCase({
    reviewEventSource: new InMemoryReviewEventSource([
      createReviewEvent(record1Target, 'benign', '2026-04-01T00:00:00.000Z'),
      createReviewEvent(record1Target, 'needs_review', '2026-04-02T00:00:00.000Z'),
      createReviewEvent(record2Target, 'malicious', '2026-04-03T00:00:00.000Z'),
    ]),
  })

  const resolvedReviewStateIndex = await resolveReviewStateIndex()

  assert.equal(resolvedReviewStateIndex.get(reviewTargetScopeKey(record1Target))?.workflow_status, 'needs_review')
  assert.equal(resolvedReviewStateIndex.get(reviewTargetScopeKey(record1Target))?.canonical_label, 'benign')
  assert.equal(resolvedReviewStateIndex.get(reviewTargetScopeKey(record2Target))?.workflow_status, 'resolved')
  assert.equal(resolvedReviewStateIndex.get(reviewTargetScopeKey(record2Target))?.canonical_label, 'malicious')
})

test('resolveReviewStateIndex applies source precedence before recency for canonical labels', async () => {
  const recordTarget = createReviewTarget('record-1')
  const resolveReviewStateIndex = createResolveReviewStateIndexUseCase({
    reviewEventSource: new InMemoryReviewEventSource([
      createReviewEvent(recordTarget, 'malicious', '2026-04-01T00:00:00.000Z', 'human'),
      createReviewEvent(recordTarget, 'benign', '2026-04-02T00:00:00.000Z', 'auto'),
      createReviewEvent(recordTarget, 'needs_review', '2026-04-03T00:00:00.000Z', 'auto'),
    ]),
  })

  const resolvedReviewStateIndex = await resolveReviewStateIndex()
  const state = resolvedReviewStateIndex.get(reviewTargetScopeKey(recordTarget))

  assert.equal(state?.workflow_status, 'needs_review')
  assert.equal(state?.canonical_label, 'malicious')
  assert.equal(state?.canonical_label_event?.review_source, 'human')
})

function createReviewEvent(
  reviewTarget: ReviewTarget,
  outcome: ReviewEvent['outcome'],
  createdAt: string,
  reviewSource: ReviewEvent['review_source'] = 'human',
): ReviewEvent {
  return {
    event_id: `${createdAt}:${reviewTarget.target_id}:${reviewSource}:${outcome}`,
    record_id: reviewTarget.record_id,
    review_target: reviewTarget,
    created_at: createdAt,
    outcome,
    notes: null,
    resolution_timestamp: outcome === 'needs_review' ? null : createdAt,
    review_source: reviewSource,
    confidence: 0.9,
  }
}

function createReviewTarget(recordId: string): ReviewTarget {
  return {
    kind: 'package_finding',
    record_id: recordId,
    target_id: `package_finding:${recordId}@1.0.0`,
    finding_key: `package_finding:${recordId}@1.0.0`,
    package_key: `${recordId}@1.0.0`,
  }
}
