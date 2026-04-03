import assert from 'node:assert/strict'
import test from 'node:test'

import {
  buildResolvedReviewStateIndex,
  getResolvedReviewState,
  resolveReviewStateFromEvents,
} from '../src/application/resolve-review-state.js'
import type { ReviewEvent, ReviewTarget } from '../src/domain/contracts.js'

test('resolveReviewStateFromEvents returns unreviewed when no review events exist', () => {
  const reviewTarget = createReviewTarget('record-1')
  const state = resolveReviewStateFromEvents(reviewTarget, [])

  assert.equal(state.workflow_status, 'unreviewed')
  assert.equal(state.canonical_label, null)
  assert.equal(state.canonical_label_source, null)
  assert.equal(state.latest_review_event, null)
  assert.equal(state.canonical_label_event, null)
  assert.deepEqual(state.review_target, reviewTarget)
})

test('resolveReviewStateFromEvents resolves a single benign review', () => {
  const reviewTarget = createReviewTarget('record-1')
  const state = resolveReviewStateFromEvents(reviewTarget, [
    createReviewEvent(reviewTarget, 'benign', '2026-04-01T00:00:00.000Z'),
  ])

  assert.equal(state.workflow_status, 'resolved')
  assert.equal(state.canonical_label, 'benign')
  assert.equal(state.canonical_label_source, 'source_precedence_then_latest_within_source')
})

test('resolveReviewStateFromEvents resolves a single malicious review', () => {
  const reviewTarget = createReviewTarget('record-1')
  const state = resolveReviewStateFromEvents(reviewTarget, [
    createReviewEvent(reviewTarget, 'malicious', '2026-04-01T00:00:00.000Z'),
  ])

  assert.equal(state.workflow_status, 'resolved')
  assert.equal(state.canonical_label, 'malicious')
  assert.equal(state.canonical_label_source, 'source_precedence_then_latest_within_source')
})

test('resolveReviewStateFromEvents keeps needs_review as workflow-only when no label exists', () => {
  const reviewTarget = createReviewTarget('record-1')
  const state = resolveReviewStateFromEvents(reviewTarget, [
    createReviewEvent(reviewTarget, 'needs_review', '2026-04-01T00:00:00.000Z'),
  ])

  assert.equal(state.workflow_status, 'needs_review')
  assert.equal(state.canonical_label, null)
  assert.equal(state.canonical_label_source, null)
})

test('resolveReviewStateFromEvents preserves the last resolved label when a later needs_review arrives', () => {
  const reviewTarget = createReviewTarget('record-1')
  const state = resolveReviewStateFromEvents(reviewTarget, [
    createReviewEvent(reviewTarget, 'benign', '2026-04-01T00:00:00.000Z'),
    createReviewEvent(reviewTarget, 'needs_review', '2026-04-02T00:00:00.000Z'),
  ])

  assert.equal(state.workflow_status, 'needs_review')
  assert.equal(state.canonical_label, 'benign')
  assert.equal(state.latest_review_event?.outcome, 'needs_review')
  assert.equal(state.canonical_label_event?.outcome, 'benign')
})

test('resolveReviewStateFromEvents uses recency within the same source tier', () => {
  const reviewTarget = createReviewTarget('record-1')
  const state = resolveReviewStateFromEvents(reviewTarget, [
    createReviewEvent(reviewTarget, 'benign', '2026-04-01T00:00:00.000Z'),
    createReviewEvent(reviewTarget, 'malicious', '2026-04-02T00:00:00.000Z'),
  ])

  assert.equal(state.workflow_status, 'resolved')
  assert.equal(state.canonical_label, 'malicious')
})

test('resolveReviewStateFromEvents updates canonical label from malicious to benign', () => {
  const reviewTarget = createReviewTarget('record-1')
  const state = resolveReviewStateFromEvents(reviewTarget, [
    createReviewEvent(reviewTarget, 'malicious', '2026-04-01T00:00:00.000Z'),
    createReviewEvent(reviewTarget, 'benign', '2026-04-02T00:00:00.000Z'),
  ])

  assert.equal(state.workflow_status, 'resolved')
  assert.equal(state.canonical_label, 'benign')
})

test('resolveReviewStateFromEvents keeps an earlier human label over a later auto label', () => {
  const reviewTarget = createReviewTarget('record-1')
  const state = resolveReviewStateFromEvents(reviewTarget, [
    createReviewEvent(reviewTarget, 'malicious', '2026-04-01T00:00:00.000Z', 'human'),
    createReviewEvent(reviewTarget, 'benign', '2026-04-02T00:00:00.000Z', 'auto'),
  ])

  assert.equal(state.workflow_status, 'resolved')
  assert.equal(state.canonical_label, 'malicious')
  assert.equal(state.canonical_label_event?.review_source, 'human')
  assert.equal(state.canonical_label_event?.outcome, 'malicious')
})

test('resolveReviewStateFromEvents keeps an earlier human label over a later external label', () => {
  const reviewTarget = createReviewTarget('record-1')
  const state = resolveReviewStateFromEvents(reviewTarget, [
    createReviewEvent(reviewTarget, 'benign', '2026-04-01T00:00:00.000Z', 'human'),
    createReviewEvent(reviewTarget, 'malicious', '2026-04-02T00:00:00.000Z', 'external'),
  ])

  assert.equal(state.workflow_status, 'resolved')
  assert.equal(state.canonical_label, 'benign')
  assert.equal(state.canonical_label_event?.review_source, 'human')
  assert.equal(state.canonical_label_event?.outcome, 'benign')
})

test('resolveReviewStateFromEvents keeps an earlier external label over a later auto label', () => {
  const reviewTarget = createReviewTarget('record-1')
  const state = resolveReviewStateFromEvents(reviewTarget, [
    createReviewEvent(reviewTarget, 'malicious', '2026-04-01T00:00:00.000Z', 'external'),
    createReviewEvent(reviewTarget, 'benign', '2026-04-02T00:00:00.000Z', 'auto'),
  ])

  assert.equal(state.workflow_status, 'resolved')
  assert.equal(state.canonical_label, 'malicious')
  assert.equal(state.canonical_label_event?.review_source, 'external')
  assert.equal(state.canonical_label_event?.outcome, 'malicious')
})

test('resolveReviewStateFromEvents keeps workflow status on the latest event overall even when label precedence differs', () => {
  const reviewTarget = createReviewTarget('record-1')
  const state = resolveReviewStateFromEvents(reviewTarget, [
    createReviewEvent(reviewTarget, 'benign', '2026-04-01T00:00:00.000Z', 'human'),
    createReviewEvent(reviewTarget, 'needs_review', '2026-04-02T00:00:00.000Z', 'auto'),
  ])

  assert.equal(state.workflow_status, 'needs_review')
  assert.equal(state.canonical_label, 'benign')
  assert.equal(state.latest_review_event?.review_source, 'auto')
  assert.equal(state.canonical_label_event?.review_source, 'human')
})

test('getResolvedReviewState returns an explicit unreviewed default for targets without events', () => {
  const reviewTarget = createReviewTarget('record-1')
  const missingTarget = createReviewTarget('missing-record')
  const resolvedReviewStateIndex = buildResolvedReviewStateIndex([
    createReviewEvent(reviewTarget, 'benign', '2026-04-01T00:00:00.000Z'),
  ])

  const state = getResolvedReviewState(missingTarget, resolvedReviewStateIndex)

  assert.equal(state.record_id, 'missing-record')
  assert.deepEqual(state.review_target, missingTarget)
  assert.equal(state.workflow_status, 'unreviewed')
  assert.equal(state.canonical_label, null)
  assert.equal(state.latest_review_event, null)
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
