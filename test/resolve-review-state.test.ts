import assert from 'node:assert/strict'
import test from 'node:test'

import { resolveReviewState } from '../src/application/resolve-review-state.js'
import type { ReviewEvent } from '../src/domain/contracts.js'

test('resolveReviewState returns unreviewed when no review events exist', () => {
  const state = resolveReviewState('record-1', [])

  assert.equal(state.workflow_status, 'unreviewed')
  assert.equal(state.canonical_label, null)
  assert.equal(state.canonical_label_source, null)
  assert.equal(state.latest_review_event, null)
  assert.equal(state.latest_label_bearing_event, null)
})

test('resolveReviewState resolves a single benign review', () => {
  const state = resolveReviewState('record-1', [createReviewEvent('benign', '2026-04-01T00:00:00.000Z')])

  assert.equal(state.workflow_status, 'resolved')
  assert.equal(state.canonical_label, 'benign')
  assert.equal(state.canonical_label_source, 'latest_label_bearing_event')
})

test('resolveReviewState resolves a single malicious review', () => {
  const state = resolveReviewState('record-1', [createReviewEvent('malicious', '2026-04-01T00:00:00.000Z')])

  assert.equal(state.workflow_status, 'resolved')
  assert.equal(state.canonical_label, 'malicious')
  assert.equal(state.canonical_label_source, 'latest_label_bearing_event')
})

test('resolveReviewState keeps needs_review as workflow-only when no label exists', () => {
  const state = resolveReviewState('record-1', [
    createReviewEvent('needs_review', '2026-04-01T00:00:00.000Z'),
  ])

  assert.equal(state.workflow_status, 'needs_review')
  assert.equal(state.canonical_label, null)
  assert.equal(state.canonical_label_source, null)
})

test('resolveReviewState preserves the last resolved label when a later needs_review arrives', () => {
  const state = resolveReviewState('record-1', [
    createReviewEvent('benign', '2026-04-01T00:00:00.000Z'),
    createReviewEvent('needs_review', '2026-04-02T00:00:00.000Z'),
  ])

  assert.equal(state.workflow_status, 'needs_review')
  assert.equal(state.canonical_label, 'benign')
  assert.equal(state.latest_review_event?.outcome, 'needs_review')
  assert.equal(state.latest_label_bearing_event?.outcome, 'benign')
})

test('resolveReviewState updates canonical label from benign to malicious', () => {
  const state = resolveReviewState('record-1', [
    createReviewEvent('benign', '2026-04-01T00:00:00.000Z'),
    createReviewEvent('malicious', '2026-04-02T00:00:00.000Z'),
  ])

  assert.equal(state.workflow_status, 'resolved')
  assert.equal(state.canonical_label, 'malicious')
})

test('resolveReviewState updates canonical label from malicious to benign', () => {
  const state = resolveReviewState('record-1', [
    createReviewEvent('malicious', '2026-04-01T00:00:00.000Z'),
    createReviewEvent('benign', '2026-04-02T00:00:00.000Z'),
  ])

  assert.equal(state.workflow_status, 'resolved')
  assert.equal(state.canonical_label, 'benign')
})

function createReviewEvent(outcome: ReviewEvent['outcome'], createdAt: string): ReviewEvent {
  return {
    event_id: `${createdAt}:record-1:${outcome}`,
    record_id: 'record-1',
    package_key: 'root@1.0.0',
    created_at: createdAt,
    outcome,
    notes: null,
    resolution_timestamp: outcome === 'needs_review' ? null : createdAt,
    review_source: 'human',
    confidence: 0.9,
  }
}
