import assert from 'node:assert/strict'
import test from 'node:test'

import {
  buildResolvedReviewStateIndex,
  getResolvedReviewState,
  resolveReviewStateFromEvents,
} from '../src/application/resolve-review-state.js'
import type { ReviewEvent } from '../src/domain/contracts.js'

test('resolveReviewStateFromEvents returns unreviewed when no review events exist', () => {
  const state = resolveReviewStateFromEvents('record-1', [])

  assert.equal(state.workflow_status, 'unreviewed')
  assert.equal(state.canonical_label, null)
  assert.equal(state.canonical_label_source, null)
  assert.equal(state.latest_review_event, null)
  assert.equal(state.latest_label_bearing_event, null)
})

test('resolveReviewStateFromEvents resolves a single benign review', () => {
  const state = resolveReviewStateFromEvents('record-1', [
    createReviewEvent('benign', '2026-04-01T00:00:00.000Z'),
  ])

  assert.equal(state.workflow_status, 'resolved')
  assert.equal(state.canonical_label, 'benign')
  assert.equal(state.canonical_label_source, 'latest_label_bearing_event')
})

test('resolveReviewStateFromEvents resolves a single malicious review', () => {
  const state = resolveReviewStateFromEvents('record-1', [
    createReviewEvent('malicious', '2026-04-01T00:00:00.000Z'),
  ])

  assert.equal(state.workflow_status, 'resolved')
  assert.equal(state.canonical_label, 'malicious')
  assert.equal(state.canonical_label_source, 'latest_label_bearing_event')
})

test('resolveReviewStateFromEvents keeps needs_review as workflow-only when no label exists', () => {
  const state = resolveReviewStateFromEvents('record-1', [
    createReviewEvent('needs_review', '2026-04-01T00:00:00.000Z'),
  ])

  assert.equal(state.workflow_status, 'needs_review')
  assert.equal(state.canonical_label, null)
  assert.equal(state.canonical_label_source, null)
})

test('resolveReviewStateFromEvents preserves the last resolved label when a later needs_review arrives', () => {
  const state = resolveReviewStateFromEvents('record-1', [
    createReviewEvent('benign', '2026-04-01T00:00:00.000Z'),
    createReviewEvent('needs_review', '2026-04-02T00:00:00.000Z'),
  ])

  assert.equal(state.workflow_status, 'needs_review')
  assert.equal(state.canonical_label, 'benign')
  assert.equal(state.latest_review_event?.outcome, 'needs_review')
  assert.equal(state.latest_label_bearing_event?.outcome, 'benign')
})

test('resolveReviewStateFromEvents updates canonical label from benign to malicious', () => {
  const state = resolveReviewStateFromEvents('record-1', [
    createReviewEvent('benign', '2026-04-01T00:00:00.000Z'),
    createReviewEvent('malicious', '2026-04-02T00:00:00.000Z'),
  ])

  assert.equal(state.workflow_status, 'resolved')
  assert.equal(state.canonical_label, 'malicious')
})

test('resolveReviewStateFromEvents updates canonical label from malicious to benign', () => {
  const state = resolveReviewStateFromEvents('record-1', [
    createReviewEvent('malicious', '2026-04-01T00:00:00.000Z'),
    createReviewEvent('benign', '2026-04-02T00:00:00.000Z'),
  ])

  assert.equal(state.workflow_status, 'resolved')
  assert.equal(state.canonical_label, 'benign')
})

test('getResolvedReviewState returns an explicit unreviewed default for records without events', () => {
  const resolvedReviewStateIndex = buildResolvedReviewStateIndex([
    createReviewEvent('benign', '2026-04-01T00:00:00.000Z'),
  ])

  const state = getResolvedReviewState('missing-record', resolvedReviewStateIndex)

  assert.equal(state.record_id, 'missing-record')
  assert.equal(state.workflow_status, 'unreviewed')
  assert.equal(state.canonical_label, null)
  assert.equal(state.latest_review_event, null)
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
