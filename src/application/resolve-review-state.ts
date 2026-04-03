import type { ResolvedReviewTargetState, ReviewEvent, ReviewTarget } from '../domain/contracts.js'
import { reviewTargetScopeKey } from '../domain/review-targets.js'

/**
 * This policy remains in the application layer for now because the rules are
 * still evolving. Treat it as the single label-resolution entry point until
 * ownership is stable enough to move into the domain layer.
 *
 * Canonical review resolution keeps workflow state separate from label state:
 * - `needs_review` is workflow-bearing but not label-bearing
 * - the latest label-bearing event determines the canonical label
 * - the latest event overall determines the current workflow status
 *
 * This preserves append-only review history without letting unresolved workflow
 * events erase a previously resolved malicious or benign label.
 */
export function resolveReviewStateFromEvents(
  reviewTarget: ReviewTarget,
  rawReviewEvents: ReviewEvent[],
): ResolvedReviewTargetState {
  let latestReviewEvent: ReviewEvent | null = null
  let latestLabelBearingEvent: ReviewEvent | null = null

  for (const event of rawReviewEvents) {
    if (reviewTargetScopeKey(event.review_target) !== reviewTargetScopeKey(reviewTarget)) {
      continue
    }

    if (isMoreRecentEvent(event, latestReviewEvent)) {
      latestReviewEvent = event
    }

    if (isLabelBearingEvent(event) && isMoreRecentEvent(event, latestLabelBearingEvent)) {
      latestLabelBearingEvent = event
    }
  }

  return {
    record_id: reviewTarget.record_id,
    review_target: reviewTarget,
    latest_review_event: latestReviewEvent,
    latest_label_bearing_event: latestLabelBearingEvent,
    workflow_status: toWorkflowStatus(latestReviewEvent),
    canonical_label: toCanonicalLabel(latestLabelBearingEvent),
    canonical_label_source: latestLabelBearingEvent === null ? null : 'latest_label_bearing_event',
  }
}

/**
 * Build the label-facing view from raw append-only review history.
 * Label-aware application code should prefer this index over reading
 * `ReviewEvent` arrays directly.
 */
export function buildResolvedReviewStateIndex(
  rawReviewEvents: ReviewEvent[],
): ReadonlyMap<string, ResolvedReviewTargetState> {
  const eventsByTargetScope = new Map<string, ReviewEvent[]>()

  for (const event of rawReviewEvents) {
    const scopeKey = reviewTargetScopeKey(event.review_target)
    const existing = eventsByTargetScope.get(scopeKey)

    if (existing === undefined) {
      eventsByTargetScope.set(scopeKey, [event])
      continue
    }

    existing.push(event)
  }

  const resolvedStates = new Map<string, ResolvedReviewTargetState>()

  for (const [scopeKey, eventsForTarget] of eventsByTargetScope.entries()) {
    const reviewTarget = eventsForTarget[0]?.review_target

    if (reviewTarget === undefined) {
      continue
    }

    resolvedStates.set(scopeKey, resolveReviewStateFromEvents(reviewTarget, eventsForTarget))
  }

  return resolvedStates
}

export function getResolvedReviewState(
  reviewTarget: ReviewTarget,
  resolvedReviewStateIndex: ReadonlyMap<string, ResolvedReviewTargetState>,
): ResolvedReviewTargetState {
  return (
    resolvedReviewStateIndex.get(reviewTargetScopeKey(reviewTarget)) ?? {
      record_id: reviewTarget.record_id,
      review_target: reviewTarget,
      latest_review_event: null,
      latest_label_bearing_event: null,
      workflow_status: 'unreviewed',
      canonical_label: null,
      canonical_label_source: null,
    }
  )
}

function isLabelBearingEvent(event: ReviewEvent): boolean {
  return event.outcome === 'malicious' || event.outcome === 'benign'
}

function toWorkflowStatus(
  latestReviewEvent: ReviewEvent | null,
): ResolvedReviewTargetState['workflow_status'] {
  if (latestReviewEvent === null) {
    return 'unreviewed'
  }

  if (latestReviewEvent.outcome === 'needs_review') {
    return 'needs_review'
  }

  return 'resolved'
}

function toCanonicalLabel(
  latestLabelBearingEvent: ReviewEvent | null,
): ResolvedReviewTargetState['canonical_label'] {
  if (latestLabelBearingEvent === null) {
    return null
  }

  if (latestLabelBearingEvent.outcome === 'malicious') {
    return 'malicious'
  }

  return 'benign'
}

function isMoreRecentEvent(candidate: ReviewEvent, current: ReviewEvent | null): boolean {
  if (current === null) {
    return true
  }

  if (candidate.created_at !== current.created_at) {
    return candidate.created_at > current.created_at
  }

  return candidate.event_id > current.event_id
}
