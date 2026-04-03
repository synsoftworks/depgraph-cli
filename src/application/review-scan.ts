import type { ReviewEvent, ReviewScanRequest, ReviewTarget, ScanReviewRecord } from '../domain/contracts.js'
import { InvalidUsageError } from '../domain/errors.js'
import type { ScanReviewStore } from '../domain/ports.js'

interface ReviewScanDependencies {
  reviewStore: ScanReviewStore
  now?: () => Date
}

export function createReviewScanUseCase({
  reviewStore,
  now = () => new Date(),
}: ReviewScanDependencies) {
  return async function reviewScan(request: ReviewScanRequest): Promise<ReviewEvent> {
    const record = await reviewStore.findScanRecord(request.record_id)

    if (record === null) {
      throw new InvalidUsageError(`No stored scan record found for "${request.record_id}".`)
    }

    const createdAt = now().toISOString()
    const reviewTarget = resolveReviewTarget(record, request.target_id)
    const reviewEvent: ReviewEvent = {
      event_id: `${createdAt}:${reviewTarget.target_id}:${request.outcome}`,
      record_id: record.record_id,
      review_target: reviewTarget,
      created_at: createdAt,
      outcome: request.outcome,
      notes: normalizeNotes(request.notes),
      resolution_timestamp: request.outcome === 'needs_review' ? null : createdAt,
      review_source: request.review_source,
      confidence: request.confidence,
    }

    await reviewStore.appendReviewEvent(reviewEvent)

    return reviewEvent
  }
}

function resolveReviewTarget(record: ScanReviewRecord, targetId: string | undefined): ReviewTarget {
  const reviewTargets = [
    ...record.findings.map((finding) => finding.review_target),
    ...record.edge_findings.map((edgeFinding) => edgeFinding.review_target),
  ]

  if (reviewTargets.length === 0) {
    throw new InvalidUsageError(
      `Stored scan record "${record.record_id}" has no reviewable findings or edge changes.`,
    )
  }

  if (targetId === undefined) {
    if (reviewTargets.length === 1) {
      return reviewTargets[0]!
    }

    throw new InvalidUsageError(
      `Stored scan record "${record.record_id}" has multiple review targets. Re-run with --target <target_id>. Available targets: ${reviewTargets.map((target) => target.target_id).join(', ')}`,
    )
  }

  const normalizedTargetId = targetId.trim()

  if (normalizedTargetId.length === 0) {
    throw new InvalidUsageError('Review target id must not be empty.')
  }

  const reviewTarget = reviewTargets.find((candidate) => candidate.target_id === normalizedTargetId)

  if (reviewTarget === undefined) {
    throw new InvalidUsageError(
      `No review target "${normalizedTargetId}" exists on stored scan record "${record.record_id}".`,
    )
  }

  return reviewTarget
}

function normalizeNotes(notes: string | null): string | null {
  if (notes === null) {
    return null
  }

  const trimmed = notes.trim()

  return trimmed.length > 0 ? trimmed : null
}
