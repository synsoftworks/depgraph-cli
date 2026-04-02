import type { ReviewEvent, ReviewScanRequest } from '../domain/contracts.js'
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
    const reviewEvent: ReviewEvent = {
      event_id: `${createdAt}:${request.record_id}:${request.outcome}`,
      record_id: record.record_id,
      package_key: record.package_key,
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

function normalizeNotes(notes: string | null): string | null {
  if (notes === null) {
    return null
  }

  const trimmed = notes.trim()

  return trimmed.length > 0 ? trimmed : null
}
