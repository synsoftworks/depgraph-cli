import type { ReviewEvent } from '../domain/contracts.js'

export function renderReviewJson(event: ReviewEvent): string {
  return JSON.stringify(event, null, 2)
}

export function renderReviewPlainText(event: ReviewEvent): string {
  const lines = [
    `Review event appended: ${event.record_id}`,
    `Outcome: ${event.outcome}`,
    `Source: ${event.review_source}`,
  ]

  if (event.confidence !== null) {
    lines.push(`Confidence: ${event.confidence.toFixed(2)}`)
  }

  if (event.notes !== null) {
    lines.push(`Notes: ${event.notes}`)
  }

  if (event.resolution_timestamp !== null) {
    lines.push(`Resolved at: ${event.resolution_timestamp}`)
  }

  return lines.join('\n')
}
