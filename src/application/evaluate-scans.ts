import type { EvaluationSummary, ReviewEvent, SignalFrequency } from '../domain/contracts.js'
import type { PackageNode, RiskSignal } from '../domain/entities.js'
import type { ScanReviewStore } from '../domain/ports.js'

interface EvaluateScansDependencies {
  reviewStore: ScanReviewStore
}

export function createEvaluateScansUseCase({ reviewStore }: EvaluateScansDependencies) {
  return async function evaluateScans(): Promise<EvaluationSummary> {
    const [scanRecords, reviewEvents] = await Promise.all([
      reviewStore.listScanRecords(),
      reviewStore.listReviewEvents(),
    ])

    const latestReviewByRecordId = selectLatestReviews(reviewEvents)
    const signalCounts = new Map<string, number>()
    let maliciousCount = 0
    let benignCount = 0
    let needsReviewCount = 0

    for (const record of scanRecords) {
      collectSignals(record.root.signals, signalCounts)
      collectNodeSignals(record.root.dependencies, signalCounts)

      const latestReview = latestReviewByRecordId.get(record.record_id)

      if (latestReview === undefined) {
        continue
      }

      switch (latestReview.outcome) {
        case 'malicious':
          maliciousCount += 1
          break
        case 'benign':
          benignCount += 1
          break
        case 'needs_review':
          needsReviewCount += 1
          break
      }
    }

    return {
      total_scans: scanRecords.length,
      labeled_records: latestReviewByRecordId.size,
      malicious_count: maliciousCount,
      benign_count: benignCount,
      needs_review_count: needsReviewCount,
      signal_frequency: toSortedSignalFrequency(signalCounts),
    }
  }
}

function selectLatestReviews(reviewEvents: ReviewEvent[]): Map<string, ReviewEvent> {
  const latestByRecordId = new Map<string, ReviewEvent>()

  for (const event of reviewEvents) {
    const current = latestByRecordId.get(event.record_id)

    if (current === undefined || current.created_at < event.created_at) {
      latestByRecordId.set(event.record_id, event)
    }
  }

  return latestByRecordId
}

function collectNodeSignals(nodes: PackageNode['dependencies'], counts: Map<string, number>): void {
  for (const node of nodes) {
    collectSignals(node.signals, counts)
    collectNodeSignals(node.dependencies, counts)
  }
}

function collectSignals(signals: RiskSignal[], counts: Map<string, number>): void {
  for (const signal of signals) {
    counts.set(signal.type, (counts.get(signal.type) ?? 0) + 1)
  }
}

function toSortedSignalFrequency(signalCounts: Map<string, number>): SignalFrequency[] {
  return Array.from(signalCounts.entries())
    .map(([type, count]) => ({ type, count }))
    .sort((left, right) => {
      if (left.count !== right.count) {
        return right.count - left.count
      }

      return left.type.localeCompare(right.type)
    })
}
