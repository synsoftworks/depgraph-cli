import { appendFile, mkdir, readFile } from 'node:fs/promises'
import { dirname, join } from 'node:path'

import type { BaselineIdentity, ReviewEvent, ScanReviewRecord } from '../domain/contracts.js'
import { StorageFailureError } from '../domain/errors.js'
import type { ScanReviewStore } from '../domain/ports.js'
import { normalizeScanReviewRecord } from '../domain/scan-review-records.js'
import {
  createPackageFindingReviewTarget,
} from '../domain/review-targets.js'
import { baselineKeyForIdentity } from '../domain/value-objects.js'

interface JsonlScanReviewStorePaths {
  scanRecordsPath: string
  reviewEventsPath: string
}

/** JSONL-backed implementation of the scan review store. */
export class JsonlScanReviewStore implements ScanReviewStore {
  constructor(private readonly paths: JsonlScanReviewStorePaths) {}

  async appendScanRecord(record: ScanReviewRecord): Promise<void> {
    await appendJsonlLine(
      this.paths.scanRecordsPath,
      record,
      `Unable to append scan record to ${this.paths.scanRecordsPath}`,
    )
  }

  async findLatestScanByBaseline(baselineIdentity: BaselineIdentity): Promise<ScanReviewRecord | null> {
    const records = await this.readScanRecords()
    const baselineKey = baselineKeyForIdentity(baselineIdentity)

    for (let index = records.length - 1; index >= 0; index -= 1) {
      const record = records[index]

      if (record?.baseline_key === baselineKey) {
        return record
      }
    }

    return null
  }

  async findScanRecord(recordId: string): Promise<ScanReviewRecord | null> {
    const records = await this.readScanRecords()

    for (let index = records.length - 1; index >= 0; index -= 1) {
      const record = records[index]

      if (record?.record_id === recordId) {
        return record
      }
    }

    return null
  }

  async appendReviewEvent(event: ReviewEvent): Promise<void> {
    await appendJsonlLine(
      this.paths.reviewEventsPath,
      event,
      `Unable to append review event to ${this.paths.reviewEventsPath}`,
    )
  }

  async listScanRecords(): Promise<ScanReviewRecord[]> {
    return this.readScanRecords()
  }

  async listReviewEvents(): Promise<ReviewEvent[]> {
    const reviewEvents = await readJsonlFile<StoredReviewEvent>(
      this.paths.reviewEventsPath,
      `Unable to read review history from ${this.paths.reviewEventsPath}`,
      `Unable to parse review history in ${this.paths.reviewEventsPath}`,
    )

    return reviewEvents.map(normalizeStoredReviewEvent)
  }

  private async readScanRecords(): Promise<ScanReviewRecord[]> {
    const records = await readJsonlFile<ScanReviewRecord>(
      this.paths.scanRecordsPath,
      `Unable to read scan history from ${this.paths.scanRecordsPath}`,
      `Unable to parse scan history in ${this.paths.scanRecordsPath}`,
    )

    return records.map((record) => normalizeScanReviewRecord(record))
  }
}

/**
 * Returns the default repo-local JSONL persistence paths.
 *
 * @param workingDirectory Working directory used to anchor `.depgraph`.
 * @returns Paths for scan and review history files.
 */
export function defaultScanReviewStorePaths(workingDirectory: string): JsonlScanReviewStorePaths {
  // Keep append-only history repo-local and inspectable instead of hiding mutable state in a user-global cache.
  return {
    scanRecordsPath: join(workingDirectory, '.depgraph', 'scans.jsonl'),
    reviewEventsPath: join(workingDirectory, '.depgraph', 'review-events.jsonl'),
  }
}

async function appendJsonlLine(path: string, value: unknown, prefix: string): Promise<void> {
  try {
    await mkdir(dirname(path), {
      recursive: true,
    })
    await appendFile(path, `${JSON.stringify(value)}\n`, 'utf8')
  } catch (error) {
    throw new StorageFailureError(`${prefix}: ${getErrorMessage(error)}`)
  }
}

async function readJsonlFile<T>(
  path: string,
  readFailurePrefix: string,
  parseFailurePrefix: string,
): Promise<T[]> {
  let contents = ''

  try {
    contents = await readFile(path, 'utf8')
  } catch (error) {
    if (isFileMissing(error)) {
      return []
    }

    throw new StorageFailureError(`${readFailurePrefix}: ${getErrorMessage(error)}`)
  }

  const lines = contents.split('\n').filter((line) => line.trim().length > 0)

  try {
    return lines.map((line) => JSON.parse(line) as T)
  } catch (error) {
    throw new StorageFailureError(`${parseFailurePrefix}: ${getErrorMessage(error)}`)
  }
}

type StoredReviewEvent = ReviewEvent & {
  package_key?: string
}

function normalizeStoredReviewEvent(event: StoredReviewEvent): ReviewEvent {
  if (event.review_target !== undefined) {
    return event
  }

  const packageKey = event.package_key

  if (packageKey === undefined) {
    throw new StorageFailureError(
      `Unable to parse review history event "${event.event_id}": explicit review_target is required.`,
    )
  }

  return {
    event_id: event.event_id,
    record_id: event.record_id,
    review_target: createPackageFindingReviewTarget(event.record_id, packageKey),
    created_at: event.created_at,
    outcome: event.outcome,
    notes: event.notes,
    resolution_timestamp: event.resolution_timestamp,
    review_source: event.review_source,
    confidence: event.confidence,
  }
}

function isFileMissing(error: unknown): error is NodeJS.ErrnoException {
  return error instanceof Error && 'code' in error && error.code === 'ENOENT'
}

function getErrorMessage(error: unknown): string {
  return error instanceof Error ? error.message : String(error)
}
