import { appendFile, mkdir, readFile } from 'node:fs/promises'
import { dirname, join } from 'node:path'

import type { BaselineIdentity, ReviewEvent, ScanReviewRecord } from '../domain/contracts.js'
import { StorageFailureError } from '../domain/errors.js'
import type { ScanReviewStore } from '../domain/ports.js'
import { baselineKeyForIdentity } from '../domain/value-objects.js'

interface JsonlScanReviewStorePaths {
  scanRecordsPath: string
  reviewEventsPath: string
}

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
    return readJsonlFile<ReviewEvent>(
      this.paths.reviewEventsPath,
      `Unable to read review history from ${this.paths.reviewEventsPath}`,
      `Unable to parse review history in ${this.paths.reviewEventsPath}`,
    )
  }

  private async readScanRecords(): Promise<ScanReviewRecord[]> {
    return readJsonlFile<ScanReviewRecord>(
      this.paths.scanRecordsPath,
      `Unable to read scan history from ${this.paths.scanRecordsPath}`,
      `Unable to parse scan history in ${this.paths.scanRecordsPath}`,
    )
  }
}

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

function isFileMissing(error: unknown): error is NodeJS.ErrnoException {
  return error instanceof Error && 'code' in error && error.code === 'ENOENT'
}

function getErrorMessage(error: unknown): string {
  return error instanceof Error ? error.message : String(error)
}
