import { readFile } from 'node:fs/promises'
import { resolve } from 'node:path'

import {
  BENCHMARK_AVAILABILITIES,
  EXPECTED_PRIORITIES,
  type BenchmarkAvailability,
  type BenchmarkCase,
  type BenchmarkManifestLoader,
  type ExpectedPriority,
} from '../domain/benchmark.js'
import { InvalidUsageError, StorageFailureError } from '../domain/errors.js'

export const DEFAULT_BENCHMARK_MANIFEST_PATH = resolve(
  process.cwd(),
  '.internal/benchmarks/benchmark-manifest.json',
)

export class JsonBenchmarkManifestLoader implements BenchmarkManifestLoader {
  constructor(private readonly manifestPath = DEFAULT_BENCHMARK_MANIFEST_PATH) {}

  async loadManifest(): Promise<BenchmarkCase[]> {
    let rawManifest: string

    try {
      rawManifest = await readFile(this.manifestPath, 'utf8')
    } catch (error) {
      throw new StorageFailureError(
        `Benchmark manifest could not be read from "${this.manifestPath}": ${getErrorMessage(error)}`,
      )
    }

    let parsed: unknown

    try {
      parsed = JSON.parse(rawManifest)
    } catch (error) {
      throw new InvalidUsageError(
        `Benchmark manifest at "${this.manifestPath}" is not valid JSON: ${getErrorMessage(error)}`,
      )
    }

    return parseBenchmarkManifest(parsed, this.manifestPath)
  }
}

function parseBenchmarkManifest(parsed: unknown, manifestPath: string): BenchmarkCase[] {
  if (!Array.isArray(parsed)) {
    throw new InvalidUsageError(`Benchmark manifest at "${manifestPath}" must be an array.`)
  }

  const seenIds = new Set<string>()

  return parsed.map((entry, index) => {
    const benchmarkCase = parseBenchmarkEntry(entry, manifestPath, index)

    if (seenIds.has(benchmarkCase.id)) {
      throw new InvalidUsageError(
        `Benchmark manifest at "${manifestPath}" contains a duplicate id "${benchmarkCase.id}".`,
      )
    }

    seenIds.add(benchmarkCase.id)
    return benchmarkCase
  })
}

function parseBenchmarkEntry(
  entry: unknown,
  manifestPath: string,
  index: number,
): BenchmarkCase {
  if (!isRecord(entry)) {
    throw new InvalidUsageError(
      `Benchmark manifest entry ${index} at "${manifestPath}" must be an object.`,
    )
  }

  const skipReason = parseOptionalString(entry.skip_reason, 'skip_reason', manifestPath, index)
  const failureNote = parseOptionalString(entry.failure_note, 'failure_note', manifestPath, index)
  const benchmarkCase: BenchmarkCase = {
    id: parseRequiredString(entry.id, 'id', manifestPath, index),
    package: parseRequiredString(entry.package, 'package', manifestPath, index),
    availability: parseAvailability(entry.availability, manifestPath, index),
    expected_priority: parseExpectedPriority(entry.expected_priority, manifestPath, index),
    expected_signals: parseExpectedSignals(entry.expected_signals, manifestPath, index),
  }

  if (skipReason !== undefined) {
    benchmarkCase.skip_reason = skipReason
  }

  if (failureNote !== undefined) {
    benchmarkCase.failure_note = failureNote
  }

  return benchmarkCase
}

function parseAvailability(
  value: unknown,
  manifestPath: string,
  index: number,
): BenchmarkAvailability {
  if (typeof value === 'string' && BENCHMARK_AVAILABILITIES.includes(value as BenchmarkAvailability)) {
    return value as BenchmarkAvailability
  }

  throw new InvalidUsageError(
    `Benchmark manifest entry ${index} at "${manifestPath}" has invalid availability.`,
  )
}

function parseExpectedPriority(
  value: unknown,
  manifestPath: string,
  index: number,
): ExpectedPriority {
  if (typeof value === 'string' && EXPECTED_PRIORITIES.includes(value as ExpectedPriority)) {
    return value as ExpectedPriority
  }

  throw new InvalidUsageError(
    `Benchmark manifest entry ${index} at "${manifestPath}" has invalid expected_priority.`,
  )
}

function parseExpectedSignals(
  value: unknown,
  manifestPath: string,
  index: number,
): string[] {
  if (!Array.isArray(value) || value.some((signal) => typeof signal !== 'string' || signal.trim().length === 0)) {
    throw new InvalidUsageError(
      `Benchmark manifest entry ${index} at "${manifestPath}" has invalid expected_signals.`,
    )
  }

  return value.map((signal) => signal.trim())
}

function parseRequiredString(
  value: unknown,
  fieldName: string,
  manifestPath: string,
  index: number,
): string {
  if (typeof value === 'string' && value.trim().length > 0) {
    return value.trim()
  }

  throw new InvalidUsageError(
    `Benchmark manifest entry ${index} at "${manifestPath}" is missing "${fieldName}".`,
  )
}

function parseOptionalString(
  value: unknown,
  fieldName: string,
  manifestPath: string,
  index: number,
): string | undefined {
  if (value === undefined) {
    return undefined
  }

  if (typeof value === 'string' && value.trim().length > 0) {
    return value.trim()
  }

  throw new InvalidUsageError(
    `Benchmark manifest entry ${index} at "${manifestPath}" has invalid "${fieldName}".`,
  )
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null
}

function getErrorMessage(error: unknown): string {
  if (error instanceof Error) {
    return error.message
  }

  return String(error)
}
