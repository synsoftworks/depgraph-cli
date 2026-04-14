import type { ScanResult } from './entities.js'

/** Supported benchmark package availability states. */
export const BENCHMARK_AVAILABILITIES = [
  'live',
  'tombstoned',
  'removed',
  'not_yet_verified',
  'private_registry_only',
] as const

/** Availability classification for a benchmark case. */
export type BenchmarkAvailability = (typeof BENCHMARK_AVAILABILITIES)[number]

/** Expected benchmark priorities used in assertions. */
export const EXPECTED_PRIORITIES = ['safe', 'normal', 'high_priority_review'] as const

/** Expected priority outcome for a benchmark case. */
export type ExpectedPriority = (typeof EXPECTED_PRIORITIES)[number]

/** Terminal benchmark execution statuses. */
export const BENCHMARK_STATUSES = ['PASS', 'FAIL', 'SKIPPED'] as const

/** Status for one evaluated benchmark case. */
export type BenchmarkStatus = (typeof BENCHMARK_STATUSES)[number]

/** One benchmark manifest entry. */
export interface BenchmarkCase {
  id: string
  package: string
  availability: BenchmarkAvailability
  skip_reason?: string
  failure_note?: string
  expected_priority: ExpectedPriority
  expected_signals: string[]
}

/** Result of running one benchmark case. */
export interface BenchmarkResult {
  id: string
  package: string
  availability: BenchmarkAvailability
  status: BenchmarkStatus
  expected_priority: ExpectedPriority
  actual_priority: ExpectedPriority | null
  expected_signals: string[]
  actual_signals: string[]
  missing_signals: string[]
  risk_score: number | null
  threshold: number | null
  skip_reason: string | null
  failure_reason: string | null
}

/** Aggregate counts for a benchmark suite run. */
export interface BenchmarkSummary {
  pass: number
  fail: number
  skipped: number
  total: number
}

/** Full result set for a benchmark suite run. */
export interface BenchmarkSuiteResult {
  results: BenchmarkResult[]
  summary: BenchmarkSummary
}

/** Port for loading benchmark cases from a manifest source. */
export interface BenchmarkManifestLoader {
  loadManifest(): Promise<BenchmarkCase[]>
}

/** Port for executing a benchmark scan. */
export interface BenchmarkScanRunner {
  runScan(packageSpec: string): Promise<ScanResult>
}
