import type { ScanResult } from './entities.js'

export const BENCHMARK_AVAILABILITIES = [
  'live',
  'tombstoned',
  'removed',
  'not_yet_verified',
  'private_registry_only',
] as const

export type BenchmarkAvailability = (typeof BENCHMARK_AVAILABILITIES)[number]

export const EXPECTED_PRIORITIES = ['safe', 'normal', 'high_priority_review'] as const

export type ExpectedPriority = (typeof EXPECTED_PRIORITIES)[number]

export const BENCHMARK_STATUSES = ['PASS', 'FAIL', 'SKIPPED'] as const

export type BenchmarkStatus = (typeof BENCHMARK_STATUSES)[number]

export interface BenchmarkCase {
  id: string
  package: string
  availability: BenchmarkAvailability
  skip_reason?: string
  failure_note?: string
  expected_priority: ExpectedPriority
  expected_signals: string[]
}

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

export interface BenchmarkSummary {
  pass: number
  fail: number
  skipped: number
  total: number
}

export interface BenchmarkSuiteResult {
  results: BenchmarkResult[]
  summary: BenchmarkSummary
}

export interface BenchmarkManifestLoader {
  loadManifest(): Promise<BenchmarkCase[]>
}

export interface BenchmarkScanRunner {
  runScan(packageSpec: string): Promise<ScanResult>
}
