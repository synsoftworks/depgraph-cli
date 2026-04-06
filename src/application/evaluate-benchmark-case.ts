import type {
  BenchmarkCase,
  BenchmarkResult,
  BenchmarkScanRunner,
  ExpectedPriority,
} from '../domain/benchmark.js'
import type { ScanResult } from '../domain/entities.js'

export interface EvaluateBenchmarkCaseDependencies {
  scanRunner: BenchmarkScanRunner
}

export async function evaluateBenchmarkCase(
  benchmarkCase: BenchmarkCase,
  dependencies: EvaluateBenchmarkCaseDependencies,
): Promise<BenchmarkResult> {
  if (benchmarkCase.availability !== 'live') {
    return {
      id: benchmarkCase.id,
      package: benchmarkCase.package,
      availability: benchmarkCase.availability,
      status: 'SKIPPED',
      expected_priority: benchmarkCase.expected_priority,
      actual_priority: null,
      expected_signals: [...benchmarkCase.expected_signals],
      actual_signals: [],
      missing_signals: [],
      risk_score: null,
      threshold: null,
      skip_reason: benchmarkCase.skip_reason ?? `availability: ${benchmarkCase.availability}`,
      failure_reason: null,
    }
  }

  try {
    const scanResult = await dependencies.scanRunner.runScan(benchmarkCase.package)
    const actualPriority = mapPriorityFromScan(scanResult)
    const actualSignals = extractActualSignals(scanResult)
    const missingSignals = findMissingSignals(benchmarkCase.expected_signals, actualSignals)
    const priorityMatches = actualPriority === benchmarkCase.expected_priority
    const status = priorityMatches && missingSignals.length === 0 ? 'PASS' : 'FAIL'

    return {
      id: benchmarkCase.id,
      package: benchmarkCase.package,
      availability: benchmarkCase.availability,
      status,
      expected_priority: benchmarkCase.expected_priority,
      actual_priority: actualPriority,
      expected_signals: [...benchmarkCase.expected_signals],
      actual_signals: actualSignals,
      missing_signals: missingSignals,
      risk_score: scanResult.root.risk_score,
      threshold: scanResult.threshold,
      skip_reason: null,
      failure_reason:
        status === 'FAIL'
          ? buildFailureReason(benchmarkCase.expected_priority, actualPriority, missingSignals)
          : null,
    }
  } catch (error) {
    return {
      id: benchmarkCase.id,
      package: benchmarkCase.package,
      availability: benchmarkCase.availability,
      status: 'FAIL',
      expected_priority: benchmarkCase.expected_priority,
      actual_priority: null,
      expected_signals: [...benchmarkCase.expected_signals],
      actual_signals: [],
      missing_signals: [...benchmarkCase.expected_signals],
      risk_score: null,
      threshold: null,
      skip_reason: null,
      failure_reason: `scan failed: ${getErrorMessage(error)}`,
    }
  }
}

export function mapPriorityFromScan(scanResult: ScanResult): ExpectedPriority {
  if (scanResult.root.risk_score >= scanResult.threshold) {
    return 'high_priority_review'
  }

  if (scanResult.warnings.length > 0) {
    return 'normal'
  }

  return 'safe'
}

export function extractActualSignals(scanResult: ScanResult): string[] {
  const signals = new Set<string>()

  for (const signal of scanResult.root.signals) {
    signals.add(signal.type)
  }

  for (const warning of scanResult.warnings) {
    signals.add(warning.kind)
  }

  return [...signals].sort((left, right) => left.localeCompare(right))
}

export function findMissingSignals(expectedSignals: string[], actualSignals: string[]): string[] {
  const actualSignalSet = new Set(actualSignals)

  return expectedSignals.filter((signal) => !actualSignalSet.has(signal))
}

function buildFailureReason(
  expectedPriority: ExpectedPriority,
  actualPriority: ExpectedPriority,
  missingSignals: string[],
): string {
  const reasons: string[] = []

  if (expectedPriority !== actualPriority) {
    reasons.push(`expected priority ${expectedPriority}, got ${actualPriority}`)
  }

  if (missingSignals.length > 0) {
    reasons.push(`missing signals: ${missingSignals.join(', ')}`)
  }

  return reasons.join('; ')
}

function getErrorMessage(error: unknown): string {
  if (error instanceof Error) {
    return error.message
  }

  return String(error)
}
