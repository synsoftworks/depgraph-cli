import type {
  BenchmarkManifestLoader,
  BenchmarkScanRunner,
  BenchmarkSuiteResult,
} from '../domain/benchmark.js'
import { evaluateBenchmarkCase } from './evaluate-benchmark-case.js'

export interface RunBenchmarkSuiteDependencies {
  manifestLoader: BenchmarkManifestLoader
  scanRunner: BenchmarkScanRunner
}

export async function runBenchmarkSuite(
  dependencies: RunBenchmarkSuiteDependencies,
): Promise<BenchmarkSuiteResult> {
  const benchmarkCases = await dependencies.manifestLoader.loadManifest()
  const results = []

  for (const benchmarkCase of benchmarkCases) {
    results.push(
      await evaluateBenchmarkCase(benchmarkCase, {
        scanRunner: dependencies.scanRunner,
      }),
    )
  }

  return {
    results,
    summary: summarizeBenchmarkResults(results),
  }
}

function summarizeBenchmarkResults(
  results: BenchmarkSuiteResult['results'],
): BenchmarkSuiteResult['summary'] {
  let pass = 0
  let fail = 0
  let skipped = 0

  for (const result of results) {
    switch (result.status) {
      case 'PASS':
        pass += 1
        break
      case 'FAIL':
        fail += 1
        break
      case 'SKIPPED':
        skipped += 1
        break
    }
  }

  return {
    pass,
    fail,
    skipped,
    total: results.length,
  }
}
