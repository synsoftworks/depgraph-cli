#!/usr/bin/env node

import { JsonBenchmarkManifestLoader } from '../adapters/benchmark-manifest-loader.js'
import { CliBenchmarkScanRunner } from '../adapters/scan-runner.js'
import { runBenchmarkSuite } from '../application/run-benchmark-suite.js'
import { renderBenchmarkSuite } from '../interface/benchmark-renderer.js'

async function main(): Promise<void> {
  const suiteResult = await runBenchmarkSuite({
    manifestLoader: new JsonBenchmarkManifestLoader(),
    scanRunner: new CliBenchmarkScanRunner(),
  })

  process.stdout.write(`${renderBenchmarkSuite(suiteResult)}\n`)
  process.exitCode = suiteResult.summary.fail > 0 ? 1 : 0
}

main().catch((error: unknown) => {
  process.stderr.write(`${getErrorMessage(error)}\n`)
  process.exitCode = 1
})

function getErrorMessage(error: unknown): string {
  if (error instanceof Error) {
    return error.message
  }

  return String(error)
}
