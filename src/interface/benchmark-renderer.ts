import type { BenchmarkResult, BenchmarkSuiteResult } from '../domain/benchmark.js'

export function renderBenchmarkSuite(suiteResult: BenchmarkSuiteResult): string {
  const idWidth = Math.max(...suiteResult.results.map((result) => result.id.length), 'ID'.length)
  const packageWidth = Math.max(
    ...suiteResult.results.map((result) => result.package.length),
    'Package'.length,
  )

  const lines = suiteResult.results.map((result) =>
    renderBenchmarkResult(result, {
      idWidth,
      packageWidth,
    }),
  )

  lines.push(
    '',
    'Summary:',
    `- PASS: ${suiteResult.summary.pass}`,
    `- FAIL: ${suiteResult.summary.fail}`,
    `- SKIPPED: ${suiteResult.summary.skipped}`,
  )

  return lines.join('\n')
}

function renderBenchmarkResult(
  result: BenchmarkResult,
  widths: {
    idWidth: number
    packageWidth: number
  },
): string {
  const idColumn = result.id.padEnd(widths.idWidth)
  const packageColumn = result.package.padEnd(widths.packageWidth)
  const statusColumn = result.status.padEnd(8)

  return `${idColumn}  ${packageColumn}  ${statusColumn} ${renderBenchmarkDetail(result)}`
}

function renderBenchmarkDetail(result: BenchmarkResult): string {
  if (result.status === 'SKIPPED') {
    return `(${result.skip_reason ?? `availability: ${result.availability}`})`
  }

  if (result.status === 'PASS') {
    const riskScore = result.risk_score === null ? 'n/a' : result.risk_score.toFixed(2)
    return `(${result.actual_priority ?? 'unknown'} ${riskScore})`
  }

  if (result.failure_reason?.startsWith('scan failed:') === true) {
    return `(${result.failure_reason})`
  }

  const details: string[] = []

  if (result.actual_priority !== null && result.risk_score !== null) {
    details.push(
      `expected: ${result.expected_priority}, got: ${result.actual_priority} ${result.risk_score.toFixed(2)}`,
    )
  } else {
    details.push(`expected: ${result.expected_priority}, got: unavailable`)
  }

  if (result.missing_signals.length > 0) {
    details.push(`missing signals: ${result.missing_signals.join(', ')}`)
  }

  return `(${details.join('; ')})`
}
