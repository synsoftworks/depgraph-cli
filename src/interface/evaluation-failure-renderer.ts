import type { FailureSurfacingSummary } from '../domain/failure-surfacing.js'

/**
 * Renders failure-surfacing output as deterministic JSON.
 *
 * @param summary Failure surfacing summary to render.
 * @returns JSON representation of the summary.
 */
export function renderFailureSurfacingJson(summary: FailureSurfacingSummary): string {
  return JSON.stringify(summary, null, 2)
}

/**
 * Renders failure-surfacing output as deterministic plain text.
 *
 * @param summary Failure surfacing summary to render.
 * @returns Plain-text failure surfacing report.
 */
export function renderFailureSurfacingPlainText(summary: FailureSurfacingSummary): string {
  const lines = [
    `Total scans: ${summary.total_records_scanned}`,
    `Matched failure patterns: ${summary.total_matches}`,
    '',
    'Known failure matches:',
  ]

  if (summary.failures.length === 0) {
    lines.push('- none')
    return lines.join('\n')
  }

  for (const failure of summary.failures) {
    lines.push(
      `- ${failure.package}@${failure.version} [${failure.failure_class}] ${failure.status}`,
    )
    lines.push(`  records: ${failure.record_ids.join(', ')}`)
    lines.push(`  reason: ${failure.reason}`)
  }

  return lines.join('\n')
}
