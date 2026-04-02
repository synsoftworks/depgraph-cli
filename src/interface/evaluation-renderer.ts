import type { EvaluationSummary } from '../domain/contracts.js'

export function renderEvaluationJson(summary: EvaluationSummary): string {
  return JSON.stringify(summary, null, 2)
}

export function renderEvaluationPlainText(summary: EvaluationSummary): string {
  const lines = [
    `Total scans: ${summary.total_scans}`,
    `Labeled records: ${summary.labeled_records}`,
    `Malicious: ${summary.malicious_count}`,
    `Benign: ${summary.benign_count}`,
    `Needs review: ${summary.needs_review_count}`,
    '',
    'Metadata coverage:',
    `- weekly_downloads missing: ${summary.metadata_coverage.weekly_downloads.missing_count}/${summary.metadata_coverage.weekly_downloads.total_nodes} nodes (${summary.metadata_coverage.weekly_downloads.missing_percent.toFixed(2)}%)`,
    `- dependents_count missing: ${summary.metadata_coverage.dependents_count.missing_count}/${summary.metadata_coverage.dependents_count.total_nodes} nodes (${summary.metadata_coverage.dependents_count.missing_percent.toFixed(2)}%)`,
    '',
    'Signal frequency:',
  ]

  if (summary.signal_frequency.length === 0) {
    lines.push('- none')
  } else {
    for (const item of summary.signal_frequency) {
      lines.push(`- ${item.type}: ${item.count}`)
    }
  }

  lines.push('', 'Signal frequency by weekly_downloads coverage:')
  lines.push(...renderCoverageSignals(summary.metadata_coverage.signal_frequency_by_weekly_downloads))
  lines.push('', 'Signal frequency by dependents_count coverage:')
  lines.push(...renderCoverageSignals(summary.metadata_coverage.signal_frequency_by_dependents_count))

  return lines.join('\n')
}

function renderCoverageSignals(summary: EvaluationSummary['metadata_coverage']['signal_frequency_by_weekly_downloads']): string[] {
  const lines = ['- known:']

  if (summary.known.length === 0) {
    lines.push('  none')
  } else {
    for (const item of summary.known) {
      lines.push(`  ${item.type}: ${item.count}`)
    }
  }

  lines.push('- missing:')

  if (summary.missing.length === 0) {
    lines.push('  none')
  } else {
    for (const item of summary.missing) {
      lines.push(`  ${item.type}: ${item.count}`)
    }
  }

  return lines
}
