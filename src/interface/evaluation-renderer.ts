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
    'Signal frequency:',
  ]

  if (summary.signal_frequency.length === 0) {
    lines.push('- none')
  } else {
    for (const item of summary.signal_frequency) {
      lines.push(`- ${item.type}: ${item.count}`)
    }
  }

  return lines.join('\n')
}
