import type { EvaluationSummary } from '../domain/contracts.js'

export function renderEvaluationJson(summary: EvaluationSummary): string {
  return JSON.stringify(summary, null, 2)
}

export function renderEvaluationPlainText(summary: EvaluationSummary): string {
  const lines = [
    `Total scans: ${summary.total_scans}`,
    '',
    'Review targets:',
    `- total: ${summary.review_targets.total_targets}`,
    `- package findings: ${summary.review_targets.package_finding_targets}`,
    `- edge findings: ${summary.review_targets.edge_finding_targets}`,
    '',
    'Raw review events:',
    `- total: ${summary.raw_review_events.total_events}`,
    `- malicious: ${summary.raw_review_events.malicious_events}`,
    `- benign: ${summary.raw_review_events.benign_events}`,
    `- needs_review: ${summary.raw_review_events.needs_review_events}`,
    '',
    `Canonical labels (${formatDerivedFrom(summary.canonical_labels.derived_from)}):`,
    `- labeled targets: ${summary.canonical_labels.total_labeled_targets}`,
    `- malicious: ${summary.canonical_labels.malicious_targets}`,
    `- benign: ${summary.canonical_labels.benign_targets}`,
    `- unlabeled: ${summary.canonical_labels.unlabeled_targets}`,
    '',
    'Workflow status:',
    `- unreviewed: ${summary.workflow_status.unreviewed_targets}`,
    `- needs_review: ${summary.workflow_status.needs_review_targets}`,
    `- resolved: ${summary.workflow_status.resolved_targets}`,
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

function renderCoverageSignals(
  summary: EvaluationSummary['metadata_coverage']['signal_frequency_by_weekly_downloads'],
): string[] {
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

function formatDerivedFrom(derivedFrom: EvaluationSummary['canonical_labels']['derived_from']): string {
  switch (derivedFrom) {
    case 'source_precedence_then_latest_within_source':
      return 'source precedence, then latest within source'
  }
}
