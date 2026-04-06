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

  lines.push(
    '',
    'Field reliability distribution:',
    `- exact tier counts from ADR-012-ready records: ${summary.field_reliability_distribution.records_with_field_reliability}`,
    `- records excluded for missing ADR-012 metadata: ${summary.field_reliability_distribution.records_excluded_missing_field_reliability}`,
    `- reliable: ${summary.field_reliability_distribution.reliable}`,
    `- conditionally reliable: ${summary.field_reliability_distribution.conditionally_reliable}`,
    `- unavailable: ${summary.field_reliability_distribution.unavailable}`,
    `- placeholder: ${summary.field_reliability_distribution.placeholder}`,
    `- heuristic output: ${summary.field_reliability_distribution.heuristic_output}`,
    `- structural only: ${summary.field_reliability_distribution.structural_only}`,
    `- scan context: ${summary.field_reliability_distribution.scan_context}`,
    '',
    'Integrity signals:',
    `- synthetic project roots: ${summary.integrity_signals.synthetic_project_root_count}`,
    `- unresolved registry lookups: ${summary.integrity_signals.unresolved_registry_lookup_count}`,
    `- deprecated security signals: ${summary.integrity_signals.deprecated_with_security_signal_count}`,
    '',
    'Field readiness issues:',
    `- dependents_count unavailable: ${summary.field_readiness_issues.dependents_count_unavailable_count}`,
    `- has_advisories placeholder rows: ${summary.field_readiness_issues.has_advisories_placeholder_count}`,
    `- records missing ADR-012 metadata: ${summary.field_readiness_issues.records_missing_field_reliability_count}`,
    '',
    'Heuristic output presence:',
    `- rows with risk_score: ${summary.heuristic_output_presence.nodes_with_risk_score}`,
    `- rows with risk_level: ${summary.heuristic_output_presence.nodes_with_risk_level}`,
    `- rows with recommendation: ${summary.heuristic_output_presence.nodes_with_recommendation}`,
    `- rows with signals: ${summary.heuristic_output_presence.nodes_with_signals}`,
    '',
    'Export readiness:',
    '- exact export-ready counts are based only on ADR-012-ready records',
    `- records total: ${summary.export_readiness.records_total}`,
    `- records with ADR-012 metadata: ${summary.export_readiness.records_with_field_reliability}`,
    `- export-ready records: ${summary.export_readiness.records_export_ready}`,
    `- records excluded for missing ADR-012 metadata: ${summary.export_readiness.records_excluded_missing_field_reliability}`,
    `- rows total: ${summary.export_readiness.rows_total}`,
    `- rows from ADR-012-ready records: ${summary.export_readiness.rows_with_reliability_metadata}`,
    `- export-ready rows: ${summary.export_readiness.rows_export_ready}`,
    `- rows excluded for missing ADR-012 metadata: ${summary.export_readiness.rows_excluded_missing_field_reliability}`,
    `- rows excluded for placeholder fields: ${summary.export_readiness.rows_excluded_placeholder_fields}`,
    `- rows excluded for unavailable fields: ${summary.export_readiness.rows_excluded_unavailable_fields}`,
    `- rows excluded for package-level reasons: ${summary.export_readiness.rows_excluded_package_level}`,
    '- conditionally reliable fields remain eligible only when missingness is preserved explicitly',
  )

  const warnings = renderReadinessWarnings(summary)

  if (warnings.length > 0) {
    lines.push('', 'Readiness warnings:')
    lines.push(...warnings.map((warning) => `- ${warning}`))
  }

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

function renderReadinessWarnings(summary: EvaluationSummary): string[] {
  const warnings: string[] = []

  if (summary.integrity_signals.deprecated_with_security_signal_count > 0) {
    warnings.push(
      `Known security-related deprecation signals detected: ${summary.integrity_signals.deprecated_with_security_signal_count}`,
    )
  }

  if (summary.field_readiness_issues.records_missing_field_reliability_count > 0) {
    warnings.push(
      'Some historical scan records predate ADR-012 and were excluded from exact tier-based readiness calculations.',
    )
  }

  return warnings
}
