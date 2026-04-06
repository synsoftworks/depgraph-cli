import assert from 'node:assert/strict'
import test from 'node:test'

import { renderEvaluationJson, renderEvaluationPlainText } from '../src/interface/evaluation-renderer.js'
import type { EvaluationSummary } from '../src/domain/contracts.js'

test('evaluation renderer surfaces raw events and derived canonical labels', () => {
  const summary = createSummary()
  const plainText = renderEvaluationPlainText(summary)
  const json = renderEvaluationJson(summary)
  const parsed = JSON.parse(json)

  assert.match(plainText, /Raw review events:/)
  assert.match(plainText, /Review targets:/)
  assert.match(plainText, /Canonical labels \(source precedence, then latest within source\):/)
  assert.match(plainText, /- total: 3/)
  assert.match(plainText, /- labeled targets: 2/)
  assert.match(plainText, /Workflow status:/)
  assert.match(plainText, /Field reliability distribution:/)
  assert.match(plainText, /exact tier counts from ADR-012-ready records: 1/)
  assert.match(plainText, /records excluded for missing ADR-012 metadata: 1/)
  assert.match(plainText, /Integrity signals:/)
  assert.match(plainText, /Field readiness issues:/)
  assert.match(plainText, /Heuristic output presence:/)
  assert.match(plainText, /Export readiness:/)
  assert.match(plainText, /exact export-ready counts are based only on ADR-012-ready records/)
  assert.match(plainText, /records total: 3/)
  assert.match(plainText, /records with ADR-012 metadata: 1/)
  assert.match(plainText, /rows from ADR-012-ready records: 2/)
  assert.match(plainText, /rows excluded for missing ADR-012 metadata: 2/)
  assert.match(plainText, /rows excluded for placeholder fields: 1/)
  assert.match(plainText, /rows excluded for unavailable fields: 0/)
  assert.match(plainText, /rows excluded for package-level reasons: 1/)
  assert.match(plainText, /blocking reasons present across rows are non-exclusive/)
  assert.match(plainText, /rows with missing ADR-012 metadata blocker: 2/)
  assert.match(plainText, /rows with placeholder field blocker: 1/)
  assert.match(plainText, /rows with unavailable field blocker: 3/)
  assert.match(plainText, /rows with package-level blocker: 1/)
  assert.match(plainText, /conditionally reliable fields remain eligible only when missingness is preserved explicitly/)
  assert.match(plainText, /Known security-related deprecation signals detected: 1/)
  assert.match(
    plainText,
    /Some historical scan records predate ADR-012 and were excluded from exact tier-based readiness calculations\./,
  )
  assert.deepEqual(Object.keys(parsed), [
    'total_scans',
    'review_targets',
    'raw_review_events',
    'canonical_labels',
    'workflow_status',
    'signal_frequency',
    'metadata_coverage',
    'field_reliability_distribution',
    'integrity_signals',
    'field_readiness_issues',
    'heuristic_output_presence',
    'export_readiness',
  ])
  assert.deepEqual(Object.keys(parsed.raw_review_events), [
    'total_events',
    'malicious_events',
    'benign_events',
    'needs_review_events',
  ])
  assert.deepEqual(Object.keys(parsed.canonical_labels), [
    'total_labeled_targets',
    'malicious_targets',
    'benign_targets',
    'unlabeled_targets',
    'derived_from',
  ])
  assert.deepEqual(Object.keys(parsed.workflow_status), [
    'unreviewed_targets',
    'needs_review_targets',
    'resolved_targets',
  ])
  assert.deepEqual(Object.keys(parsed.metadata_coverage), [
    'weekly_downloads',
    'dependents_count',
    'signal_frequency_by_weekly_downloads',
    'signal_frequency_by_dependents_count',
  ])
  assert.deepEqual(Object.keys(parsed.field_reliability_distribution), [
    'records_with_field_reliability',
    'records_excluded_missing_field_reliability',
    'reliable',
    'conditionally_reliable',
    'unavailable',
    'placeholder',
    'heuristic_output',
    'structural_only',
    'scan_context',
  ])
  assert.deepEqual(Object.keys(parsed.export_readiness), [
    'records_total',
    'records_with_field_reliability',
    'records_export_ready',
    'records_excluded_missing_field_reliability',
    'rows_total',
    'rows_with_reliability_metadata',
    'rows_export_ready',
    'rows_excluded_missing_field_reliability',
    'rows_excluded_placeholder_fields',
    'rows_excluded_unavailable_fields',
    'rows_excluded_package_level',
    'rows_blocking_reasons',
  ])
  assert.deepEqual(parsed, summary)
})

function createSummary(): EvaluationSummary {
  return {
    total_scans: 3,
    review_targets: {
      total_targets: 3,
      package_finding_targets: 2,
      edge_finding_targets: 1,
    },
    raw_review_events: {
      total_events: 3,
      malicious_events: 1,
      benign_events: 1,
      needs_review_events: 1,
    },
    canonical_labels: {
      total_labeled_targets: 2,
      malicious_targets: 1,
      benign_targets: 1,
      unlabeled_targets: 1,
      derived_from: 'source_precedence_then_latest_within_source',
    },
    workflow_status: {
      unreviewed_targets: 1,
      needs_review_targets: 1,
      resolved_targets: 1,
    },
    signal_frequency: [{ type: 'root_signal', count: 2 }],
    metadata_coverage: {
      weekly_downloads: {
        total_nodes: 4,
        missing_count: 1,
        missing_percent: 25,
      },
      dependents_count: {
        total_nodes: 4,
        missing_count: 2,
        missing_percent: 50,
      },
      signal_frequency_by_weekly_downloads: {
        known: [{ type: 'root_signal', count: 2 }],
        missing: [],
      },
      signal_frequency_by_dependents_count: {
        known: [],
        missing: [{ type: 'root_signal', count: 2 }],
      },
    },
    field_reliability_distribution: {
      records_with_field_reliability: 1,
      records_excluded_missing_field_reliability: 1,
      reliable: 15,
      conditionally_reliable: 1,
      unavailable: 1,
      placeholder: 1,
      heuristic_output: 15,
      structural_only: 15,
      scan_context: 17,
    },
    integrity_signals: {
      synthetic_project_root_count: 1,
      unresolved_registry_lookup_count: 1,
      deprecated_with_security_signal_count: 1,
    },
    field_readiness_issues: {
      dependents_count_unavailable_count: 3,
      has_advisories_placeholder_count: 3,
      records_missing_field_reliability_count: 1,
    },
    heuristic_output_presence: {
      nodes_with_risk_score: 3,
      nodes_with_risk_level: 3,
      nodes_with_recommendation: 3,
      nodes_with_signals: 3,
    },
    export_readiness: {
      records_total: 3,
      records_with_field_reliability: 1,
      records_export_ready: 0,
      records_excluded_missing_field_reliability: 2,
      rows_total: 4,
      rows_with_reliability_metadata: 2,
      rows_export_ready: 0,
      rows_excluded_missing_field_reliability: 2,
      rows_excluded_placeholder_fields: 1,
      rows_excluded_unavailable_fields: 0,
      rows_excluded_package_level: 1,
      rows_blocking_reasons: {
        missing_field_reliability: 2,
        placeholder_fields: 1,
        unavailable_fields: 3,
        package_level: 1,
      },
    },
  }
}
