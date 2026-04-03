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
  assert.deepEqual(Object.keys(parsed), [
    'total_scans',
    'review_targets',
    'raw_review_events',
    'canonical_labels',
    'workflow_status',
    'signal_frequency',
    'metadata_coverage',
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
  }
}
