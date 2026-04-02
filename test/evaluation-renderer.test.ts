import assert from 'node:assert/strict'
import test from 'node:test'

import { renderEvaluationJson, renderEvaluationPlainText } from '../src/interface/evaluation-renderer.js'
import type { EvaluationSummary } from '../src/domain/contracts.js'

test('evaluation renderer surfaces raw events and derived canonical labels', () => {
  const summary = createSummary()
  const plainText = renderEvaluationPlainText(summary)
  const json = renderEvaluationJson(summary)

  assert.match(plainText, /Raw review events:/)
  assert.match(plainText, /Canonical labels \(derived from latest_label_bearing_event\):/)
  assert.match(plainText, /- total: 3/)
  assert.match(plainText, /- labeled records: 2/)
  assert.match(plainText, /Workflow status:/)
  assert.deepEqual(JSON.parse(json), summary)
})

function createSummary(): EvaluationSummary {
  return {
    total_scans: 3,
    raw_review_events: {
      total_events: 3,
      malicious_events: 1,
      benign_events: 1,
      needs_review_events: 1,
    },
    canonical_labels: {
      total_labeled_records: 2,
      malicious_records: 1,
      benign_records: 1,
      unlabeled_records: 1,
      derived_from: 'latest_label_bearing_event',
    },
    workflow_status: {
      unreviewed_records: 1,
      needs_review_records: 1,
      resolved_records: 1,
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
