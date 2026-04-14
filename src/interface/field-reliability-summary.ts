import type { ScanResult } from '../domain/entities.js'

/**
 * Produces concise human-readable ADR-012 field reliability notes for scan output.
 *
 * @param result Completed scan result with field reliability metadata.
 * @returns Summary lines for plain-text rendering.
 */
export function getFieldReliabilityPolicySummary(result: ScanResult): string[] {
  const fields = result.field_reliability.fields

  return [
    summarizeField(
      'weekly_downloads',
      'package_node.weekly_downloads',
      fields['package_node.weekly_downloads']?.tier,
      'conditionally reliable',
    ),
    summarizeField(
      'dependents_count',
      'package_node.dependents_count',
      fields['package_node.dependents_count']?.tier,
      'not populated',
    ),
    summarizeField(
      'has_advisories',
      'package_node.has_advisories',
      fields['package_node.has_advisories']?.tier,
      'placeholder only',
    ),
    'risk_score, risk_level, signals, and recommendation are heuristic outputs, not ground truth',
    '"safe" means below the configured threshold, not verified benign',
    'warnings describe scan-time incompleteness and provenance, not package-behavior truth',
  ]
}

function summarizeField(
  label: string,
  fieldId: string,
  actualTier: string | undefined,
  expectedSummary: string,
): string {
  if (actualTier === undefined) {
    return `${label}: policy missing for ${fieldId}`
  }

  return `${label}: ${expectedSummary}`
}
