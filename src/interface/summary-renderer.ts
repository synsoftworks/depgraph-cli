/**
 * Responsibilities:
 * - Render the compact scan summary mode for CI and human log consumption.
 * - Format only high-signal fields already computed by the scan result.
 *
 * Non-responsibilities:
 * - Do not render detailed findings, tree structure, or JSON output.
 * - Do not derive new counts, scores, or policy decisions.
 */
import type { ScanResult } from '../domain/entities.js'
import { buildCompactScanSummary } from './scan-output-presenter.js'

/**
 * Renders the minimal scan summary output for `scan --summary`.
 *
 * @param result Completed scan result.
 * @returns Deterministic compact text containing the root package, overall risk, and key counts.
 */
export function renderSummaryText(result: ScanResult): string {
  const summary = buildCompactScanSummary(result)

  return [
    summary.scanned_package,
    '',
    `${summary.overall_risk_level} (${summary.overall_risk_score.toFixed(2)})`,
    '',
    `- packages requiring review: ${summary.packages_requiring_review}`,
    `- findings with security-related signals: ${summary.security_related_findings}`,
    `- packages that appear safe: ${summary.packages_appearing_safe}`,
  ].join('\n')
}
