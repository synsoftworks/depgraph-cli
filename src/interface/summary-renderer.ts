import type { ScanResult } from '../domain/entities.js'
import { buildCompactScanSummary } from './scan-output-presenter.js'

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
