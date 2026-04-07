/**
 * Responsibilities:
 * - Project scan results into presentation-oriented summary and finding views.
 * - Normalize user-facing reason text from existing scan signals.
 *
 * Non-responsibilities:
 * - Do not recompute scores, signals, thresholds, or policy decisions.
 * - Do not render terminal, TUI, or JSON output directly.
 */
import type { EdgeFinding } from '../domain/contracts.js'
import type { RiskSignal, ScanFinding, ScanResult } from '../domain/entities.js'

const SECURITY_SIGNAL_TYPES = new Set([
  'security_tombstone',
  'security_deprecation_language',
])

const SECURITY_MESSAGE_PATTERN = /\b(?:security|vulnerab(?:ility|ilities)|cve-\d{4}-\d+)\b/i
const CVE_PATTERN = /\bCVE-\d{4}-\d+\b/i

export interface ScanSummaryBlock {
  packages_requiring_review: number
  security_related_findings: number
  packages_appearing_safe: number
}

export interface CompactScanSummary {
  scanned_package: string
  overall_risk_level: ScanResult['overall_risk_level']
  overall_risk_score: number
  packages_requiring_review: number
  security_related_findings: number
  packages_appearing_safe: number
}

/**
 * Builds the standard scan summary counts used by human-facing renderers.
 *
 * @param result Completed scan result with precomputed counts and findings.
 * @returns Stable count totals derived from the existing scan result.
 */
export function buildScanSummary(result: ScanResult): ScanSummaryBlock {
  return {
    packages_requiring_review: result.suspicious_count,
    security_related_findings: result.findings.filter(isSecurityRelatedFinding).length,
    packages_appearing_safe: result.safe_count,
  }
}

/**
 * Builds the compact scan summary projection for minimal output modes.
 *
 * @param result Completed scan result with precomputed overall risk and counts.
 * @returns Compact summary data ready for renderer formatting.
 */
export function buildCompactScanSummary(result: ScanResult): CompactScanSummary {
  const summary = buildScanSummary(result)

  return {
    scanned_package: result.root.key,
    overall_risk_level: result.overall_risk_level,
    overall_risk_score: result.overall_risk_score,
    packages_requiring_review: summary.packages_requiring_review,
    security_related_findings: summary.security_related_findings,
    packages_appearing_safe: summary.packages_appearing_safe,
  }
}

/**
 * Splits findings into priority and routine buckets for stable presentation order.
 *
 * @param findings Findings already produced by scan logic.
 * @returns Findings partitioned by whether they carry security-related signals.
 */
export function partitionFindings(findings: ScanFinding[]): {
  priority: ScanFinding[]
  routine: ScanFinding[]
} {
  const priority: ScanFinding[] = []
  const routine: ScanFinding[] = []

  for (const finding of findings) {
    if (isSecurityRelatedFinding(finding)) {
      priority.push(finding)
    } else {
      routine.push(finding)
    }
  }

  return { priority, routine }
}

/**
 * Collapses raw finding signals into concise user-facing reasons.
 *
 * @param finding Finding explanation inputs from the scan result.
 * @returns Deduplicated reason strings suitable for plain-text rendering.
 */
export function formatFindingReasons(finding: Pick<ScanFinding, 'signals' | 'explanation'>): string[] {
  const reasons: string[] = []
  const handledTypes = new Set<string>()
  const deprecatedSignal = finding.signals.find((signal) => signal.type === 'deprecated_package')
  const securityDeprecationSignal = finding.signals.find(
    (signal) => signal.type === 'security_deprecation_language',
  )

  if (finding.signals.some((signal) => signal.type === 'security_tombstone')) {
    reasons.push('registry marks this as a security placeholder package for a previously malicious package')
    handledTypes.add('security_tombstone')
  }

  // Merge paired deprecation signals into one reason so presentation does not leak signal decomposition.
  if (deprecatedSignal !== undefined && securityDeprecationSignal !== undefined) {
    reasons.push(formatSecurityDeprecationReason(deprecatedSignal))
    handledTypes.add('deprecated_package')
    handledTypes.add('security_deprecation_language')
  } else if (deprecatedSignal !== undefined) {
    reasons.push(formatDeprecatedReason(deprecatedSignal))
    handledTypes.add('deprecated_package')
  } else if (securityDeprecationSignal !== undefined) {
    reasons.push(formatSecurityDeprecationReason(securityDeprecationSignal))
    handledTypes.add('security_deprecation_language')
  }

  if (finding.signals.some((signal) => signal.type === 'new_and_unproven')) {
    reasons.push('new package with minimal version history and no observed adoption')
    handledTypes.add('new_and_unproven')
    handledTypes.add('new_package_age')
    handledTypes.add('low_version_history')
    handledTypes.add('low_weekly_downloads')
    handledTypes.add('zero_downloads')
  } else {
    const ageSignal = finding.signals.find((signal) => signal.type === 'new_package_age')
    if (ageSignal !== undefined) {
      reasons.push(formatPublishedAgeReason(ageSignal))
      handledTypes.add('new_package_age')
    }

    const versionSignal = finding.signals.find((signal) => signal.type === 'low_version_history')
    if (versionSignal !== undefined) {
      reasons.push(formatVersionHistoryReason(versionSignal))
      handledTypes.add('low_version_history')
    }

    const zeroDownloadsSignal = finding.signals.find((signal) => signal.type === 'zero_downloads')
    if (zeroDownloadsSignal !== undefined) {
      reasons.push('no observed weekly downloads')
      handledTypes.add('zero_downloads')
      handledTypes.add('low_weekly_downloads')
    } else {
      const downloadSignal = finding.signals.find((signal) => signal.type === 'low_weekly_downloads')
      if (downloadSignal !== undefined) {
        reasons.push(formatDownloadReason(downloadSignal))
        handledTypes.add('low_weekly_downloads')
      }
    }
  }

  const churnSignal = finding.signals.find((signal) => signal.type === 'rapid_publish_churn')
  if (churnSignal !== undefined) {
    reasons.push(formatPublishChurnReason(churnSignal))
    handledTypes.add('rapid_publish_churn')
  }

  const dependencySurfaceSignal = finding.signals.find(
    (signal) => signal.type === 'large_dependency_surface',
  )
  if (dependencySurfaceSignal !== undefined) {
    reasons.push(formatDependencySurfaceReason(dependencySurfaceSignal))
    handledTypes.add('large_dependency_surface')
  }

  if (finding.signals.some((signal) => signal.type === 'unresolved_registry_lookup')) {
    reasons.push('registry metadata could not be resolved')
    handledTypes.add('unresolved_registry_lookup')
  }

  if (finding.signals.some((signal) => signal.type === 'new_direct_dependency_edge')) {
    reasons.push('new direct dependency introduced since the previous scan')
    handledTypes.add('new_direct_dependency_edge')
  }

  if (finding.signals.some((signal) => signal.type === 'new_transitive_dependency_edge')) {
    reasons.push('new transitive dependency introduced since the previous scan')
    handledTypes.add('new_transitive_dependency_edge')
  }

  for (const signal of finding.signals) {
    if (handledTypes.has(signal.type)) {
      continue
    }

    const fallbackReason = normalizeReason(signal.reason)
    if (fallbackReason.length > 0) {
      reasons.push(fallbackReason)
    }
  }

  if (reasons.length === 0) {
    const explanation = normalizeReason(finding.explanation)
    if (explanation.length > 0) {
      reasons.push(explanation)
    }
  }

  return deduplicate(reasons)
}

/**
 * Formats a user-facing explanation for an edge finding.
 *
 * @param edgeFinding Newly introduced dependency edge finding.
 * @returns Stable explanation text without internal diff terminology.
 */
export function formatEdgeFindingReason(edgeFinding: EdgeFinding): string {
  return `new ${edgeFinding.edge_type} dependency in the current dependency tree compared with the previous scan`
}

/**
 * Determines whether a finding should be treated as security-related in presentation.
 *
 * @param finding Finding with its existing signal set.
 * @returns `true` when the finding should be surfaced as security-related.
 */
export function isSecurityRelatedFinding(finding: Pick<ScanFinding, 'signals'>): boolean {
  return finding.signals.some(isSecurityRelatedSignal)
}

function isSecurityRelatedSignal(signal: RiskSignal): boolean {
  if (SECURITY_SIGNAL_TYPES.has(signal.type)) {
    return true
  }

  if (signal.type !== 'deprecated_package') {
    return false
  }

  // Older records may only retain a generic deprecation signal, so the message text is the fallback signal.
  const value = typeof signal.value === 'string' ? signal.value : signal.reason
  return SECURITY_MESSAGE_PATTERN.test(value)
}

function formatSecurityDeprecationReason(signal: RiskSignal): string {
  const message = extractSignalText(signal)
  const cve = message.match(CVE_PATTERN)?.[0]?.toUpperCase()

  if (cve !== undefined) {
    return `deprecated due to a security vulnerability (${cve} referenced)`
  }

  return 'deprecated due to a security-related warning in the deprecation message'
}

function formatDeprecatedReason(signal: RiskSignal): string {
  const message = extractSignalText(signal)

  if (message.length === 0) {
    return 'package is deprecated'
  }

  return `package is deprecated: ${message}`
}

function formatPublishedAgeReason(signal: RiskSignal): string {
  const days = typeof signal.value === 'number' ? signal.value : null

  if (days === null) {
    return normalizeReason(signal.reason)
  }

  if (days === 0) {
    return 'published today'
  }

  if (days === 1) {
    return 'published 1 day ago'
  }

  return `published ${days.toLocaleString()} days ago`
}

function formatVersionHistoryReason(signal: RiskSignal): string {
  const total = typeof signal.value === 'number' ? signal.value : null

  if (total === null) {
    return normalizeReason(signal.reason)
  }

  return `only ${total.toLocaleString()} published version${total === 1 ? '' : 's'}`
}

function formatDownloadReason(signal: RiskSignal): string {
  const downloads = typeof signal.value === 'number' ? signal.value : null

  if (downloads === null) {
    return normalizeReason(signal.reason)
  }

  return `low ecosystem adoption (${downloads.toLocaleString()} weekly downloads)`
}

function formatPublishChurnReason(signal: RiskSignal): string {
  const publishes = typeof signal.value === 'number' ? signal.value : null

  if (publishes === null) {
    return normalizeReason(signal.reason)
  }

  return `${publishes.toLocaleString()} releases published in the last 30 days`
}

function formatDependencySurfaceReason(signal: RiskSignal): string {
  const dependencies = typeof signal.value === 'number' ? signal.value : null

  if (dependencies === null) {
    return normalizeReason(signal.reason)
  }

  return `large dependency surface (${dependencies.toLocaleString()} direct dependencies)`
}

function extractSignalText(signal: RiskSignal): string {
  const value = typeof signal.value === 'string' ? signal.value : ''

  if (value.length > 0) {
    return normalizeReason(stripDeprecationPrefix(value))
  }

  return normalizeReason(stripDeprecationPrefix(signal.reason))
}

function stripDeprecationPrefix(text: string): string {
  return text.replace(/^package is deprecated:\s*/i, '')
}

function normalizeReason(text: string): string {
  return text.replaceAll(/\s+/g, ' ').trim()
}

function deduplicate(values: string[]): string[] {
  return Array.from(new Set(values))
}
