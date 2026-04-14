import { basename } from 'node:path'

import type { BaselineIdentity, PackageSpec, ResolvedPackage, ScanMode } from './contracts.js'
import type { Recommendation, RiskLevel, RiskSignal } from './entities.js'
import { InvalidUsageError } from './errors.js'
import { isSecurityRelatedDeprecation } from './security-deprecation.js'

/** Default maximum dependency depth for scans. */
export const DEFAULT_MAX_DEPTH = 3
/** Default risk threshold for surfacing findings. */
export const DEFAULT_THRESHOLD = 0.4
/** Additive weights used by the default heuristic risk scorer. */
export const RISK_SIGNAL_WEIGHTS = {
  low: 0.08,
  medium: 0.16,
  high: 0.32,
  critical: 0.55,
} as const

/**
 * Parses a package spec into name and optional version range components.
 *
 * @param input Raw user-supplied package spec.
 * @returns Parsed package spec.
 */
export function parsePackageSpec(input: string): PackageSpec {
  const trimmed = input.trim()

  if (trimmed.length === 0) {
    throw new InvalidUsageError('Package spec is required.')
  }

  if (trimmed.startsWith('@')) {
    const slashIndex = trimmed.indexOf('/')

    if (slashIndex <= 1) {
      throw new InvalidUsageError(`Invalid scoped package spec "${input}".`)
    }

    const versionSeparatorIndex = trimmed.indexOf('@', slashIndex + 1)

    if (versionSeparatorIndex === -1) {
      return { name: trimmed }
    }

    const versionRange = trimmed.slice(versionSeparatorIndex + 1)

    if (versionRange.length === 0) {
      throw new InvalidUsageError(`Invalid package version in "${input}".`)
    }

    return {
      name: trimmed.slice(0, versionSeparatorIndex),
      version_range: versionRange,
    }
  }

  const versionSeparatorIndex = trimmed.indexOf('@')

  if (versionSeparatorIndex === -1) {
    return { name: trimmed }
  }

  const name = trimmed.slice(0, versionSeparatorIndex)
  const versionRange = trimmed.slice(versionSeparatorIndex + 1)

  if (name.length === 0 || versionRange.length === 0) {
    throw new InvalidUsageError(`Invalid package spec "${input}".`)
  }

  return {
    name,
    version_range: versionRange,
  }
}

/**
 * Validates and normalizes a requested scan depth.
 *
 * @param value Candidate depth value.
 * @returns Normalized depth.
 */
export function normalizeMaxDepth(value: number): number {
  if (!Number.isInteger(value) || value < 0) {
    throw new InvalidUsageError('Depth must be a non-negative integer.')
  }

  return value
}

/**
 * Validates and normalizes a finding threshold.
 *
 * @param value Candidate threshold value.
 * @returns Threshold rounded to two decimal places.
 */
export function normalizeThreshold(value: number): number {
  if (!Number.isFinite(value) || value < 0 || value > 1) {
    throw new InvalidUsageError('Threshold must be a number between 0 and 1.')
  }

  return Number(value.toFixed(2))
}

/**
 * Formats an exact resolved package into the canonical package key.
 *
 * @param pkg Resolved package identity.
 * @returns Stable package key in `name@version` form.
 */
export function packageKey(pkg: ResolvedPackage): string {
  return `${pkg.name}@${pkg.version}`
}

/**
 * Normalizes a scan target string for baseline identity and persistence.
 *
 * @param input Raw package spec.
 * @returns Canonical scan target string.
 */
export function normalizeScanTarget(input: string): string {
  const parsed = parsePackageSpec(input)

  return parsed.version_range === undefined ? parsed.name : `${parsed.name}@${parsed.version_range}`
}

/**
 * Builds the baseline identity for a completed scan.
 *
 * @param scanMode Structural scan source.
 * @param scanTarget Canonical scan target.
 * @param requestedDepth Requested traversal depth.
 * @param workspaceIdentity Optional workspace identifier.
 * @returns Baseline identity used for history lookup.
 */
export function baselineIdentityForScan(
  scanMode: ScanMode,
  scanTarget: string,
  requestedDepth: number,
  workspaceIdentity = 'local',
): BaselineIdentity {
  return {
    scan_mode: scanMode,
    scan_target: scanTarget,
    requested_depth: requestedDepth,
    workspace_identity: workspaceIdentity.trim().length > 0 ? workspaceIdentity : 'local',
  }
}

/**
 * Formats a baseline identity into its persisted lookup key.
 *
 * @param identity Baseline identity.
 * @returns Stable baseline key string.
 */
export function baselineKeyForIdentity(identity: BaselineIdentity): string {
  return `${identity.scan_mode}::${identity.scan_target}::depth=${identity.requested_depth}::workspace=${identity.workspace_identity}`
}

/**
 * Resolves a project scan target from a project name or filesystem root.
 *
 * @param projectName Optional package name from lockfile or package.json.
 * @param projectRoot Filesystem root for the scanned project.
 * @returns Canonical project scan target.
 */
export function normalizeProjectScanTarget(projectName: string | undefined, projectRoot: string): string {
  const trimmedName = projectName?.trim() ?? ''

  if (trimmedName.length > 0) {
    return trimmedName
  }

  const fallback = basename(projectRoot).trim()

  if (fallback.length > 0) {
    return fallback
  }

  throw new InvalidUsageError('Project scan target could not be resolved from package-lock.json.')
}

/**
 * Parses an exact package key back into a resolved package identity.
 *
 * @param input Package key in `name@version` form.
 * @returns Exact resolved package.
 */
export function parsePackageKey(input: string): ResolvedPackage {
  const parsed = parsePackageSpec(input)

  if (parsed.version_range === undefined) {
    throw new InvalidUsageError('Package key must include an exact version, for example lodash@4.17.21.')
  }

  return {
    name: parsed.name,
    version: parsed.version_range,
  }
}

/**
 * Calculates package age in whole days.
 *
 * @param publishedAt Publish timestamp.
 * @param now Comparison timestamp.
 * @returns Non-negative whole-day age.
 */
export function calculateAgeDays(publishedAt: string, now: Date = new Date()): number {
  const publishedTime = new Date(publishedAt).getTime()

  if (Number.isNaN(publishedTime)) {
    return 0
  }

  const diffMs = Math.max(0, now.getTime() - publishedTime)

  return Math.floor(diffMs / 86_400_000)
}

/**
 * Maps a numeric risk score to a risk level.
 *
 * @param score Score in the range `0..1`.
 * @returns Risk level bucket.
 */
export function riskLevelForScore(score: number): RiskLevel {
  if (score > 0.7) {
    return 'critical'
  }

  if (score >= 0.4) {
    return 'review'
  }

  return 'safe'
}

/**
 * Sums risk-signal weights into a bounded risk score.
 *
 * @param signals Signals contributing to a package assessment.
 * @returns Score rounded to two decimal places.
 */
export function riskScoreForSignals(signals: RiskSignal[]): number {
  const score = Math.min(
    1,
    signals.reduce((total, signal) => total + RISK_SIGNAL_WEIGHTS[signal.weight], 0),
  )

  return Number(score.toFixed(2))
}

/**
 * Maps a risk level to the default install recommendation.
 *
 * @param level Risk level bucket.
 * @returns Recommendation for that level.
 */
export function recommendationForRiskLevel(level: RiskLevel): Recommendation {
  switch (level) {
    case 'critical':
      return 'do_not_install'
    case 'review':
      return 'review'
    default:
      return 'install'
  }
}

/**
 * Checks whether a deprecation message contains security-related language.
 *
 * @param message Deprecation message from registry metadata.
 * @returns `true` when the message should be treated as security-related.
 */
export function hasSecurityDeprecationLanguage(message: string | null): boolean {
  if (message === null) {
    return false
  }

  return isSecurityRelatedDeprecation(message)
}
