import { basename } from 'node:path'

import type { BaselineIdentity, PackageSpec, ResolvedPackage, ScanMode } from './contracts.js'
import type { Recommendation, RiskLevel, RiskSignal } from './entities.js'
import { InvalidUsageError } from './errors.js'

export const DEFAULT_MAX_DEPTH = 3
export const DEFAULT_THRESHOLD = 0.4
export const SECURITY_DEPRECATION_KEYWORDS = ['security', 'vulnerability', 'cve'] as const
export const RISK_SIGNAL_WEIGHTS = {
  low: 0.08,
  medium: 0.16,
  high: 0.32,
  critical: 0.55,
} as const

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

export function normalizeMaxDepth(value: number): number {
  if (!Number.isInteger(value) || value < 0) {
    throw new InvalidUsageError('Depth must be a non-negative integer.')
  }

  return value
}

export function normalizeThreshold(value: number): number {
  if (!Number.isFinite(value) || value < 0 || value > 1) {
    throw new InvalidUsageError('Threshold must be a number between 0 and 1.')
  }

  return Number(value.toFixed(2))
}

export function packageKey(pkg: ResolvedPackage): string {
  return `${pkg.name}@${pkg.version}`
}

export function normalizeScanTarget(input: string): string {
  const parsed = parsePackageSpec(input)

  return parsed.version_range === undefined ? parsed.name : `${parsed.name}@${parsed.version_range}`
}

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

export function baselineKeyForIdentity(identity: BaselineIdentity): string {
  return `${identity.scan_mode}::${identity.scan_target}::depth=${identity.requested_depth}::workspace=${identity.workspace_identity}`
}

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

export function calculateAgeDays(publishedAt: string, now: Date = new Date()): number {
  const publishedTime = new Date(publishedAt).getTime()

  if (Number.isNaN(publishedTime)) {
    return 0
  }

  const diffMs = Math.max(0, now.getTime() - publishedTime)

  return Math.floor(diffMs / 86_400_000)
}

export function riskLevelForScore(score: number): RiskLevel {
  if (score > 0.7) {
    return 'critical'
  }

  if (score >= 0.4) {
    return 'review'
  }

  return 'safe'
}

export function riskScoreForSignals(signals: RiskSignal[]): number {
  const score = Math.min(
    1,
    signals.reduce((total, signal) => total + RISK_SIGNAL_WEIGHTS[signal.weight], 0),
  )

  return Number(score.toFixed(2))
}

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

export function hasSecurityDeprecationLanguage(message: string | null): boolean {
  if (message === null) {
    return false
  }

  const normalizedMessage = message.toLowerCase()

  return SECURITY_DEPRECATION_KEYWORDS.some((keyword) => normalizedMessage.includes(keyword))
}
