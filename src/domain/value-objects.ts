import type { PackageSpec, ResolvedPackage } from './contracts.js'
import type { Recommendation, RiskLevel } from './entities.js'
import { InvalidUsageError } from './errors.js'

export const DEFAULT_MAX_DEPTH = 3
export const DEFAULT_THRESHOLD = 0.4

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
