import type { PackageMetadata, RiskAssessment } from '../domain/contracts.js'
import type { RiskSignal, RiskSignalWeight } from '../domain/entities.js'
import type { RiskScorer, RiskScorerContext } from '../domain/ports.js'
import {
  calculateAgeDays,
  hasSecurityDeprecationLanguage,
  recommendationForRiskLevel,
  riskScoreForSignals,
  riskLevelForScore,
} from '../domain/value-objects.js'

const MATURE_PACKAGE_VERSION_THRESHOLD = 100
const MATURE_PACKAGE_DOWNLOAD_THRESHOLD = 100_000

export class HeuristicRiskScorer implements RiskScorer {
  constructor(private readonly now: () => Date = () => new Date()) {}

  assessPackage(metadata: PackageMetadata, context: RiskScorerContext): RiskAssessment {
    const signals: RiskSignal[] = []
    const ageDays = calculateAgeDays(metadata.published_at, this.now())
    const dependencyCount = context.dependency_count

    if (ageDays <= 7) {
      if (isFreshReleaseOnMaturePackage(metadata)) {
        // Mature packages still get a freshness signal, but strong adoption and long version history dampen the default suspicion.
        signals.push({
          type: 'fresh_release_on_mature_package',
          value: ageDays,
          weight: 'low',
          reason: `package was published ${ageDays} day(s) ago on a mature, high-traffic package`,
        })
      } else {
        signals.push({
          type: 'new_package_age',
          value: ageDays,
          weight: 'high',
          reason: `package was published ${ageDays} day(s) ago`,
        })
      }
    }

    if (metadata.total_versions <= 2) {
      signals.push({
        type: 'low_version_history',
        value: metadata.total_versions,
        weight: 'medium',
        reason: `package has only ${metadata.total_versions} published version(s)`,
      })
    }

    if (metadata.weekly_downloads !== null && metadata.weekly_downloads < 1_000) {
      signals.push({
        type: 'low_weekly_downloads',
        value: metadata.weekly_downloads,
        weight: 'high',
        reason: `package has only ${metadata.weekly_downloads} weekly download(s)`,
      })
    }

    if (metadata.weekly_downloads === 0) {
      signals.push({
        type: 'zero_downloads',
        value: 0,
        weight: 'high',
        reason: 'package has never been downloaded — no ecosystem adoption',
      })
    }

    if (metadata.is_security_tombstone) {
      signals.push({
        type: 'security_tombstone',
        value: metadata.package.version,
        weight: 'critical',
        reason:
          metadata.deprecated_message ??
          'package is an npm security placeholder or tombstone for a previously malicious package',
      })
    } else if (metadata.deprecated_message !== null) {
      signals.push({
        type: 'deprecated_package',
        value: metadata.deprecated_message,
        weight: 'medium',
        reason: `package is deprecated: ${metadata.deprecated_message}`,
      })
    }

    if (hasSecurityDeprecationLanguage(metadata.deprecated_message)) {
      signals.push({
        type: 'security_deprecation_language',
        value: metadata.deprecated_message,
        weight: 'high',
        reason: 'deprecation message contains security-related language',
      })
    }

    if (metadata.publish_events_last_30_days >= 3) {
      signals.push({
        type: 'rapid_publish_churn',
        value: metadata.publish_events_last_30_days,
        weight: 'medium',
        reason: `${metadata.publish_events_last_30_days} version publish events happened in the last 30 days`,
      })
    }

    if (dependencyCount >= 25) {
      signals.push({
        type: 'large_dependency_surface',
        value: dependencyCount,
        weight: 'low',
        reason: `package introduces ${dependencyCount} direct dependencies`,
      })
    }

    if (
      ageDays <= 7 &&
      metadata.total_versions <= 2 &&
      metadata.weekly_downloads === 0
    ) {
      signals.push({
        type: 'new_and_unproven',
        value: `${ageDays}:${metadata.total_versions}`,
        weight: 'critical',
        reason:
          'package is new, unversioned, and has zero downloads — matches supply chain injection pattern',
      })
    }

    const calibratedSignals = calibrateFreshnessSignals(signals)
    const riskScore = riskScoreForSignals(calibratedSignals)
    const riskLevel = riskLevelForScore(riskScore)

    return {
      risk_score: riskScore,
      risk_level: riskLevel,
      recommendation: recommendationForRiskLevel(riskLevel),
      signals: calibratedSignals,
    }
  }
}

function isFreshReleaseOnMaturePackage(metadata: PackageMetadata): boolean {
  return (
    metadata.total_versions >= MATURE_PACKAGE_VERSION_THRESHOLD &&
    metadata.weekly_downloads !== null &&
    metadata.weekly_downloads >= MATURE_PACKAGE_DOWNLOAD_THRESHOLD
  )
}

function calibrateFreshnessSignals(signals: RiskSignal[]): RiskSignal[] {
  const hasNewPackageAge = signals.some((signal) => signal.type === 'new_package_age')
  const hasRapidPublishChurn = signals.some((signal) => signal.type === 'rapid_publish_churn')

  if (!hasNewPackageAge || !hasRapidPublishChurn || hasStrongerThanFreshnessConcern(signals)) {
    return signals
  }

  // Freshness and churn stay visible, but this pair alone should not cross review without stronger corroborating evidence.
  return signals.map((signal) =>
    signal.type === 'new_package_age'
      ? {
          ...signal,
          weight: 'medium' satisfies RiskSignalWeight,
        }
      : signal,
  )
}

function hasStrongerThanFreshnessConcern(signals: RiskSignal[]): boolean {
  return signals.some(
    (signal) =>
      ![
        'new_package_age',
        'fresh_release_on_mature_package',
        'rapid_publish_churn',
        'large_dependency_surface',
      ].includes(signal.type),
  )
}
