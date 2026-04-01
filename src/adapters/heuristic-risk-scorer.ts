import type { PackageMetadata, RiskAssessment } from '../domain/contracts.js'
import type { RiskSignal } from '../domain/entities.js'
import type { RiskScorer, RiskScorerContext } from '../domain/ports.js'
import {
  calculateAgeDays,
  recommendationForRiskLevel,
  riskLevelForScore,
} from '../domain/value-objects.js'

const SIGNAL_WEIGHTS = {
  low: 0.08,
  medium: 0.16,
  high: 0.32,
  critical: 0.55,
} as const

export class HeuristicRiskScorer implements RiskScorer {
  constructor(private readonly now: () => Date = () => new Date()) {}

  assessPackage(metadata: PackageMetadata, context: RiskScorerContext): RiskAssessment {
    const signals: RiskSignal[] = []
    const ageDays = calculateAgeDays(metadata.published_at, this.now())
    const dependencyCount = context.dependency_count

    if (ageDays <= 7) {
      signals.push({
        type: 'new_package_age',
        value: ageDays,
        weight: 'high',
        reason: `package was published ${ageDays} day(s) ago`,
      })
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

    if (ageDays <= 7 && metadata.total_versions <= 2 && metadata.weekly_downloads === 0) {
      signals.push({
        type: 'new_and_unproven',
        value: `${ageDays}:${metadata.total_versions}`,
        weight: 'critical',
        reason:
          'package is new, unversioned, and has zero downloads — matches supply chain injection pattern',
      })
    }

    const score = Math.min(
      1,
      signals.reduce((total, signal) => total + SIGNAL_WEIGHTS[signal.weight], 0),
    )
    const riskScore = Number(score.toFixed(2))
    const riskLevel = riskLevelForScore(riskScore)

    return {
      risk_score: riskScore,
      risk_level: riskLevel,
      recommendation: recommendationForRiskLevel(riskLevel),
      signals,
    }
  }
}
