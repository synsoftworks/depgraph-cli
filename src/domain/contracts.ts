import type { Recommendation, RiskLevel, RiskSignal } from './entities.js'

export interface PackageSpec {
  name: string
  version_range?: string
}

export interface ResolvedPackage {
  name: string
  version: string
}

export interface DependencyPath {
  packages: ResolvedPackage[]
}

export interface ScanRequest {
  package_spec: string
  max_depth: number
  threshold: number
  verbose: boolean
}

export interface PackageMetadata {
  package: ResolvedPackage
  dependencies: Record<string, string>
  // v1 requires publish timestamps so age- and churn-based signals remain well-defined.
  published_at: string
  first_published_at: string
  last_published_at: string
  total_versions: number
  publish_events_last_30_days: number
  weekly_downloads: number | null
  deprecated_message: string | null
  is_security_tombstone: boolean
  has_advisories: boolean
  dependents_count: number | null
}

export interface RiskAssessment {
  risk_score: number
  risk_level: RiskLevel
  recommendation: Recommendation
  signals: RiskSignal[]
}
