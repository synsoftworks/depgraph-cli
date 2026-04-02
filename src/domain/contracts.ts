import type {
  PackageNode,
  Recommendation,
  ReviewOutcome,
  ReviewSource,
  RiskLevel,
  RiskSignal,
  ScanFinding,
} from './entities.js'

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

export interface DependencyGraphEdge {
  from: string
  to: string
  child_depth: number
}

export interface NewDependencyEdgeFinding {
  parent_key: string
  child_key: string
  path: string[]
  depth: number
  edge_type: 'direct' | 'transitive'
}

export interface ScanReviewRecord {
  record_id: string
  created_at: string
  package: ResolvedPackage
  package_key: string
  scan_target: string
  baseline_key: string
  baseline_record_id: string | null
  requested_depth: number
  threshold: number
  raw_score: number
  risk_level: RiskLevel
  signals: RiskSignal[]
  findings: ScanFinding[]
  root: PackageNode
  total_scanned: number
  suspicious_count: number
  safe_count: number
  scan_duration_ms: number
  dependency_edges: DependencyGraphEdge[]
  new_dependency_edge_findings: NewDependencyEdgeFinding[]
}

export interface ReviewScanRequest {
  record_id: string
  outcome: ReviewOutcome
  notes: string | null
  review_source: ReviewSource
  confidence: number | null
}

export interface ReviewEvent {
  event_id: string
  record_id: string
  package_key: string
  created_at: string
  outcome: ReviewOutcome
  notes: string | null
  resolution_timestamp: string | null
  review_source: ReviewSource
  confidence: number | null
}

export interface SignalFrequency {
  type: string
  count: number
}

export interface EvaluationSummary {
  total_scans: number
  labeled_records: number
  malicious_count: number
  benign_count: number
  needs_review_count: number
  signal_frequency: SignalFrequency[]
}
