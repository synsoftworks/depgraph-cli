import type {
  DependencyPath,
  EdgeFinding,
  PackageFindingReviewTarget,
  PackageMetadataStatus,
  ScanMode,
  ScanWarning,
} from './contracts.js'

/** Severity band derived from a package risk score. */
export type RiskLevel = 'safe' | 'review' | 'critical'
/** Install guidance derived from a package risk level. */
export type Recommendation = 'install' | 'review' | 'do_not_install'
/** Relative contribution of an individual risk signal. */
export type RiskSignalWeight = 'low' | 'medium' | 'high' | 'critical'
/** Review outcome captured in review history. */
export type ReviewOutcome = 'malicious' | 'benign' | 'needs_review'
/** Origin of a review decision. */
export type ReviewSource = 'human' | 'auto' | 'external'
/** Reliability tier assigned by ADR-012 field policy. */
export type FieldReliabilityTier =
  | 'reliable'
  | 'conditionally_reliable'
  | 'unavailable'
  | 'placeholder'
  | 'heuristic_output'
  | 'structural_only'
  | 'scan_context'

/** Reliability guidance for a single exported field. */
export interface FieldReliabilityEntry {
  tier: FieldReliabilityTier
  guidance: string
  notes?: string[]
}

/** ADR-012 field reliability policy snapshot attached to a scan result. */
export interface FieldReliabilityReport {
  adr: 'ADR-012'
  fields: Record<string, FieldReliabilityEntry>
}

/** One heuristic signal contributing to a package risk assessment. */
export interface RiskSignal {
  type: string
  value: string | number | boolean | null
  weight: RiskSignalWeight
  reason: string
}

/** Materialized dependency node in the rendered scan tree. */
export interface PackageNode {
  name: string
  version: string
  key: string
  depth: number
  // Project-root nodes from package-lock scans are structural roots, not published packages.
  // Package-only metadata fields are therefore nullable on those nodes.
  is_project_root: boolean
  metadata_status: PackageMetadataStatus
  metadata_warning: string | null
  lockfile_resolved_url: string | null
  lockfile_integrity: string | null
  age_days: number | null
  weekly_downloads: number | null
  dependents_count: number | null
  deprecated_message: string | null
  is_security_tombstone: boolean
  published_at: string | null
  first_published: string | null
  last_published: string | null
  total_versions: number | null
  dependency_count: number
  publish_events_last_30_days: number | null
  has_advisories: boolean
  risk_score: number
  risk_level: RiskLevel
  signals: RiskSignal[]
  recommendation: Recommendation
  dependencies: PackageNode[]
}

/** Suspicious package finding surfaced from the scanned dependency view. */
export interface ScanFinding {
  key: string
  name: string
  version: string
  depth: number
  review_target: PackageFindingReviewTarget
  path: DependencyPath
  risk_score: number
  risk_level: RiskLevel
  recommendation: Recommendation
  signals: RiskSignal[]
  explanation: string
}

/** Full application-layer result returned by a completed scan. */
export interface ScanResult {
  record_id: string
  scan_mode: ScanMode
  scan_target: string
  baseline_record_id: string | null
  requested_depth: number
  threshold: number
  field_reliability: FieldReliabilityReport
  root: PackageNode
  edge_findings: EdgeFinding[]
  findings: ScanFinding[]
  total_scanned: number
  suspicious_count: number
  safe_count: number
  overall_risk_score: number
  overall_risk_level: RiskLevel
  warnings: ScanWarning[]
  scan_duration_ms: number
  timestamp: string
}
