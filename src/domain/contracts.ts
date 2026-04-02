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
  workspace_identity?: string
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

export interface BaselineIdentity {
  scan_target: string
  requested_depth: number
  workspace_identity: string
}

export interface EdgeFinding {
  parent_key: string
  child_key: string
  path: string[]
  depth: number
  edge_type: 'direct' | 'transitive'
  baseline_record_id: string | null
  baseline_identity: BaselineIdentity
  reason: string
  recommendation: Recommendation | null
}

export interface ScanReviewRecord {
  record_id: string
  created_at: string
  package: ResolvedPackage
  package_key: string
  scan_target: string
  baseline_identity: BaselineIdentity
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
  edge_findings: EdgeFinding[]
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

export type CanonicalLabel = 'malicious' | 'benign'
export type WorkflowStatus = 'unreviewed' | 'needs_review' | 'resolved'
export type CanonicalLabelSource = 'latest_label_bearing_event'

export interface ResolvedReviewState {
  record_id: string
  latest_review_event: ReviewEvent | null
  latest_label_bearing_event: ReviewEvent | null
  workflow_status: WorkflowStatus
  canonical_label: CanonicalLabel | null
  canonical_label_source: CanonicalLabelSource | null
}

export interface SignalFrequency {
  type: string
  count: number
}

export interface MetadataFieldCoverage {
  total_nodes: number
  missing_count: number
  missing_percent: number
}

export interface CoverageSignalFrequency {
  known: SignalFrequency[]
  missing: SignalFrequency[]
}

export interface MetadataCoverageSummary {
  weekly_downloads: MetadataFieldCoverage
  dependents_count: MetadataFieldCoverage
  signal_frequency_by_weekly_downloads: CoverageSignalFrequency
  signal_frequency_by_dependents_count: CoverageSignalFrequency
}

export interface RawReviewEventSummary {
  total_events: number
  malicious_events: number
  benign_events: number
  needs_review_events: number
}

export interface CanonicalLabelSummary {
  total_labeled_records: number
  malicious_records: number
  benign_records: number
  unlabeled_records: number
  derived_from: CanonicalLabelSource
}

export interface WorkflowStatusSummary {
  unreviewed_records: number
  needs_review_records: number
  resolved_records: number
}

export interface EvaluationSummary {
  total_scans: number
  raw_review_events: RawReviewEventSummary
  canonical_labels: CanonicalLabelSummary
  workflow_status: WorkflowStatusSummary
  signal_frequency: SignalFrequency[]
  metadata_coverage: MetadataCoverageSummary
}
