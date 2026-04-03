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
  // v1 paths follow the current BFS tree projection, not every possible parent path in the underlying DAG.
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
  // Despite the name, v1 stores edges from the current BFS dependency tree projection.
  // Shared packages collapsed by the traverser may have additional real parents that are not represented here.
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
  // Edge findings describe newly introduced projected edges relative to the latest matching baseline scan.
  parent_key: string
  child_key: string
  path: string[]
  depth: number
  edge_type: 'direct' | 'transitive'
  review_target: EdgeFindingReviewTarget
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
  // Projected edges captured from the current v1 traversal model.
  dependency_edges: DependencyGraphEdge[]
  edge_findings: EdgeFinding[]
}

export interface ReviewScanRequest {
  record_id: string
  target_id?: string
  outcome: ReviewOutcome
  notes: string | null
  review_source: ReviewSource
  confidence: number | null
}

export type ReviewTargetKind = 'package_finding' | 'edge_finding'

interface ReviewTargetBase {
  kind: ReviewTargetKind
  record_id: string
  target_id: string
}

export interface PackageFindingReviewTarget extends ReviewTargetBase {
  kind: 'package_finding'
  finding_key: string
  package_key: string
}

export interface EdgeFindingReviewTarget extends ReviewTargetBase {
  kind: 'edge_finding'
  edge_finding_key: string
  parent_key: string
  child_key: string
  edge_type: EdgeFinding['edge_type']
}

export type ReviewTarget = PackageFindingReviewTarget | EdgeFindingReviewTarget

/**
 * Review events are append-only source history.
 * They preserve raw review evidence, but they are not a safe label interface.
 * Any label-aware consumer must derive `ResolvedReviewTargetState` before using them.
 * Canonical labels are not simple latest-wins projections of this history.
 */
export interface ReviewEvent {
  event_id: string
  record_id: string
  review_target: ReviewTarget
  created_at: string
  outcome: ReviewOutcome
  notes: string | null
  resolution_timestamp: string | null
  review_source: ReviewSource
  confidence: number | null
}

export type CanonicalLabel = 'malicious' | 'benign'
export type WorkflowStatus = 'unreviewed' | 'needs_review' | 'resolved'
// Current canonical-label policy: higher-trust sources win; recency only breaks ties within a source tier.
export type CanonicalLabelSource = 'source_precedence_then_latest_within_source'

/**
 * Resolved review state is the label-facing view of review history.
 * Canonical labels are derived from raw review events and must not be stored
 * or treated as mutable source-of-truth state. Label derivation applies
 * review-source precedence first, then recency within the same source tier.
 */
export interface ResolvedReviewTargetState {
  record_id: string
  review_target: ReviewTarget
  latest_review_event: ReviewEvent | null
  canonical_label_event: ReviewEvent | null
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
  total_labeled_targets: number
  malicious_targets: number
  benign_targets: number
  unlabeled_targets: number
  derived_from: CanonicalLabelSource
}

export interface WorkflowStatusSummary {
  unreviewed_targets: number
  needs_review_targets: number
  resolved_targets: number
}

export interface ReviewTargetSummary {
  total_targets: number
  package_finding_targets: number
  edge_finding_targets: number
}

export interface EvaluationSummary {
  total_scans: number
  review_targets: ReviewTargetSummary
  raw_review_events: RawReviewEventSummary
  canonical_labels: CanonicalLabelSummary
  workflow_status: WorkflowStatusSummary
  signal_frequency: SignalFrequency[]
  metadata_coverage: MetadataCoverageSummary
}
