import type {
  BaselineIdentity,
  DependencyPath,
  PackageMetadata,
  PackageMetadataStatus,
  PackageSpec,
  RiskAssessment,
  ResolvedReviewTargetState,
  ReviewEvent,
  ScanReviewRecord,
} from './contracts.js'

/** Traversed package node emitted by dependency adapters before application projection. */
export interface TraversedPackageNode {
  key: string
  package: PackageMetadata['package']
  metadata: PackageMetadata | null
  resolved_dependencies?: Record<string, string>
  metadata_status?: PackageMetadataStatus
  metadata_warning?: string | null
  lockfile_resolved_url?: string | null
  lockfile_integrity?: string | null
  depth: number
  parent_key: string | null
  path: DependencyPath
  is_virtual_root?: boolean
}

/** Traversed dependency structure produced by a dependency adapter. */
export interface TraversedDependencyGraph {
  // v1 traversal returns a breadth-first tree projection keyed by first-seen resolved packages.
  root_key: string
  nodes: TraversedPackageNode[]
}

/** Port for resolving registry metadata for an exact package. */
export interface PackageMetadataSource {
  resolvePackage(spec: PackageSpec): Promise<PackageMetadata>
}

/** Port for registry-backed dependency traversal. */
export interface RegistryDependencyTraverser {
  traverse(root: PackageSpec, max_depth: number): Promise<TraversedDependencyGraph>
}

/** Port for package-lock-based dependency traversal. */
export interface PackageLockDependencyTraverser {
  // v1 package-lock scanning reads resolved dependency structure from package-lock.json itself.
  // It currently supports lockfileVersion 2+ with a packages map.
  traverse(package_lock_path: string, max_depth: number): Promise<TraversedDependencyGraph>
}

/** Port for pnpm-lock-based dependency traversal. */
export interface PnpmLockDependencyTraverser {
  // v1 pnpm scanning reads resolved dependency structure from pnpm-lock.yaml itself.
  // It currently supports importer-scoped project scans backed by a packages snapshot map.
  traverse(pnpm_lock_path: string, project_root: string, max_depth: number): Promise<TraversedDependencyGraph>
}

/** Context available to the risk scorer for a traversed package. */
export interface RiskScorerContext {
  depth: number
  path: DependencyPath
  dependency_count: number
}

/** Port for heuristic package risk scoring. */
export interface RiskScorer {
  assessPackage(metadata: PackageMetadata, context: RiskScorerContext): RiskAssessment
}

/** Persistence port for scan history and review events. */
export interface ScanReviewStore {
  appendScanRecord(record: ScanReviewRecord): Promise<void>
  findLatestScanByBaseline(baselineIdentity: BaselineIdentity): Promise<ScanReviewRecord | null>
  findScanRecord(recordId: string): Promise<ScanReviewRecord | null>
  appendReviewEvent(event: ReviewEvent): Promise<void>
  listScanRecords(): Promise<ScanReviewRecord[]>
  listReviewEvents(): Promise<ReviewEvent[]>
}
