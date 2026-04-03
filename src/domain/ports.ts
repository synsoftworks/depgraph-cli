import type {
  BaselineIdentity,
  DependencyPath,
  PackageMetadata,
  PackageSpec,
  RiskAssessment,
  ResolvedReviewTargetState,
  ReviewEvent,
  ScanReviewRecord,
} from './contracts.js'

export interface TraversedPackageNode {
  key: string
  package: PackageMetadata['package']
  metadata: PackageMetadata
  depth: number
  parent_key: string | null
  path: DependencyPath
  is_virtual_root?: boolean
}

export interface TraversedDependencyGraph {
  // v1 traversal returns a breadth-first tree projection keyed by first-seen resolved packages.
  root_key: string
  nodes: TraversedPackageNode[]
}

export interface PackageMetadataSource {
  resolvePackage(spec: PackageSpec): Promise<PackageMetadata>
}

export interface RegistryDependencyTraverser {
  traverse(root: PackageSpec, max_depth: number): Promise<TraversedDependencyGraph>
}

export interface PackageLockDependencyTraverser {
  // v1 package-lock scanning reads resolved dependency structure from package-lock.json itself.
  // It currently supports lockfileVersion 2+ with a packages map.
  traverse(package_lock_path: string, max_depth: number): Promise<TraversedDependencyGraph>
}

export interface RiskScorerContext {
  depth: number
  path: DependencyPath
  dependency_count: number
}

export interface RiskScorer {
  assessPackage(metadata: PackageMetadata, context: RiskScorerContext): RiskAssessment
}

export interface ScanReviewStore {
  appendScanRecord(record: ScanReviewRecord): Promise<void>
  findLatestScanByBaseline(baselineIdentity: BaselineIdentity): Promise<ScanReviewRecord | null>
  findScanRecord(recordId: string): Promise<ScanReviewRecord | null>
  appendReviewEvent(event: ReviewEvent): Promise<void>
  listScanRecords(): Promise<ScanReviewRecord[]>
  listReviewEvents(): Promise<ReviewEvent[]>
}
