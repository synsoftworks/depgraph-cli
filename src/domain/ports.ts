import type {
  DependencyPath,
  PackageMetadata,
  PackageSpec,
  RiskAssessment,
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
}

export interface TraversedDependencyGraph {
  root_key: string
  nodes: TraversedPackageNode[]
}

export interface PackageMetadataSource {
  resolvePackage(spec: PackageSpec): Promise<PackageMetadata>
}

export interface DependencyTraverser {
  traverse(root: PackageSpec, max_depth: number): Promise<TraversedDependencyGraph>
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
  findLatestScanByBaseline(baselineKey: string): Promise<ScanReviewRecord | null>
  findScanRecord(recordId: string): Promise<ScanReviewRecord | null>
  appendReviewEvent(event: ReviewEvent): Promise<void>
  listScanRecords(): Promise<ScanReviewRecord[]>
  listReviewEvents(): Promise<ReviewEvent[]>
}
