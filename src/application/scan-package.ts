import type {
  BaselineIdentity,
  DependencyGraphEdge,
  EdgeFinding,
  PackageLockScanRequest,
  RiskAssessment,
  ScanWarning,
  ScanMode,
  ScanRequest,
  ScanReviewRecord,
} from '../domain/contracts.js'
import type { PackageNode, RiskSignal, ScanFinding, ScanResult } from '../domain/entities.js'
import { InvalidUsageError } from '../domain/errors.js'
import type {
  PackageLockDependencyTraverser,
  RegistryDependencyTraverser,
  RiskScorer,
  ScanReviewStore,
  TraversedDependencyGraph,
  TraversedPackageNode,
} from '../domain/ports.js'
import {
  baselineIdentityForScan,
  baselineKeyForIdentity,
  calculateAgeDays,
  normalizeMaxDepth,
  normalizeProjectScanTarget,
  normalizeScanTarget,
  normalizeThreshold,
  packageKey,
  parsePackageSpec,
  recommendationForRiskLevel,
  riskLevelForScore,
  riskScoreForSignals,
} from '../domain/value-objects.js'
import {
  createEdgeFindingReviewTarget,
  createPackageFindingReviewTarget,
} from '../domain/review-targets.js'

interface ScanPackageDependencies {
  registryTraverser: RegistryDependencyTraverser
  packageLockTraverser: PackageLockDependencyTraverser
  scorer: RiskScorer
  reviewStore: ScanReviewStore
  now?: () => Date
}

interface DependencyEdgeSnapshot {
  edge: DependencyGraphEdge
  path: string[]
}

type PendingEdgeFinding = Omit<EdgeFinding, 'review_target'>
type PendingScanFinding = Omit<ScanFinding, 'review_target'>

export function createScanPackageUseCase({
  registryTraverser,
  packageLockTraverser,
  scorer,
  reviewStore,
  now = () => new Date(),
}: ScanPackageDependencies) {
  return async function scanPackage(request: ScanRequest): Promise<ScanResult> {
    const startedAt = now()
    const maxDepth = normalizeMaxDepth(request.max_depth)
    const threshold = normalizeThreshold(request.threshold)
    const traversedGraph = await traverseForRequest(
      request,
      maxDepth,
      registryTraverser,
      packageLockTraverser,
    )
    const scanTarget = resolveScanTarget(request, traversedGraph)
    const baselineIdentity = baselineIdentityForScan(
      request.scan_mode,
      scanTarget,
      maxDepth,
      resolveWorkspaceIdentity(request),
    )
    const baselineKey = baselineKeyForIdentity(baselineIdentity)

    if (traversedGraph.root_key.length === 0 || traversedGraph.nodes.length === 0) {
      throw new InvalidUsageError(
        `No dependency structure could be resolved for "${describeScanSource(request)}".`,
      )
    }

    const edgeSnapshots = buildDependencyEdgeSnapshots(traversedGraph)
    const dependencyEdges = edgeSnapshots.map((snapshot) => snapshot.edge)
    const previousRecord = await findPreviousRecord(reviewStore, baselineIdentity)
    const pendingEdgeFindings = buildEdgeFindings(previousRecord, edgeSnapshots, baselineIdentity)
    const deltaSignals = buildDeltaSignals(pendingEdgeFindings)
    const nodeMap = new Map<string, PackageNode>()
    const pendingFindings: PendingScanFinding[] = []
    const warnings: ScanWarning[] = []
    let overallRiskScore = 0

    for (const traversedNode of traversedGraph.nodes) {
      let assessment = assessTraversedNode(traversedNode, scorer)

      if (traversedNode.key === traversedGraph.root_key && deltaSignals.length > 0) {
        assessment = mergeRiskSignals(assessment, deltaSignals)
      }

      const packageNode = toPackageNode(traversedNode, assessment, startedAt)

      if (metadataStatusForNode(traversedNode) === 'unresolved_registry_lookup') {
        warnings.push({
          kind: 'unresolved_registry_lookup',
          package_key: traversedNode.key,
          package_name: traversedNode.package.name,
          package_version: traversedNode.package.version,
          message:
            traversedNode.metadata_warning ??
            `Registry metadata for ${traversedNode.key} could not be resolved.`,
          lockfile_resolved_url: traversedNode.lockfile_resolved_url ?? null,
          lockfile_integrity: traversedNode.lockfile_integrity ?? null,
        })
      }

      nodeMap.set(traversedNode.key, packageNode)
      overallRiskScore = Math.max(overallRiskScore, assessment.risk_score)

      if (assessment.risk_score >= threshold) {
        pendingFindings.push({
          key: traversedNode.key,
          name: traversedNode.package.name,
          version: traversedNode.package.version,
          depth: traversedNode.depth,
          path: traversedNode.path,
          risk_score: assessment.risk_score,
          risk_level: assessment.risk_level,
          recommendation: assessment.recommendation,
          signals: assessment.signals,
          explanation: buildExplanation(assessment.signals),
        })
      }
    }

    for (const traversedNode of traversedGraph.nodes) {
      if (traversedNode.parent_key === null) {
        continue
      }

      const parentNode = nodeMap.get(traversedNode.parent_key)
      const childNode = nodeMap.get(traversedNode.key)

      if (parentNode !== undefined && childNode !== undefined) {
        parentNode.dependencies.push(childNode)
      }
    }

    const completedAt = now()
    const rootNode = nodeMap.get(traversedGraph.root_key)!
    const recordId = `${completedAt.toISOString()}:${packageKey({
      name: rootNode.name,
      version: rootNode.version,
    })}:depth=${maxDepth}`
    const findings = pendingFindings
      .map((finding) => ({
        ...finding,
        review_target: createPackageFindingReviewTarget(recordId, finding.key),
      }))
      .sort(compareFindings)
    const edgeFindings = pendingEdgeFindings.map((edgeFinding) => ({
      ...edgeFinding,
      review_target: createEdgeFindingReviewTarget(
        recordId,
        edgeFinding.parent_key,
        edgeFinding.child_key,
        edgeFinding.edge_type,
      ),
    }))
    const result: ScanResult = {
      record_id: recordId,
      scan_mode: request.scan_mode,
      scan_target: scanTarget,
      baseline_record_id: previousRecord?.record_id ?? null,
      requested_depth: maxDepth,
      threshold,
      root: rootNode,
      edge_findings: edgeFindings,
      findings,
      total_scanned: traversedGraph.nodes.length,
      suspicious_count: findings.length,
      safe_count: traversedGraph.nodes.length - findings.length,
      overall_risk_score: Number(overallRiskScore.toFixed(2)),
      overall_risk_level: riskLevelForScore(overallRiskScore),
      warnings,
      scan_duration_ms: Math.max(0, completedAt.getTime() - startedAt.getTime()),
      timestamp: completedAt.toISOString(),
    }

    await reviewStore.appendScanRecord(
      buildScanReviewRecord({
        result,
        baselineIdentity,
        dependencyEdges,
        baselineKey,
        baselineRecordId: previousRecord?.record_id ?? null,
        edgeFindings,
      }),
    )

    return result
  }
}

async function traverseForRequest(
  request: ScanRequest,
  maxDepth: number,
  registryTraverser: RegistryDependencyTraverser,
  packageLockTraverser: PackageLockDependencyTraverser,
): Promise<TraversedDependencyGraph> {
  switch (request.scan_mode) {
    case 'registry_package':
      return registryTraverser.traverse(parsePackageSpec(request.package_spec), maxDepth)
    case 'package_lock':
      return packageLockTraverser.traverse(request.package_lock_path, maxDepth)
  }
}

function resolveScanTarget(request: ScanRequest, traversedGraph: TraversedDependencyGraph): string {
  switch (request.scan_mode) {
    case 'registry_package':
      return normalizeScanTarget(request.package_spec)
    case 'package_lock':
      return normalizeProjectScanTarget(
        traversedGraph.nodes[0]?.package.name,
        request.project_root,
      )
  }
}

function resolveWorkspaceIdentity(request: ScanRequest): string | undefined {
  return request.workspace_identity ?? (request.scan_mode === 'package_lock' ? request.project_root : undefined)
}

function describeScanSource(request: ScanRequest): string {
  switch (request.scan_mode) {
    case 'registry_package':
      return request.package_spec
    case 'package_lock':
      return request.package_lock_path
  }
}

function assessTraversedNode(
  traversedNode: TraversedPackageNode,
  scorer: RiskScorer,
): RiskAssessment {
  if (traversedNode.is_virtual_root === true) {
    return {
      risk_score: 0,
      risk_level: 'safe',
      recommendation: 'install',
      signals: [],
    }
  }

  if (traversedNode.metadata === null) {
    const signals: RiskSignal[] = [
      {
        type: 'unresolved_registry_lookup',
        value: traversedNode.key,
        weight: 'low',
        reason:
          traversedNode.metadata_warning ??
          `registry metadata for ${traversedNode.key} could not be resolved; dependency is being evaluated with incomplete evidence`,
      },
    ]
    const riskScore = riskScoreForSignals(signals)
    const riskLevel = riskLevelForScore(riskScore)

    return {
      risk_score: riskScore,
      risk_level: riskLevel,
      recommendation: recommendationForRiskLevel(riskLevel),
      signals,
    }
  }

  return scorer.assessPackage(traversedNode.metadata, {
    depth: traversedNode.depth,
    path: traversedNode.path,
    dependency_count: Object.keys(resolvedDependenciesForNode(traversedNode)).length,
  })
}

function buildExplanation(signals: PackageNode['signals']): string {
  if (signals.length === 0) {
    return 'No suspicious signals exceeded the configured threshold.'
  }

  return signals.map((signal) => signal.reason).join('; ')
}

function toPackageNode(
  traversedNode: TraversedPackageNode,
  assessment: RiskAssessment,
  startedAt: Date,
): PackageNode {
  const isProjectRoot = traversedNode.is_virtual_root === true

  return {
    name: traversedNode.package.name,
    version: traversedNode.package.version,
    key: traversedNode.key,
    depth: traversedNode.depth,
    is_project_root: isProjectRoot,
    metadata_status: metadataStatusForNode(traversedNode),
    metadata_warning: traversedNode.metadata_warning ?? null,
    lockfile_resolved_url: traversedNode.lockfile_resolved_url ?? null,
    lockfile_integrity: traversedNode.lockfile_integrity ?? null,
    age_days:
      isProjectRoot || traversedNode.metadata === null
        ? null
        : calculateAgeDays(traversedNode.metadata.published_at, startedAt),
    weekly_downloads:
      isProjectRoot || traversedNode.metadata === null ? null : traversedNode.metadata.weekly_downloads,
    dependents_count:
      isProjectRoot || traversedNode.metadata === null ? null : traversedNode.metadata.dependents_count,
    deprecated_message:
      isProjectRoot || traversedNode.metadata === null ? null : traversedNode.metadata.deprecated_message,
    is_security_tombstone:
      isProjectRoot || traversedNode.metadata === null ? false : traversedNode.metadata.is_security_tombstone,
    published_at:
      isProjectRoot || traversedNode.metadata === null ? null : traversedNode.metadata.published_at,
    first_published:
      isProjectRoot || traversedNode.metadata === null ? null : traversedNode.metadata.first_published_at,
    last_published:
      isProjectRoot || traversedNode.metadata === null ? null : traversedNode.metadata.last_published_at,
    total_versions:
      isProjectRoot || traversedNode.metadata === null ? null : traversedNode.metadata.total_versions,
    dependency_count: Object.keys(resolvedDependenciesForNode(traversedNode)).length,
    publish_events_last_30_days: isProjectRoot
      || traversedNode.metadata === null
      ? null
      : traversedNode.metadata.publish_events_last_30_days,
    has_advisories:
      isProjectRoot || traversedNode.metadata === null ? false : traversedNode.metadata.has_advisories,
    risk_score: assessment.risk_score,
    risk_level: assessment.risk_level,
    signals: assessment.signals,
    recommendation: assessment.recommendation,
    dependencies: [],
  }
}

function compareFindings(left: PendingScanFinding, right: PendingScanFinding): number {
  if (left.depth !== right.depth) {
    return left.depth - right.depth
  }

  if (left.risk_score !== right.risk_score) {
    return right.risk_score - left.risk_score
  }

  return left.key.localeCompare(right.key)
}

async function findPreviousRecord(
  reviewStore: ScanReviewStore,
  baselineIdentity: BaselineIdentity,
): Promise<ScanReviewRecord | null> {
  try {
    return await reviewStore.findLatestScanByBaseline(baselineIdentity)
  } catch {
    return null
  }
}

function mergeRiskSignals(assessment: RiskAssessment, extraSignals: PackageNode['signals']): RiskAssessment {
  const signals = [...assessment.signals, ...extraSignals]
  const riskScore = riskScoreForSignals(signals)
  const riskLevel = riskLevelForScore(riskScore)

  return {
    risk_score: riskScore,
    risk_level: riskLevel,
    recommendation: recommendationForRiskLevel(riskLevel),
    signals,
  }
}

function buildDependencyEdgeSnapshots(graph: TraversedDependencyGraph): DependencyEdgeSnapshot[] {
  // These snapshots come from the current BFS tree projection, not a full preserved dependency DAG.
  const snapshots = graph.nodes
    .filter((node) => node.parent_key !== null)
    .map((node) => ({
      edge: {
        from: node.parent_key!,
        to: node.key,
        child_depth: node.depth,
      },
      path: node.path.packages.map((pkg) => packageKey(pkg)),
    }))

  snapshots.sort((left, right) => {
    if (left.edge.child_depth !== right.edge.child_depth) {
      return left.edge.child_depth - right.edge.child_depth
    }

    if (left.edge.from !== right.edge.from) {
      return left.edge.from.localeCompare(right.edge.from)
    }

    return left.edge.to.localeCompare(right.edge.to)
  })

  return snapshots
}

function buildEdgeFindings(
  previousRecord: ScanReviewRecord | null,
  currentEdges: DependencyEdgeSnapshot[],
  baselineIdentity: BaselineIdentity,
): PendingEdgeFinding[] {
  // Baseline diffing compares projected edges from matching scans under the current v1 traversal model.
  if (previousRecord === null) {
    return []
  }

  const previousEdgeIds = new Set(previousRecord.dependency_edges.map((edge) => formatEdgeId(edge)))

  return currentEdges
    .filter((snapshot) => !previousEdgeIds.has(formatEdgeId(snapshot.edge)))
    .map((snapshot) => ({
      parent_key: snapshot.edge.from,
      child_key: snapshot.edge.to,
      path: snapshot.path,
      depth: snapshot.edge.child_depth,
      edge_type: snapshot.edge.child_depth === 1 ? 'direct' : 'transitive',
      baseline_record_id: previousRecord.record_id,
      baseline_identity: baselineIdentity,
      reason: `new ${snapshot.edge.child_depth === 1 ? 'direct' : 'transitive'} dependency edge ${snapshot.edge.from} -> ${snapshot.edge.to} via ${snapshot.path.join(' > ')} compared with baseline ${previousRecord.created_at}`,
      recommendation: 'review',
    }))
}

function buildDeltaSignals(
  edgeFindings: PendingEdgeFinding[],
): RiskSignal[] {
  return edgeFindings.map((finding) => ({
    type: finding.edge_type === 'direct' ? 'new_direct_dependency_edge' : 'new_transitive_dependency_edge',
    value: `${finding.parent_key}->${finding.child_key}`,
    weight: finding.edge_type === 'direct' ? 'high' : 'medium',
    reason: finding.reason,
  }))
}

function formatEdgeId(edge: DependencyGraphEdge): string {
  return `${edge.from}->${edge.to}`
}

function buildScanReviewRecord({
  result,
  baselineIdentity,
  dependencyEdges,
  baselineKey,
  baselineRecordId,
  edgeFindings,
}: {
  result: ScanResult
  baselineIdentity: BaselineIdentity
  dependencyEdges: DependencyGraphEdge[]
  baselineKey: string
  baselineRecordId: string | null
  edgeFindings: EdgeFinding[]
}): ScanReviewRecord {
  const pkg = {
    name: result.root.name,
    version: result.root.version,
  }

  return {
    record_id: result.record_id,
    created_at: result.timestamp,
    scan_mode: result.scan_mode,
    package: pkg,
    package_key: packageKey(pkg),
    scan_target: result.scan_target,
    baseline_identity: baselineIdentity,
    baseline_key: baselineKey,
    baseline_record_id: baselineRecordId,
    requested_depth: result.requested_depth,
    threshold: result.threshold,
    raw_score: result.overall_risk_score,
    risk_level: result.overall_risk_level,
    signals: result.root.signals,
    findings: result.findings,
    root: result.root,
    total_scanned: result.total_scanned,
    suspicious_count: result.suspicious_count,
    safe_count: result.safe_count,
    warnings: result.warnings,
    scan_duration_ms: result.scan_duration_ms,
    dependency_edges: dependencyEdges,
    edge_findings: edgeFindings,
  }
}

function metadataStatusForNode(traversedNode: TraversedPackageNode): PackageNode['metadata_status'] {
  if (traversedNode.metadata_status !== undefined) {
    return traversedNode.metadata_status
  }

  if (traversedNode.is_virtual_root === true) {
    return 'synthetic_project_root'
  }

  if (traversedNode.metadata === null) {
    return 'unresolved_registry_lookup'
  }

  return 'enriched'
}

function resolvedDependenciesForNode(traversedNode: TraversedPackageNode): Record<string, string> {
  return traversedNode.resolved_dependencies ?? traversedNode.metadata?.dependencies ?? {}
}

export function isSuspiciousExitCode(result: ScanResult): number {
  return result.suspicious_count > 0 ? 1 : 0
}

export function getRootKey(result: ScanResult): string {
  return packageKey({
    name: result.root.name,
    version: result.root.version,
  })
}
