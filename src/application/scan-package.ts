import type {
  DependencyGraphEdge,
  NewDependencyEdgeFinding,
  RiskAssessment,
  ScanRequest,
  ScanReviewRecord,
} from '../domain/contracts.js'
import type { PackageNode, RiskSignal, ScanFinding, ScanResult } from '../domain/entities.js'
import { InvalidUsageError } from '../domain/errors.js'
import type {
  DependencyTraverser,
  RiskScorer,
  ScanReviewStore,
  TraversedDependencyGraph,
} from '../domain/ports.js'
import {
  baselineKeyForScan,
  calculateAgeDays,
  normalizeMaxDepth,
  normalizeScanTarget,
  normalizeThreshold,
  packageKey,
  parsePackageSpec,
  recommendationForRiskLevel,
  riskLevelForScore,
  riskScoreForSignals,
} from '../domain/value-objects.js'

interface ScanPackageDependencies {
  traverser: DependencyTraverser
  scorer: RiskScorer
  reviewStore: ScanReviewStore
  now?: () => Date
}

interface DependencyEdgeSnapshot {
  edge: DependencyGraphEdge
  path: string[]
}

export function createScanPackageUseCase({
  traverser,
  scorer,
  reviewStore,
  now = () => new Date(),
}: ScanPackageDependencies) {
  return async function scanPackage(request: ScanRequest): Promise<ScanResult> {
    const startedAt = now()
    const packageSpec = parsePackageSpec(request.package_spec)
    const scanTarget = normalizeScanTarget(request.package_spec)
    const maxDepth = normalizeMaxDepth(request.max_depth)
    const threshold = normalizeThreshold(request.threshold)
    const baselineKey = baselineKeyForScan(scanTarget, maxDepth)
    const traversedGraph = await traverser.traverse(packageSpec, maxDepth)

    if (traversedGraph.root_key.length === 0 || traversedGraph.nodes.length === 0) {
      throw new InvalidUsageError(`No package graph could be resolved for "${request.package_spec}".`)
    }

    const edgeSnapshots = buildDependencyEdgeSnapshots(traversedGraph)
    const dependencyEdges = edgeSnapshots.map((snapshot) => snapshot.edge)
    const previousRecord = await findPreviousRecord(reviewStore, baselineKey)
    const newDependencyEdgeFindings = buildNewDependencyEdgeFindings(previousRecord, edgeSnapshots)
    const deltaSignals = buildDeltaSignals(newDependencyEdgeFindings, previousRecord)
    const nodeMap = new Map<string, PackageNode>()
    const findings: ScanFinding[] = []
    let overallRiskScore = 0

    for (const traversedNode of traversedGraph.nodes) {
      let assessment = scorer.assessPackage(traversedNode.metadata, {
        depth: traversedNode.depth,
        path: traversedNode.path,
        dependency_count: Object.keys(traversedNode.metadata.dependencies).length,
      })

      if (traversedNode.key === traversedGraph.root_key && deltaSignals.length > 0) {
        assessment = mergeRiskSignals(assessment, deltaSignals)
      }

      const packageNode: PackageNode = {
        name: traversedNode.package.name,
        version: traversedNode.package.version,
        key: traversedNode.key,
        depth: traversedNode.depth,
        age_days: calculateAgeDays(traversedNode.metadata.published_at, startedAt),
        weekly_downloads: traversedNode.metadata.weekly_downloads,
        dependents_count: traversedNode.metadata.dependents_count,
        deprecated_message: traversedNode.metadata.deprecated_message,
        is_security_tombstone: traversedNode.metadata.is_security_tombstone,
        published_at: traversedNode.metadata.published_at,
        first_published: traversedNode.metadata.first_published_at,
        last_published: traversedNode.metadata.last_published_at,
        total_versions: traversedNode.metadata.total_versions,
        dependency_count: Object.keys(traversedNode.metadata.dependencies).length,
        publish_events_last_30_days: traversedNode.metadata.publish_events_last_30_days,
        has_advisories: traversedNode.metadata.has_advisories,
        risk_score: assessment.risk_score,
        risk_level: assessment.risk_level,
        signals: assessment.signals,
        recommendation: assessment.recommendation,
        dependencies: [],
      }

      nodeMap.set(traversedNode.key, packageNode)
      overallRiskScore = Math.max(overallRiskScore, assessment.risk_score)

      if (assessment.risk_score >= threshold) {
        findings.push({
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

    findings.sort(compareFindings)

    const completedAt = now()
    const rootNode = nodeMap.get(traversedGraph.root_key)!
    const recordId = `${completedAt.toISOString()}:${packageKey({
      name: rootNode.name,
      version: rootNode.version,
    })}:depth=${maxDepth}`
    const result: ScanResult = {
      record_id: recordId,
      scan_target: scanTarget,
      baseline_record_id: previousRecord?.record_id ?? null,
      requested_depth: maxDepth,
      threshold,
      root: rootNode,
      findings,
      total_scanned: traversedGraph.nodes.length,
      suspicious_count: findings.length,
      safe_count: traversedGraph.nodes.length - findings.length,
      overall_risk_score: Number(overallRiskScore.toFixed(2)),
      overall_risk_level: riskLevelForScore(overallRiskScore),
      scan_duration_ms: Math.max(0, completedAt.getTime() - startedAt.getTime()),
      timestamp: completedAt.toISOString(),
    }

    await reviewStore.appendScanRecord(
      buildScanReviewRecord({
        result,
        dependencyEdges,
        baselineKey,
        baselineRecordId: previousRecord?.record_id ?? null,
        newDependencyEdgeFindings,
      }),
    )

    return result
  }
}

function buildExplanation(signals: PackageNode['signals']): string {
  if (signals.length === 0) {
    return 'No suspicious signals exceeded the configured threshold.'
  }

  return signals.map((signal) => signal.reason).join('; ')
}

function compareFindings(left: ScanFinding, right: ScanFinding): number {
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
  baselineKey: string,
): Promise<ScanReviewRecord | null> {
  try {
    return await reviewStore.findLatestScanByBaseline(baselineKey)
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

function buildNewDependencyEdgeFindings(
  previousRecord: ScanReviewRecord | null,
  currentEdges: DependencyEdgeSnapshot[],
): NewDependencyEdgeFinding[] {
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
    }))
}

function buildDeltaSignals(
  newEdgeFindings: NewDependencyEdgeFinding[],
  previousRecord: ScanReviewRecord | null,
): RiskSignal[] {
  if (previousRecord === null) {
    return []
  }

  return newEdgeFindings.map((finding) => ({
    type: finding.edge_type === 'direct' ? 'new_direct_dependency_edge' : 'new_transitive_dependency_edge',
    value: `${finding.parent_key}->${finding.child_key}`,
    weight: finding.edge_type === 'direct' ? 'high' : 'medium',
    reason: `new ${finding.edge_type} dependency edge ${finding.parent_key} -> ${finding.child_key} via ${finding.path.join(' > ')} compared with baseline ${previousRecord.created_at}`,
  }))
}

function formatEdgeId(edge: DependencyGraphEdge): string {
  return `${edge.from}->${edge.to}`
}

function buildScanReviewRecord({
  result,
  dependencyEdges,
  baselineKey,
  baselineRecordId,
  newDependencyEdgeFindings,
}: {
  result: ScanResult
  dependencyEdges: DependencyGraphEdge[]
  baselineKey: string
  baselineRecordId: string | null
  newDependencyEdgeFindings: NewDependencyEdgeFinding[]
}): ScanReviewRecord {
  const pkg = {
    name: result.root.name,
    version: result.root.version,
  }

  return {
    record_id: result.record_id,
    created_at: result.timestamp,
    package: pkg,
    package_key: packageKey(pkg),
    scan_target: result.scan_target,
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
    scan_duration_ms: result.scan_duration_ms,
    dependency_edges: dependencyEdges,
    new_dependency_edge_findings: newDependencyEdgeFindings,
  }
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
