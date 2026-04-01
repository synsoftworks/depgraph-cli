import type { ScanRequest } from '../domain/contracts.js'
import type { PackageNode, ScanFinding, ScanResult } from '../domain/entities.js'
import { InvalidUsageError } from '../domain/errors.js'
import type { DependencyTraverser, RiskScorer } from '../domain/ports.js'
import {
  calculateAgeDays,
  normalizeMaxDepth,
  normalizeThreshold,
  packageKey,
  parsePackageSpec,
  riskLevelForScore,
} from '../domain/value-objects.js'

interface ScanPackageDependencies {
  traverser: DependencyTraverser
  scorer: RiskScorer
  now?: () => Date
}

export function createScanPackageUseCase({
  traverser,
  scorer,
  now = () => new Date(),
}: ScanPackageDependencies) {
  return async function scanPackage(request: ScanRequest): Promise<ScanResult> {
    const startedAt = now()
    const packageSpec = parsePackageSpec(request.package_spec)
    const maxDepth = normalizeMaxDepth(request.max_depth)
    const threshold = normalizeThreshold(request.threshold)
    const traversedGraph = await traverser.traverse(packageSpec, maxDepth)

    if (traversedGraph.root_key.length === 0 || traversedGraph.nodes.length === 0) {
      throw new InvalidUsageError(`No package graph could be resolved for "${request.package_spec}".`)
    }

    const nodeMap = new Map<string, PackageNode>()
    const findings: ScanFinding[] = []
    let overallRiskScore = 0

    for (const traversedNode of traversedGraph.nodes) {
      const assessment = scorer.assessPackage(traversedNode.metadata, {
        depth: traversedNode.depth,
        path: traversedNode.path,
        dependency_count: Object.keys(traversedNode.metadata.dependencies).length,
      })

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

    return {
      scan_target: request.package_spec,
      requested_depth: maxDepth,
      threshold,
      root: nodeMap.get(traversedGraph.root_key)!,
      findings,
      total_scanned: traversedGraph.nodes.length,
      suspicious_count: findings.length,
      safe_count: traversedGraph.nodes.length - findings.length,
      overall_risk_score: Number(overallRiskScore.toFixed(2)),
      overall_risk_level: riskLevelForScore(overallRiskScore),
      scan_duration_ms: Math.max(0, completedAt.getTime() - startedAt.getTime()),
      timestamp: completedAt.toISOString(),
    }
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

export function isSuspiciousExitCode(result: ScanResult): number {
  return result.suspicious_count > 0 ? 1 : 0
}

export function getRootKey(result: ScanResult): string {
  return packageKey({
    name: result.root.name,
    version: result.root.version,
  })
}
