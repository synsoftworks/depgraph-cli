/**
 * Responsibilities:
 * - Normalize stored scan records into the current domain contract.
 * - Backfill legacy fields required by downstream application code.
 *
 * Non-responsibilities:
 * - Do not persist records, render output, or alter review semantics.
 * - Do not recompute scan findings, scores, or review outcomes.
 */
import type { BaselineIdentity, ScanReviewRecord } from './contracts.js'
import type { PackageNode } from './entities.js'
import { normalizeEdgeFinding, normalizeScanFinding } from './review-targets.js'
import { packageKey } from './value-objects.js'
import { baselineKeyForIdentity } from './value-objects.js'

type StoredScanReviewRecord = Omit<
  ScanReviewRecord,
  'scan_mode' | 'baseline_identity' | 'edge_findings' | 'warnings' | 'dependency_edges'
> & {
  scan_mode?: ScanReviewRecord['scan_mode']
  baseline_identity?: Partial<BaselineIdentity>
  findings?: ScanReviewRecord['findings']
  edge_findings?: ScanReviewRecord['edge_findings']
  warnings?: ScanReviewRecord['warnings']
  dependency_edges?: ScanReviewRecord['dependency_edges']
  new_dependency_edge_findings?: ScanReviewRecord['edge_findings']
}

/**
 * Normalizes a stored scan record into the current `ScanReviewRecord` shape.
 *
 * @param record Persisted scan record that may be missing newer fields.
 * @returns A normalized scan record safe for current application consumers.
 */
export function normalizeScanReviewRecord(record: StoredScanReviewRecord): ScanReviewRecord {
  const baselineIdentity = normalizeBaselineIdentity(record)
  // Older records can omit package identity fields, so downstream consumers normalize from the root node first.
  const root = normalizePackageNode(record.root)
  const scanMode = record.scan_mode ?? baselineIdentity.scan_mode
  const findings = (record.findings ?? []).map((finding) => normalizeScanFinding(record.record_id, finding))
  const primaryFindingKey = resolvePrimaryFindingKey(record.primary_finding_key, findings)

  return {
    ...record,
    scan_mode: scanMode,
    package:
      record.package ??
      {
        name: root.name,
        version: root.version,
      },
    package_key: record.package_key ?? packageKey(record.package ?? root),
    scan_target: record.scan_target ?? baselineIdentity.scan_target,
    ...(primaryFindingKey !== undefined ? { primary_finding_key: primaryFindingKey } : {}),
    baseline_identity: baselineIdentity,
    baseline_key: baselineKeyForIdentity(baselineIdentity),
    warnings: record.warnings ?? [],
    findings,
    edge_findings: getStoredEdgeFindings(record).map((edgeFinding) =>
      normalizeEdgeFinding(record.record_id, edgeFinding),
    ),
    root,
    dependency_edges: record.dependency_edges ?? [],
  }
}

function normalizeBaselineIdentity(record: StoredScanReviewRecord): BaselineIdentity {
  const baselineIdentity = record.baseline_identity

  return {
    // Legacy records may have neither top-level nor nested scan mode metadata; registry_package is the historical fallback.
    scan_mode: baselineIdentity?.scan_mode ?? record.scan_mode ?? 'registry_package',
    // Scan target moved between record shapes over time, so the fallback chain preserves historical compatibility.
    scan_target: baselineIdentity?.scan_target ?? record.scan_target ?? deriveScanTarget(record),
    requested_depth: baselineIdentity?.requested_depth ?? record.requested_depth ?? 0,
    // Workspace identity was absent in early records but newer baseline matching requires a stable value.
    workspace_identity: baselineIdentity?.workspace_identity ?? 'local',
  }
}

function normalizePackageNode(node: PackageNode): PackageNode {
  return {
    ...node,
    is_project_root: node.is_project_root ?? false,
    // Synthetic roots predated explicit metadata_status and must be reconstructed from the older project-root flag.
    metadata_status:
      node.metadata_status ?? (node.is_project_root ? 'synthetic_project_root' : 'enriched'),
    metadata_warning: node.metadata_warning ?? null,
    lockfile_resolved_url: node.lockfile_resolved_url ?? null,
    lockfile_integrity: node.lockfile_integrity ?? null,
    dependencies: node.dependencies.map(normalizePackageNode),
  }
}

function deriveScanTarget(record: StoredScanReviewRecord): string {
  if (typeof record.scan_target === 'string' && record.scan_target.length > 0) {
    return record.scan_target
  }

  if (record.package !== undefined) {
    return packageKey(record.package)
  }

  if (typeof record.package_key === 'string' && record.package_key.length > 0) {
    return record.package_key
  }

  return normalizePackageNode(record.root).key
}

function getStoredEdgeFindings(record: StoredScanReviewRecord): ScanReviewRecord['edge_findings'] {
  // Legacy records used the earlier field name; both are accepted during normalization.
  return record.edge_findings ?? record.new_dependency_edge_findings ?? []
}

function resolvePrimaryFindingKey(
  storedPrimaryFindingKey: string | undefined,
  findings: ScanReviewRecord['findings'],
): string | undefined {
  if (typeof storedPrimaryFindingKey === 'string' && storedPrimaryFindingKey.length > 0) {
    return storedPrimaryFindingKey
  }

  const primaryFinding = findings[0]

  if (primaryFinding !== undefined && primaryFinding.depth > 0) {
    return primaryFinding.key
  }

  return undefined
}
