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

export function normalizeScanReviewRecord(record: StoredScanReviewRecord): ScanReviewRecord {
  const baselineIdentity = normalizeBaselineIdentity(record)
  const root = normalizePackageNode(record.root)
  const scanMode = record.scan_mode ?? baselineIdentity.scan_mode

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
    baseline_identity: baselineIdentity,
    baseline_key: baselineKeyForIdentity(baselineIdentity),
    warnings: record.warnings ?? [],
    findings: (record.findings ?? []).map((finding) => normalizeScanFinding(record.record_id, finding)),
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
    scan_mode: baselineIdentity?.scan_mode ?? record.scan_mode ?? 'registry_package',
    scan_target: baselineIdentity?.scan_target ?? record.scan_target ?? deriveScanTarget(record),
    requested_depth: baselineIdentity?.requested_depth ?? record.requested_depth ?? 0,
    workspace_identity: baselineIdentity?.workspace_identity ?? 'local',
  }
}

function normalizePackageNode(node: PackageNode): PackageNode {
  return {
    ...node,
    is_project_root: node.is_project_root ?? false,
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
  return record.edge_findings ?? record.new_dependency_edge_findings ?? []
}
