import type { BaselineIdentity, ScanReviewRecord } from './contracts.js'
import type { PackageNode } from './entities.js'
import { normalizeEdgeFinding, normalizeScanFinding } from './review-targets.js'
import { baselineKeyForIdentity } from './value-objects.js'

export function normalizeScanReviewRecord(record: ScanReviewRecord): ScanReviewRecord {
  const baselineIdentity = normalizeBaselineIdentity(record)

  return {
    ...record,
    scan_mode: record.scan_mode ?? baselineIdentity.scan_mode,
    baseline_identity: baselineIdentity,
    baseline_key: baselineKeyForIdentity(baselineIdentity),
    warnings: record.warnings ?? [],
    findings: record.findings.map((finding) => normalizeScanFinding(record.record_id, finding)),
    edge_findings: record.edge_findings.map((edgeFinding) =>
      normalizeEdgeFinding(record.record_id, edgeFinding),
    ),
    root: normalizePackageNode(record.root),
  }
}

function normalizeBaselineIdentity(record: ScanReviewRecord): BaselineIdentity {
  return {
    scan_mode: record.baseline_identity.scan_mode ?? record.scan_mode ?? 'registry_package',
    scan_target: record.baseline_identity.scan_target,
    requested_depth: record.baseline_identity.requested_depth,
    workspace_identity: record.baseline_identity.workspace_identity,
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
