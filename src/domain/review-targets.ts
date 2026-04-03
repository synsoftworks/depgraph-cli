import type {
  EdgeFinding,
  EdgeFindingReviewTarget,
  PackageFindingReviewTarget,
  ReviewTarget,
  ReviewTargetKind,
} from './contracts.js'
import type { ScanFinding } from './entities.js'

export function packageFindingTargetId(packageKey: string): string {
  return `package_finding:${packageKey}`
}

export function edgeFindingTargetId(
  parentKey: string,
  childKey: string,
  edgeType: EdgeFinding['edge_type'],
): string {
  return `edge_finding:${edgeType}:${parentKey}->${childKey}`
}

export function createPackageFindingReviewTarget(
  recordId: string,
  packageKey: string,
): PackageFindingReviewTarget {
  const targetId = packageFindingTargetId(packageKey)

  return {
    kind: 'package_finding',
    record_id: recordId,
    target_id: targetId,
    finding_key: targetId,
    package_key: packageKey,
  }
}

export function createEdgeFindingReviewTarget(
  recordId: string,
  parentKey: string,
  childKey: string,
  edgeType: EdgeFinding['edge_type'],
): EdgeFindingReviewTarget {
  const targetId = edgeFindingTargetId(parentKey, childKey, edgeType)

  return {
    kind: 'edge_finding',
    record_id: recordId,
    target_id: targetId,
    edge_finding_key: targetId,
    parent_key: parentKey,
    child_key: childKey,
    edge_type: edgeType,
  }
}

export function normalizeScanFinding(recordId: string, finding: ScanFinding): ScanFinding {
  const reviewTarget =
    finding.review_target ??
    createPackageFindingReviewTarget(recordId, finding.key)

  return {
    ...finding,
    review_target: reviewTarget,
  }
}

export function normalizeEdgeFinding(recordId: string, edgeFinding: EdgeFinding): EdgeFinding {
  const reviewTarget =
    edgeFinding.review_target ??
    createEdgeFindingReviewTarget(
      recordId,
      edgeFinding.parent_key,
      edgeFinding.child_key,
      edgeFinding.edge_type,
    )

  return {
    ...edgeFinding,
    review_target: reviewTarget,
  }
}

export function reviewTargetScopeKey(reviewTarget: ReviewTarget): string {
  return `${reviewTarget.record_id}::${reviewTarget.target_id}`
}

export function isReviewTargetKind(
  value: string,
  expectedKind: ReviewTargetKind,
): boolean {
  return value === expectedKind
}
