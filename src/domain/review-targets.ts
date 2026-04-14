import type {
  EdgeFinding,
  EdgeFindingReviewTarget,
  PackageFindingReviewTarget,
  ReviewTarget,
  ReviewTargetKind,
} from './contracts.js'
import type { ScanFinding } from './entities.js'

/**
 * Builds the stable target id for a package finding.
 *
 * @param packageKey Exact package key for the finding.
 * @returns Target id in `package_finding:<packageKey>` form.
 */
export function packageFindingTargetId(packageKey: string): string {
  return `package_finding:${packageKey}`
}

/**
 * Builds the stable target id for an edge finding.
 *
 * @param parentKey Parent package key.
 * @param childKey Child package key.
 * @param edgeType Edge kind relative to the root.
 * @returns Target id for the edge finding.
 */
export function edgeFindingTargetId(
  parentKey: string,
  childKey: string,
  edgeType: EdgeFinding['edge_type'],
): string {
  return `edge_finding:${edgeType}:${parentKey}->${childKey}`
}

/**
 * Creates a normalized review target for a package finding.
 *
 * @param recordId Owning scan record id.
 * @param packageKey Exact package key for the finding.
 * @returns Package-finding review target.
 */
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

/**
 * Creates a normalized review target for an edge finding.
 *
 * @param recordId Owning scan record id.
 * @param parentKey Parent package key.
 * @param childKey Child package key.
 * @param edgeType Edge kind relative to the root.
 * @returns Edge-finding review target.
 */
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

/**
 * Ensures a package finding carries a normalized review target.
 *
 * @param recordId Owning scan record id.
 * @param finding Scan finding that may predate explicit review targets.
 * @returns Finding with a guaranteed review target.
 */
export function normalizeScanFinding(recordId: string, finding: ScanFinding): ScanFinding {
  const reviewTarget =
    finding.review_target ??
    createPackageFindingReviewTarget(recordId, finding.key)

  return {
    ...finding,
    review_target: reviewTarget,
  }
}

/**
 * Ensures an edge finding carries a normalized review target.
 *
 * @param recordId Owning scan record id.
 * @param edgeFinding Edge finding that may predate explicit review targets.
 * @returns Edge finding with a guaranteed review target.
 */
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

/**
 * Builds the persisted lookup key for resolved review-state indexes.
 *
 * @param reviewTarget Review target identity.
 * @returns Stable scope key combining record id and target id.
 */
export function reviewTargetScopeKey(reviewTarget: ReviewTarget): string {
  return `${reviewTarget.record_id}::${reviewTarget.target_id}`
}

/**
 * Narrows a string value to a specific review-target kind.
 *
 * @param value Candidate review-target kind.
 * @param expectedKind Expected kind.
 * @returns `true` when the value matches the expected kind.
 */
export function isReviewTargetKind(
  value: string,
  expectedKind: ReviewTargetKind,
): boolean {
  return value === expectedKind
}
