/** Classification of a surfaced benchmark failure. */
export type SurfacedFailureClass = 'underweighted_signal' | 'missing_signal'

/** Status explaining why a surfaced failure is being reported. */
export type SurfacedFailureStatus = 'historical_match' | 'known_boundary_case'

/** One surfaced historical or known-boundary failure entry. */
export interface SurfacedFailure {
  package: string
  version: string
  failure_class: SurfacedFailureClass
  status: SurfacedFailureStatus
  record_ids: string[]
  reason: string
}

/** Aggregate output of the failure-surfacing evaluation flow. */
export interface FailureSurfacingSummary {
  total_records_scanned: number
  total_matches: number
  failures: SurfacedFailure[]
}

/** Hand-maintained known boundary case that should still surface in reports. */
export interface KnownBoundaryCase {
  package: string
  version: string
  failure_class: Extract<SurfacedFailureClass, 'missing_signal'>
  status: Extract<SurfacedFailureStatus, 'known_boundary_case'>
  reason: string
}

/** Known benchmark boundary cases that are expected to miss current metadata-only heuristics. */
export const KNOWN_BOUNDARY_CASES: KnownBoundaryCase[] = [
  {
    package: 'isite',
    version: '2024.8.19',
    failure_class: 'missing_signal',
    status: 'known_boundary_case',
    reason:
      'Known metadata boundary case (BM-003/FN-002): registry metadata can look normal while malicious behavior exists only in the tarball.',
  },
]
