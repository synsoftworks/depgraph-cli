export type SurfacedFailureClass = 'underweighted_signal' | 'missing_signal'

export type SurfacedFailureStatus = 'historical_match' | 'known_boundary_case'

export interface SurfacedFailure {
  package: string
  version: string
  failure_class: SurfacedFailureClass
  status: SurfacedFailureStatus
  record_ids: string[]
  reason: string
}

export interface FailureSurfacingSummary {
  total_records_scanned: number
  total_matches: number
  failures: SurfacedFailure[]
}

export interface KnownBoundaryCase {
  package: string
  version: string
  failure_class: Extract<SurfacedFailureClass, 'missing_signal'>
  status: Extract<SurfacedFailureStatus, 'known_boundary_case'>
  reason: string
}

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
