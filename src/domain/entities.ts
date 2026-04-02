import type { DependencyPath, EdgeFinding } from './contracts.js'

export type RiskLevel = 'safe' | 'review' | 'critical'
export type Recommendation = 'install' | 'review' | 'do_not_install'
export type RiskSignalWeight = 'low' | 'medium' | 'high' | 'critical'
export type ReviewOutcome = 'malicious' | 'benign' | 'needs_review'
export type ReviewSource = 'human' | 'auto' | 'external'

export interface RiskSignal {
  type: string
  value: string | number | boolean | null
  weight: RiskSignalWeight
  reason: string
}

export interface PackageNode {
  name: string
  version: string
  key: string
  depth: number
  age_days: number
  weekly_downloads: number | null
  dependents_count: number | null
  deprecated_message: string | null
  is_security_tombstone: boolean
  published_at: string
  first_published: string
  last_published: string
  total_versions: number
  dependency_count: number
  publish_events_last_30_days: number
  has_advisories: boolean
  risk_score: number
  risk_level: RiskLevel
  signals: RiskSignal[]
  recommendation: Recommendation
  dependencies: PackageNode[]
}

export interface ScanFinding {
  key: string
  name: string
  version: string
  depth: number
  path: DependencyPath
  risk_score: number
  risk_level: RiskLevel
  recommendation: Recommendation
  signals: RiskSignal[]
  explanation: string
}

export interface ScanResult {
  record_id: string
  scan_target: string
  baseline_record_id: string | null
  requested_depth: number
  threshold: number
  root: PackageNode
  edge_findings: EdgeFinding[]
  findings: ScanFinding[]
  total_scanned: number
  suspicious_count: number
  safe_count: number
  overall_risk_score: number
  overall_risk_level: RiskLevel
  scan_duration_ms: number
  timestamp: string
}
