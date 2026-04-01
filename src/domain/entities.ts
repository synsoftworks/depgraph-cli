export type RiskLevel = 'safe' | 'review' | 'critical'

export type Recommendation = 'install' | 'review' | 'do_not_install'

export interface RiskSignal {
  type: string
  value: string | number
  weight: 'low' | 'medium' | 'high' | 'critical'
}

export interface PackageNode {
  name: string
  version: string
  depth: number
  age_days: number
  weekly_downloads: number
  first_published: string
  last_published: string
  total_versions: number
  has_advisories: boolean
  sensitive_imports: string[]
  risk_score: number
  risk_level: RiskLevel
  signals: RiskSignal[]
  recommendation: Recommendation
  dependencies: PackageNode[]   // recursive — DAG node
}

export interface ScanResult {
  root: PackageNode
  total_scanned: number
  suspicious_count: number
  safe_count: number
  overall_risk_score: number
  overall_risk_level: RiskLevel
  scan_duration_ms: number
  timestamp: string
}