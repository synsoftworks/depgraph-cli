import type { ScanResult } from '../domain/entities.js'

export function renderJson(result: ScanResult): string {
  const { field_reliability: _fieldReliability, ...publicResult } = result

  return JSON.stringify(publicResult, null, 2)
}
