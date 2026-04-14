import type { ScanResult } from '../domain/entities.js'

/**
 * Renders the public scan contract as deterministic JSON.
 *
 * @param result Completed scan result.
 * @returns Public JSON output without internal reliability metadata.
 */
export function renderJson(result: ScanResult): string {
  const { field_reliability: _fieldReliability, ...publicResult } = result

  return JSON.stringify(publicResult, null, 2)
}
