import type { FieldReliabilityEntry, FieldReliabilityReport } from './entities.js'

/**
 * Builds the current ADR-012 field reliability policy snapshot.
 *
 * @returns Field reliability report used in scan results and readiness analysis.
 */
export function createFieldReliabilityReport(): FieldReliabilityReport {
  return {
    adr: 'ADR-012',
    fields: {
      'scan_result.record_id': scanContext(
        'Retain as scan metadata only; do not treat as package-behavior data.',
      ),
      'scan_result.scan_mode': scanContext(
        'Retain as scan metadata only; do not treat as package-behavior data.',
      ),
      'scan_result.scan_target': scanContext(
        'Retain as scan metadata only; do not treat as package-behavior data.',
      ),
      'scan_result.baseline_record_id': scanContext(
        'Retain as scan provenance only; do not treat as package-behavior data.',
      ),
      'scan_result.requested_depth': scanContext(
        'Retain as scan metadata only; do not treat as package-behavior data.',
      ),
      'scan_result.threshold': scanContext(
        'Retain as scan metadata only; do not treat as package-behavior data.',
      ),
      'scan_result.root': structuralOnly(
        'Use as the graph entrypoint only; do not treat the container field itself as a feature.',
      ),
      'scan_result.edge_findings': structuralOnly(
        'Use for graph-change review context only; do not treat the container field itself as a feature.',
      ),
      'scan_result.findings': structuralOnly(
        'Use for review workflow context only; do not treat the container field itself as a feature.',
      ),
      'scan_result.total_scanned': scanContext(
        'Retain as scan metadata only; do not treat as package-behavior data.',
      ),
      'scan_result.suspicious_count': heuristicOutput(
        'Valid for UI and debugging; do not use as ground-truth package behavior or labels.',
      ),
      'scan_result.safe_count': heuristicOutput(
        'Valid for UI and debugging; do not use as ground-truth package behavior or labels.',
      ),
      'scan_result.overall_risk_score': heuristicOutput(
        'Valid for UI and debugging; do not use as ground-truth package behavior or labels.',
      ),
      'scan_result.overall_risk_level': heuristicOutput(
        'Valid for UI and debugging; do not use as ground-truth package behavior or labels.',
      ),
      'scan_result.warnings': scanContext(
        'Retain as scan-time incompleteness and provenance metadata, not package-behavior truth.',
      ),
      'scan_result.scan_duration_ms': scanContext(
        'Retain as scan metadata only; do not treat as package-behavior data.',
      ),
      'scan_result.timestamp': scanContext(
        'Retain as scan metadata only; do not treat as package-behavior data.',
      ),
      'package_node.name': reliable('Safe for analysis and feature use.'),
      'package_node.version': reliable('Safe for analysis and feature use.'),
      'package_node.key': reliable('Safe for analysis and feature use.'),
      'package_node.depth': structuralOnly(
        'Retain for graph context only; do not treat as a direct risk feature.',
      ),
      'package_node.is_project_root': structuralOnly(
        'Retain for traversal context only; do not treat as a direct risk feature.',
      ),
      'package_node.metadata_status': reliable('Safe for analysis and feature use.'),
      'package_node.metadata_warning': scanContext(
        'Retain as scan-time provenance and incompleteness context, not package-behavior truth.',
      ),
      'package_node.lockfile_resolved_url': scanContext(
        'Retain as provenance for lockfile scans only; do not treat as package-behavior data.',
      ),
      'package_node.lockfile_integrity': scanContext(
        'Retain as provenance for lockfile scans only; do not treat as package-behavior data.',
      ),
      'package_node.age_days': reliable('Safe for analysis and feature use.'),
      'package_node.weekly_downloads': conditionallyReliable(
        'Use only with explicit missing-value handling.',
        'Do not coerce null to 0.',
        'Downloads are not a standalone trust signal.',
      ),
      'package_node.dependents_count': unavailable(
        'Exclude from analysis and export until collection is implemented.',
        'Interpret raw values through the metadata field-state helpers.',
        'Do not treat null as zero or as a benign missing feature value.',
      ),
      'package_node.deprecated_message': reliable('Safe for analysis and feature use.'),
      'package_node.is_security_tombstone': reliable('Safe for analysis and feature use.'),
      'package_node.published_at': reliable('Safe for analysis and feature use.'),
      'package_node.first_published': reliable('Safe for analysis and feature use.'),
      'package_node.last_published': reliable('Safe for analysis and feature use.'),
      'package_node.total_versions': reliable('Safe for analysis and feature use.'),
      'package_node.dependency_count': reliable('Safe for analysis and feature use.'),
      'package_node.publish_events_last_30_days': reliable('Safe for analysis and feature use.'),
      'package_node.has_advisories': placeholder(
        'Exclude from analysis and export until advisory ingestion is implemented.',
        'Interpret raw values through the metadata field-state helpers.',
        'Do not treat false as observed clean advisory status.',
      ),
      'package_node.risk_score': heuristicOutput(
        'Valid for UI and debugging; do not use as ground truth or labels.',
      ),
      'package_node.risk_level': heuristicOutput(
        'Valid for UI and debugging; do not use as ground truth or labels.',
      ),
      'package_node.signals': heuristicOutput(
        'Valid for UI and debugging; do not use as ground truth or labels.',
      ),
      'package_node.recommendation': heuristicOutput(
        'Valid for UI and debugging; do not use as ground truth or labels.',
      ),
      'package_node.dependencies': structuralOnly(
        'The relationship container is structural only; child node fields retain their own policy.',
      ),
      'scan_finding.key': reliable('Safe for analysis and feature use.'),
      'scan_finding.name': reliable('Safe for analysis and feature use.'),
      'scan_finding.version': reliable('Safe for analysis and feature use.'),
      'scan_finding.depth': structuralOnly(
        'Retain for graph context only; do not treat as a direct risk feature.',
      ),
      'scan_finding.review_target': structuralOnly(
        'Use for workflow addressing only; do not treat as a feature or label.',
      ),
      'scan_finding.path': structuralOnly(
        'Use for graph context only; do not treat as a direct risk feature.',
      ),
      'scan_finding.risk_score': heuristicOutput(
        'Valid for UI and debugging; do not use as ground truth or labels.',
      ),
      'scan_finding.risk_level': heuristicOutput(
        'Valid for UI and debugging; do not use as ground truth or labels.',
      ),
      'scan_finding.recommendation': heuristicOutput(
        'Valid for UI and debugging; do not use as ground truth or labels.',
      ),
      'scan_finding.signals': heuristicOutput(
        'Valid for UI and debugging; do not use as ground truth or labels.',
      ),
      'scan_finding.explanation': heuristicOutput(
        'Valid for UI and debugging; do not use as ground truth or labels.',
      ),
      'edge_finding.parent_key': structuralOnly(
        'Use for graph-change context only; do not treat as a direct risk feature.',
      ),
      'edge_finding.child_key': structuralOnly(
        'Use for graph-change context only; do not treat as a direct risk feature.',
      ),
      'edge_finding.path': structuralOnly(
        'Use for graph-change context only; do not treat as a direct risk feature.',
      ),
      'edge_finding.depth': structuralOnly(
        'Use for graph-change context only; do not treat as a direct risk feature.',
      ),
      'edge_finding.edge_type': structuralOnly(
        'Use for graph-change context only; do not treat as a direct risk feature.',
      ),
      'edge_finding.review_target': structuralOnly(
        'Use for workflow addressing only; do not treat as a feature or label.',
      ),
      'edge_finding.baseline_record_id': scanContext(
        'Retain as scan provenance only; do not treat as package-behavior data.',
      ),
      'edge_finding.baseline_identity': structuralOnly(
        'Use for baseline matching context only; do not treat as a feature or label.',
      ),
      'edge_finding.reason': heuristicOutput(
        'Valid for UI and debugging; do not use as ground truth or labels.',
      ),
      'edge_finding.recommendation': heuristicOutput(
        'Valid for UI and debugging; do not use as ground truth or labels.',
      ),
      'scan_warning.kind': scanContext(
        'Retain as scan-time incompleteness and provenance metadata, not package-behavior truth.',
      ),
      'scan_warning.package_key': scanContext(
        'Retain as scan-time incompleteness and provenance metadata, not package-behavior truth.',
      ),
      'scan_warning.package_name': scanContext(
        'Retain as scan-time incompleteness and provenance metadata, not package-behavior truth.',
      ),
      'scan_warning.package_version': scanContext(
        'Retain as scan-time incompleteness and provenance metadata, not package-behavior truth.',
      ),
      'scan_warning.message': scanContext(
        'Retain as scan-time incompleteness and provenance metadata, not package-behavior truth.',
      ),
      'scan_warning.lockfile_resolved_url': scanContext(
        'Retain as scan-time incompleteness and provenance metadata, not package-behavior truth.',
      ),
      'scan_warning.lockfile_integrity': scanContext(
        'Retain as scan-time incompleteness and provenance metadata, not package-behavior truth.',
      ),
    },
  }
}

function reliable(guidance: string, ...notes: string[]): FieldReliabilityEntry {
  return entry('reliable', guidance, notes)
}

function conditionallyReliable(guidance: string, ...notes: string[]): FieldReliabilityEntry {
  return entry('conditionally_reliable', guidance, notes)
}

function unavailable(guidance: string, ...notes: string[]): FieldReliabilityEntry {
  return entry('unavailable', guidance, notes)
}

function placeholder(guidance: string, ...notes: string[]): FieldReliabilityEntry {
  return entry('placeholder', guidance, notes)
}

function heuristicOutput(guidance: string, ...notes: string[]): FieldReliabilityEntry {
  return entry('heuristic_output', guidance, notes)
}

function structuralOnly(guidance: string, ...notes: string[]): FieldReliabilityEntry {
  return entry('structural_only', guidance, notes)
}

function scanContext(guidance: string, ...notes: string[]): FieldReliabilityEntry {
  return entry('scan_context', guidance, notes)
}

function entry(
  tier: FieldReliabilityEntry['tier'],
  guidance: string,
  notes: string[],
): FieldReliabilityEntry {
  if (notes.length === 0) {
    return {
      tier,
      guidance,
    }
  }

  return {
    tier,
    guidance,
    notes,
  }
}
