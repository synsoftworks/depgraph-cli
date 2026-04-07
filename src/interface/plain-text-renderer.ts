/**
 * Responsibilities:
 * - Render the full deterministic plain-text scan surface for non-TUI flows.
 * - Apply presentation hierarchy using precomputed scan data and presenter projections.
 *
 * Non-responsibilities:
 * - Do not compute scores, collapse raw signals, or apply policy decisions.
 * - Do not shape JSON or terminal UI output.
 */
import type { PackageNode, ScanResult } from '../domain/entities.js'
import {
  buildScanSummary,
  formatEdgeFindingReason,
  formatFindingReasons,
  formatFindingSignalLabels,
  partitionFindings,
} from './scan-output-presenter.js'

/**
 * Renders the full plain-text scan output for `--no-tui` and non-interactive usage.
 *
 * @param result Completed scan result.
 * @returns Deterministic plain-text output including summary, warnings, findings, and tree.
 */
export function renderPlainText(result: ScanResult): string {
  const summary = buildScanSummary(result)
  const findings = partitionFindings(result.findings)
  const lines = [
    `Scan: ${result.root.key}`,
    `Target: ${result.scan_target}`,
    `Record: ${result.record_id}`,
    `Overall risk: ${result.overall_risk_level} (${result.overall_risk_score.toFixed(2)})`,
    '',
    'Summary:',
    `- Packages scanned: ${result.total_scanned}`,
    `- Packages requiring review: ${summary.packages_requiring_review}`,
    `- Findings with security-related signals: ${summary.security_related_findings}`,
    `- Packages that appear safe: ${summary.packages_appearing_safe}`,
    '',
    `Warnings: ${result.warnings.length}`,
  ]

  if (result.warnings.length > 0) {
    lines.push('', 'Warnings:')

    for (const warning of result.warnings) {
      lines.push(`- ${warning.package_key} [${warning.kind}] ${warning.message}`)

      if (warning.lockfile_resolved_url !== null) {
        lines.push(`  resolved: ${warning.lockfile_resolved_url}`)
      }
    }
  }

  lines.push(
    '',
    'Changed dependencies:',
  )

  if (result.edge_findings.length === 0) {
    lines.push('- none')
  } else {
    for (const edgeFinding of result.edge_findings) {
      lines.push(
        `- ${edgeFinding.parent_key} -> ${edgeFinding.child_key} [${edgeFinding.edge_type}]`,
      )
      lines.push(`  Path: ${edgeFinding.path.join(' > ')}`)
      lines.push(`  Target: ${edgeFinding.review_target.target_id}`)
      lines.push(`  Reason: ${formatEdgeFindingReason(edgeFinding)}`)
    }
  }

  lines.push(
    '',
    'Priority findings:',
  )

  if (findings.priority.length === 0) {
    lines.push('- none')
  } else {
    lines.push(...renderFindings(findings.priority))
  }

  lines.push('', 'Routine findings:')

  if (findings.routine.length === 0) {
    lines.push('- none')
  } else {
    lines.push(...renderFindings(findings.routine))
  }

  lines.push('', 'Dependency tree:')
  lines.push(...renderTree(result.root))

  return lines.join('\n')
}

function renderFindings(findings: ScanResult['findings']): string[] {
  const lines: string[] = []

  for (const finding of findings) {
    lines.push(`- ${finding.key} [${finding.risk_level} ${finding.risk_score.toFixed(2)}]`)
    lines.push(`  Path: ${formatPath(finding.path.packages)}`)
    lines.push(`  Target: ${finding.review_target.target_id}`)
    lines.push(`  Signals: ${formatFindingSignalLabels(finding).join(', ')}`)

    for (const reason of formatFindingReasons(finding)) {
      lines.push(`  - ${reason}`)
    }
  }

  return lines
}

function renderTree(node: PackageNode, prefix = '', isLast = true): string[] {
  const connector = prefix.length === 0 ? '-' : isLast ? '└─' : '├─'
  const lines = [
    `${prefix}${connector} ${node.key}${formatNodeTags(node, prefix.length === 0)} [${node.risk_level} ${node.risk_score.toFixed(2)}]`,
  ]
  // Prefix state is derived during traversal so tree rows stay deterministic across environments.
  const childPrefix = prefix.length === 0 ? '  ' : `${prefix}${isLast ? '  ' : '│ '}`

  node.dependencies.forEach((dependency, index) => {
    lines.push(...renderTree(dependency, childPrefix, index === node.dependencies.length - 1))
  })

  return lines
}

function formatPath(packages: ScanResult['findings'][number]['path']['packages']): string {
  return packages.map((pkg) => `${pkg.name}@${pkg.version}`).join(' > ')
}

function formatNodeTags(node: PackageNode, isRootNode: boolean): string {
  const tags: string[] = []

  if (isRootNode) {
    tags.push('scanned package')
  }

  if (node.is_project_root) {
    tags.push('project root')
  }

  if (node.metadata_status === 'unresolved_registry_lookup') {
    tags.push('registry metadata unavailable')
  }

  if (tags.length === 0) {
    return ''
  }

  return ` [${tags.join(', ')}]`
}
