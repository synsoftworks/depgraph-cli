import type { PackageNode, ScanResult } from '../domain/entities.js'

export function renderPlainText(result: ScanResult): string {
  const lines = [
    `Scan: ${result.root.key}`,
    `Mode: ${result.scan_mode}`,
    `Target: ${result.scan_target}`,
    `Record: ${result.record_id}`,
    `Overall risk: ${result.overall_risk_level} (${result.overall_risk_score.toFixed(2)})`,
    `Total scanned: ${result.total_scanned}`,
    `Suspicious packages: ${result.suspicious_count}`,
    `Warnings: ${result.warnings.length}`,
    '',
    'Warnings:',
  ]

  if (result.warnings.length === 0) {
    lines.push('- none')
  } else {
    for (const warning of result.warnings) {
      lines.push(
        `- ${warning.package_key} [${warning.kind}] ${warning.message}`,
      )

      if (warning.lockfile_resolved_url !== null) {
        lines.push(`  resolved: ${warning.lockfile_resolved_url}`)
      }
    }
  }

  lines.push(
    '',
    'Changed edges in current tree view:',
  )

  if (result.edge_findings.length === 0) {
    lines.push('- none')
  } else {
    for (const edgeFinding of result.edge_findings) {
      lines.push(
        `- ${edgeFinding.parent_key} -> ${edgeFinding.child_key} [${edgeFinding.edge_type}] via ${edgeFinding.path.join(' > ')}`,
      )
      lines.push(`  target: ${edgeFinding.review_target.target_id}`)
      lines.push(`  explanation: ${edgeFinding.reason}`)
    }
  }

  lines.push(
    '',
    'Findings:',
  )

  if (result.findings.length === 0) {
    lines.push('- none')
  } else {
    for (const finding of result.findings) {
      lines.push(
        `- ${finding.key} [${finding.risk_level} ${finding.risk_score.toFixed(2)}] via ${formatPath(finding.path.packages)}`,
      )
      lines.push(`  target: ${finding.review_target.target_id}`)
      lines.push(`  explanation: ${finding.explanation}`)
    }
  }

  lines.push('', 'Current tree view:')
  lines.push(...renderTree(result.root))

  return lines.join('\n')
}

function renderTree(node: PackageNode, prefix = '', isLast = true): string[] {
  const connector = prefix.length === 0 ? '-' : isLast ? '└─' : '├─'
  const lines = [
    `${prefix}${connector} ${node.key}${formatNodeTags(node)} [${node.risk_level} ${node.risk_score.toFixed(2)}]`,
  ]
  const childPrefix = prefix.length === 0 ? '  ' : `${prefix}${isLast ? '  ' : '│ '}`

  node.dependencies.forEach((dependency, index) => {
    lines.push(...renderTree(dependency, childPrefix, index === node.dependencies.length - 1))
  })

  return lines
}

function formatPath(packages: ScanResult['findings'][number]['path']['packages']): string {
  return packages.map((pkg) => `${pkg.name}@${pkg.version}`).join(' > ')
}

function formatNodeTags(node: PackageNode): string {
  const tags: string[] = []

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
