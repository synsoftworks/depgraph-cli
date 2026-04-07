import React, { useEffect } from 'react'
import { Box, Text, render, useApp } from 'ink'

import type { EdgeFinding } from '../domain/contracts.js'
import type { PackageNode, RiskLevel, ScanFinding, ScanResult } from '../domain/entities.js'
import {
  buildScanSummary,
  formatEdgeFindingReason,
  formatFindingReasons,
  isSecurityRelatedFinding,
} from './scan-output-presenter.js'

const DIVIDER = '─'.repeat(92)
const PANEL_WIDTH = 88

function AutoExit(): React.JSX.Element | null {
  const { exit } = useApp()

  useEffect(() => {
    const timeout = setTimeout(() => exit(), 0)

    return () => clearTimeout(timeout)
  }, [exit])

  return null
}

function ScanResultView({ result }: { result: ScanResult }): React.JSX.Element {
  const findingsByKey = new Map(result.findings.map((finding) => [finding.key, finding]))
  const summary = buildScanSummary(result)
  const exitCode = result.suspicious_count > 0 ? 1 : 0
  const showOverallRisk = shouldRenderOverallRisk(result)

  return (
    <Box flexDirection="column" paddingX={1}>
      <AutoExit />
      <Box justifyContent="space-between" marginBottom={1}>
        <Box>
          <Text bold color="white">
            depgraph
          </Text>
          <Text color="gray">{'  scan'}</Text>
        </Box>
        <Text color="gray">{`${result.total_scanned} packages`}</Text>
      </Box>

      <Box
        flexDirection="column"
        borderStyle="single"
        borderColor="blue"
        paddingX={1}
        paddingY={0}
        marginBottom={1}
        width={PANEL_WIDTH}
      >
        <Text color="gray">SCANNING</Text>
        <Text bold color="white">
          {result.root.key}
          <Text color="gray">
            {` · depth: ${result.requested_depth} · visited: ${result.total_scanned}`}
          </Text>
        </Text>
      </Box>

      <Box flexDirection="column" marginBottom={1}>
        <SummaryPanel result={summary} />
        {result.warnings.length > 0 ? <WarningsPanel warnings={result.warnings} /> : null}

        {result.edge_findings.length > 0 ? (
          <ChangedEdgesPanel edgeFindings={result.edge_findings} />
        ) : null}

        {flattenTree(result.root).map((row) => (
          <React.Fragment key={row.node.key}>
            <TreeRow
              node={row.node}
              prefix={row.prefix}
              finding={findingsByKey.get(row.node.key)}
            />
            {findingsByKey.has(row.node.key) ? (
              <FindingPanel
                node={row.node}
                finding={findingsByKey.get(row.node.key)!}
                threshold={result.threshold}
              />
            ) : null}
          </React.Fragment>
        ))}
      </Box>

      <Text color="gray">{DIVIDER}</Text>

      <Box marginTop={1} justifyContent={showOverallRisk ? 'space-between' : 'flex-start'}>
        <Box>
          <MetricBlock value={String(result.total_scanned)} label="PACKAGES SCANNED" color="greenBright" />
          <MetricBlock
            value={String(result.suspicious_count)}
            label="SUSPICIOUS"
            color={result.suspicious_count > 0 ? 'redBright' : 'gray'}
          />
          <MetricBlock value={String(result.safe_count)} label="SAFE" color="greenBright" />
        </Box>
        {showOverallRisk ? (
          <Box flexDirection="column" width={42}>
            <Text color="gray">OVERALL RISK</Text>
            <RiskBar score={result.overall_risk_score} />
            <Text color={riskColor(result.overall_risk_level)}>
              {`${formatPresentedRiskLevel(result.overall_risk_level)} · ${result.overall_risk_score.toFixed(2)}`}
            </Text>
          </Box>
        ) : null}
      </Box>

      <Box marginTop={1}>
        <Text color="gray">Process exited with code </Text>
        <Text color={exitCode === 0 ? 'greenBright' : 'redBright'}>{String(exitCode)}</Text>
        <Text color="gray">
          {exitCode === 0 ? ' (no suspicious packages found)' : ' (suspicious packages found)'}
        </Text>
      </Box>
    </Box>
  )
}

function ChangedEdgesPanel({ edgeFindings }: { edgeFindings: EdgeFinding[] }): React.JSX.Element {
  return (
    <Box marginBottom={1}>
      <Box
        flexDirection="column"
        borderStyle="single"
        borderColor="yellow"
        paddingX={1}
        paddingY={0}
        width={PANEL_WIDTH}
      >
        <Text color="gray">CHANGED DEPENDENCIES</Text>
        {edgeFindings.map((edgeFinding) => (
          <Box key={`${edgeFinding.parent_key}->${edgeFinding.child_key}`} flexDirection="column" marginBottom={1}>
            <Text color="yellowBright">
              {`${edgeFinding.parent_key} -> ${edgeFinding.child_key} [${edgeFinding.edge_type}]`}
            </Text>
            <Text color="gray">{edgeFinding.path.join(' > ')}</Text>
            <Text color="white">{formatEdgeFindingReason(edgeFinding)}</Text>
          </Box>
        ))}
      </Box>
    </Box>
  )
}

function SummaryPanel({
  result,
}: {
  result: ReturnType<typeof buildScanSummary>
}): React.JSX.Element {
  return (
    <Box marginBottom={1}>
      <Box
        flexDirection="column"
        borderStyle="single"
        borderColor="green"
        paddingX={1}
        paddingY={0}
        width={PANEL_WIDTH}
      >
        <Text color="gray">SUMMARY</Text>
        <MetricLine label="Packages requiring review" value={String(result.packages_requiring_review)} />
        <MetricLine
          label="Findings with security-related signals"
          value={String(result.security_related_findings)}
        />
        <MetricLine label="Packages that appear safe" value={String(result.packages_appearing_safe)} />
      </Box>
    </Box>
  )
}

function MetricLine({ label, value }: { label: string; value: string }): React.JSX.Element {
  return (
    <Box>
      <Text color="greenBright">{'• '}</Text>
      <Text color="gray">{`${label}: `}</Text>
      <Text color="white">{value}</Text>
    </Box>
  )
}

function TreeRow({
  node,
  prefix,
  finding,
}: {
  node: PackageNode
  prefix: string
  finding: ScanFinding | undefined
}): React.JSX.Element {
  const isRootNode = node.depth === 0
  const isActiveFinding = finding !== undefined
  const nameColor = isActiveFinding
    ? 'white'
    : isRootNode
      ? 'white'
      : node.risk_level === 'safe'
        ? 'gray'
        : riskColor(node.risk_level)

  return (
    <Box alignItems="center">
      <Text color={isActiveFinding ? 'red' : 'blue'}>{prefix}</Text>
      <Text bold={isRootNode || isActiveFinding} color={nameColor}>
        {node.name}
      </Text>
      <Text color="gray">{`@${node.version}`}</Text>
      {isRootNode ? <Text color="gray">{' · scanned package'}</Text> : null}
      {node.is_project_root ? <Text color="gray">{' · project root'}</Text> : null}
      {node.metadata_status === 'unresolved_registry_lookup' ? (
        <Text color="yellow">{' · registry metadata unavailable'}</Text>
      ) : null}
      <RiskBadge level={node.risk_level} />
    </Box>
  )
}

function WarningsPanel({
  warnings,
}: {
  warnings: ScanResult['warnings']
}): React.JSX.Element {
  return (
    <Box marginBottom={1}>
      <Box
        flexDirection="column"
        borderStyle="single"
        borderColor="yellow"
        paddingX={1}
        paddingY={0}
        width={PANEL_WIDTH}
      >
        <Text color="gray">WARNINGS</Text>
        {warnings.map((warning) => (
          <Box key={warning.package_key} flexDirection="column" marginBottom={1}>
            <Text color="yellowBright">{warning.package_key}</Text>
            <Text color="white">{warning.message}</Text>
            {warning.lockfile_resolved_url !== null ? (
              <Text color="gray">{warning.lockfile_resolved_url}</Text>
            ) : null}
          </Box>
        ))}
      </Box>
    </Box>
  )
}

function FindingPanel({
  node,
  finding,
  threshold,
}: {
  node: PackageNode
  finding: ScanFinding
  threshold: number
}): React.JSX.Element {
  const reasons = formatFindingReasons(finding)
  const findingKind = isSecurityRelatedFinding(finding) ? 'PRIORITY FINDING' : 'ROUTINE FINDING'
  const details: Array<[string, string, string]> = [
    ['package age', formatAge(node.age_days), 'redBright'],
    ['weekly downloads', formatDownloads(node.weekly_downloads, node.is_security_tombstone), 'redBright'],
    ['total versions', formatPublishedVersions(node.total_versions), 'yellowBright'],
    ['risk score', `${finding.risk_score.toFixed(2)} (threshold: ${threshold.toFixed(2)})`, 'redBright'],
  ]

  if (node.is_security_tombstone) {
    details.splice(2, 0, ['registry', 'security tombstone', 'redBright'])
  }

  if (node.dependents_count !== null) {
    details.splice(node.is_security_tombstone ? 3 : 2, 0, [
      'dependents',
      `${node.dependents_count.toLocaleString()} packages`,
      'redBright',
    ])
  }

  return (
    <Box marginLeft={4} marginBottom={1}>
      <Box
        flexDirection="column"
        borderStyle="single"
        borderColor="red"
        paddingX={1}
        paddingY={0}
        width={PANEL_WIDTH - 4}
      >
        <Text color="gray">{findingKind}</Text>
        {details.map(([label, value, color]) => (
          <Box key={label}>
            <Text color="redBright">{'• '}</Text>
            <Text color="gray">{`${label.padEnd(16)}`}</Text>
            <Text color={color}>{value}</Text>
          </Box>
        ))}
        {reasons.length > 0 ? (
          <Box flexDirection="column" marginTop={1}>
            {reasons.map((reason) => (
              <Box key={reason}>
                <Text color="redBright">{'• '}</Text>
                <Text color="yellowBright">{reason}</Text>
              </Box>
            ))}
          </Box>
        ) : null}
      </Box>
    </Box>
  )
}

function RiskBadge({ level }: { level: RiskLevel }): React.JSX.Element {
  const color = riskColor(level)

  return (
    <Box marginLeft={1}>
      <Text color="gray">[</Text>
      <Text bold color={color}>{formatPresentedRiskLevel(level)}</Text>
      <Text color="gray">]</Text>
    </Box>
  )
}

function RiskBar({
  score,
}: {
  score: number
}): React.JSX.Element {
  const total = 28
  const filled = Math.max(0, Math.min(total, Math.round(score * total)))
  const empty = Math.max(0, total - filled)
  const low = Math.min(filled, Math.floor(total * 0.33))
  const medium = Math.min(Math.max(filled - low, 0), Math.floor(total * 0.34))
  const high = Math.max(filled - low - medium, 0)

  return (
    <Box>
      {low > 0 ? <Text color="greenBright">{'█'.repeat(low)}</Text> : null}
      {medium > 0 ? <Text color="yellowBright">{'█'.repeat(medium)}</Text> : null}
      {high > 0 ? <Text color="redBright">{'█'.repeat(high)}</Text> : null}
      {empty > 0 ? <Text color="#2c3243">{'█'.repeat(empty)}</Text> : null}
    </Box>
  )
}

function MetricBlock({
  value,
  label,
  color,
}: {
  value: string
  label: string
  color: string
}): React.JSX.Element {
  return (
    <Box flexDirection="column" marginRight={3} width={16}>
      <Text bold color={color}>
        {value}
      </Text>
      <Text color="gray">{label}</Text>
    </Box>
  )
}

function flattenTree(node: PackageNode, ancestors: boolean[] = []): Array<{ node: PackageNode; prefix: string }> {
  const rows = [
    {
      node,
      prefix: buildTreePrefix(ancestors),
    },
  ]

  node.dependencies.forEach((dependency, index) => {
    rows.push(
      ...flattenTree(dependency, [...ancestors, index === node.dependencies.length - 1]),
    )
  })

  return rows
}

function buildTreePrefix(ancestors: boolean[]): string {
  if (ancestors.length === 0) {
    return ''
  }

  const branchPrefix = ancestors
    .slice(0, -1)
    .map((isLast) => (isLast ? '   ' : '│  '))
    .join('')
  const connector = ancestors.at(-1) === true ? '└─ ' : '├─ '

  return `${branchPrefix}${connector}`
}

function riskColor(level: RiskLevel): string {
  switch (level) {
    case 'critical':
      return 'redBright'
    case 'review':
      return 'yellowBright'
    default:
      return 'greenBright'
  }
}

function riskLabel(level: RiskLevel): string {
  return formatPresentedRiskLevel(level)
}

export function formatPresentedRiskLevel(level: RiskLevel): string {
  switch (level) {
    case 'critical':
      return 'critical'
    case 'review':
      return 'review'
    default:
      return 'safe'
  }
}

function formatAge(days: number | null): string {
  if (days === null) {
    return 'n/a'
  }

  if (days === 0) {
    return 'today'
  }

  if (days === 1) {
    return '1 day old'
  }

  return `${days.toLocaleString()} days old`
}

function formatPublishedVersions(totalVersions: number | null): string {
  if (totalVersions === null) {
    return 'n/a'
  }

  return `${totalVersions}`
}

function formatDownloads(downloads: number | null, isSecurityTombstone: boolean): string {
  if (isSecurityTombstone) {
    return 'ignored for tombstone'
  }

  if (downloads === null) {
    return 'unknown'
  }

  return `${downloads.toLocaleString()} / week`
}

export function shouldRenderOverallRisk(result: Pick<ScanResult, 'suspicious_count'>): boolean {
  return result.suspicious_count > 0
}

export async function renderInk(result: ScanResult): Promise<void> {
  const app = render(<ScanResultView result={result} />)
  await app.waitUntilExit()
}
