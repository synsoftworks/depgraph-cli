import React, { useEffect } from 'react'
import { Box, Text, render, useApp } from 'ink'

import type { EdgeFinding } from '../domain/contracts.js'
import type { PackageNode, RiskLevel, RiskSignal, ScanFinding, ScanResult } from '../domain/entities.js'

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
  const allSignals = collectSignals(result.root)
  const signalTags = deriveSignalTags(result, allSignals)
  const exitCode = result.suspicious_count > 0 ? 1 : 0

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
          <Text color="gray">{` · depth: ${result.requested_depth} · visited: ${result.total_scanned}`}</Text>
        </Text>
      </Box>

      <Box flexDirection="column" marginBottom={1}>
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

      <Box marginTop={1} justifyContent="space-between">
        <Box>
          <MetricBlock value={String(result.total_scanned)} label="PACKAGES SCANNED" color="greenBright" />
          <MetricBlock
            value={String(result.suspicious_count)}
            label="SUSPICIOUS"
            color={result.suspicious_count > 0 ? 'redBright' : 'gray'}
          />
          <MetricBlock value={String(result.safe_count)} label="SAFE" color="greenBright" />
        </Box>
        <Box flexDirection="column" width={42}>
          <Text color="gray">OVERALL RISK</Text>
          <RiskBar score={result.overall_risk_score} level={result.overall_risk_level} />
          <Text color={riskColor(result.overall_risk_level)}>
            {`${formatOverallRiskLabel(result.overall_risk_level)} · ${result.overall_risk_score.toFixed(2)}`}
          </Text>
        </Box>
      </Box>

      {signalTags.length > 0 ? (
        <Box marginTop={1} flexWrap="wrap">
          {signalTags.map((tag) => (
            <StatusChip key={tag} label={tag} color="blueBright" />
          ))}
        </Box>
      ) : null}

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
        <Text color="gray">CHANGED EDGES IN CURRENT TREE VIEW</Text>
        <Text color="gray">current resolved view from registry metadata</Text>
        {edgeFindings.map((edgeFinding) => (
          <Box key={`${edgeFinding.parent_key}->${edgeFinding.child_key}`} flexDirection="column" marginBottom={1}>
            <Text color="yellowBright">
              {`${edgeFinding.parent_key} -> ${edgeFinding.child_key} [${edgeFinding.edge_type}]`}
            </Text>
            <Text color="gray">{edgeFinding.path.join(' > ')}</Text>
            <Text color="white">{edgeFinding.reason}</Text>
          </Box>
        ))}
      </Box>
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
  const emphatic = finding !== undefined || node.risk_level === 'critical'

  return (
    <Box>
      <Text color={emphatic ? 'red' : 'blue'}>{prefix}</Text>
      <Text bold={emphatic} color={emphatic ? 'redBright' : 'white'}>
        {node.name}
      </Text>
      <Text color="gray">{`@${node.version}`}</Text>
      <RiskBadge level={node.risk_level} />
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
  const details: Array<[string, string, string]> = [
    ['age', formatAge(node.age_days), 'redBright'],
    ['downloads', formatDownloads(node.weekly_downloads, node.is_security_tombstone), 'redBright'],
    ['versions', `${node.total_versions} published`, 'yellowBright'],
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

  if (node.deprecated_message !== null) {
    details.push(['deprecation', node.deprecated_message, 'yellowBright'])
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
        {details.map(([label, value, color]) => (
          <Box key={label}>
            <Text color="redBright">{'• '}</Text>
            <Text color="gray">{`${label.padEnd(11)}`}</Text>
            <Text color={color}>{value}</Text>
          </Box>
        ))}
        <Box>
          <Text color="redBright">{'• '}</Text>
          <Text color="gray">{'signals'.padEnd(11)}</Text>
          <Text color="yellowBright">{finding.signals.map((signal) => formatSignalLabel(signal.type)).join(' · ')}</Text>
        </Box>
      </Box>
    </Box>
  )
}

function RiskBadge({ level }: { level: RiskLevel }): React.JSX.Element {
  const color = riskColor(level)

  return (
    <Box
      borderStyle="round"
      borderColor={color}
      paddingX={1}
      marginLeft={1}
    >
      <Text color={color}>
        {level === 'critical' ? ' suspicious ' : ` ${riskLabel(level)} `}
      </Text>
    </Box>
  )
}

function RiskBar({
  score,
  level,
}: {
  score: number
  level: RiskLevel
}): React.JSX.Element {
  const total = 28
  const filled = Math.max(0, Math.min(total, Math.round(score * total)))
  const empty = Math.max(0, total - filled)
  const low = Math.min(filled, Math.floor(total * 0.33))
  const medium = Math.min(Math.max(filled - low, 0), Math.floor(total * 0.34))
  const high = Math.max(filled - low - medium, 0)

  return (
    <Text>
      <Text color="greenBright">{'█'.repeat(low)}</Text>
      <Text color="yellowBright">{'█'.repeat(medium)}</Text>
      <Text color="redBright">{'█'.repeat(high)}</Text>
      <Text color="#2c3243">{'█'.repeat(empty)}</Text>
    </Text>
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

function StatusChip({
  label,
  color,
}: {
  label: string
  color: string
}): React.JSX.Element {
  return (
    <Box borderStyle="round" borderColor="blue" paddingX={1} marginRight={1}>
      <Text color="blueBright">{label}</Text>
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

function collectSignals(node: PackageNode): RiskSignal[] {
  return [node.signals, ...node.dependencies.map(collectSignals)].flat()
}

function getMaxDepth(node: PackageNode): number {
  return Math.max(node.depth, ...node.dependencies.map(getMaxDepth), 0)
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
  switch (level) {
    case 'critical':
      return 'suspicious'
    case 'review':
      return 'review'
    default:
      return 'safe'
  }
}

function formatOverallRiskLabel(level: RiskLevel): string {
  switch (level) {
    case 'critical':
      return 'HIGH'
    case 'review':
      return 'MEDIUM'
    default:
      return 'LOW'
  }
}

function formatSignalLabel(type: string): string {
  switch (type) {
    case 'security_tombstone':
      return 'security tombstone'
    case 'new_and_unproven':
      return 'zero provenance'
    case 'new_package_age':
      return 'new publisher'
    case 'zero_downloads':
      return 'zero downloads'
    case 'deprecated_package':
      return 'deprecated package'
    default:
      return type.replaceAll('_', ' ')
  }
}

function formatAge(days: number): string {
  if (days === 0) {
    return 'today'
  }

  if (days === 1) {
    return '1 day old'
  }

  return `${days.toLocaleString()} days old`
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

function deriveSignalTags(result: ScanResult, signals: RiskSignal[]): string[] {
  const tags = new Set<string>()

  if (result.findings.some((finding) => finding.depth === 1)) {
    tags.add('depth-1 threat')
  }

  for (const signal of signals) {
    tags.add(formatSignalLabel(signal.type))
  }

  return Array.from(tags).slice(0, 6)
}

export async function renderInk(result: ScanResult): Promise<void> {
  const app = render(<ScanResultView result={result} />)
  await app.waitUntilExit()
}
