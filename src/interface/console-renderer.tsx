import React, { useEffect } from 'react'
import { Box, Text, render, useApp } from 'ink'

import type { PackageNode, ScanResult } from '../domain/entities.js'

function AutoExit(): React.JSX.Element | null {
  const { exit } = useApp()

  useEffect(() => {
    const timeout = setTimeout(() => exit(), 0)

    return () => clearTimeout(timeout)
  }, [exit])

  return null
}

function ScanResultView({ result }: { result: ScanResult }): React.JSX.Element {
  return (
    <Box flexDirection="column">
      <AutoExit />
      <Text color="cyan">{`Scan: ${result.root.key}`}</Text>
      <Text>{`Overall risk: ${result.overall_risk_level} (${result.overall_risk_score.toFixed(2)})`}</Text>
      <Text>{`Total scanned: ${result.total_scanned}`}</Text>
      <Text>{`Suspicious packages: ${result.suspicious_count}`}</Text>
      <Box flexDirection="column" marginTop={1}>
        <Text color="yellow">Findings</Text>
        {result.findings.length === 0 ? (
          <Text>- none</Text>
        ) : (
          result.findings.map((finding) => (
            <Box key={finding.key} flexDirection="column">
              <Text>{`- ${finding.key} [${finding.risk_level} ${finding.risk_score.toFixed(2)}]`}</Text>
              <Text color="gray">{`  via ${finding.path.packages
                .map((pkg) => `${pkg.name}@${pkg.version}`)
                .join(' > ')}`}</Text>
            </Box>
          ))
        )}
      </Box>
      <Box flexDirection="column" marginTop={1}>
        <Text color="green">Tree</Text>
        {renderTree(result.root).map((line) => (
          <Text key={line}>{line}</Text>
        ))}
      </Box>
    </Box>
  )
}

function renderTree(node: PackageNode, prefix = '', isLast = true): string[] {
  const connector = prefix.length === 0 ? '-' : isLast ? '└─' : '├─'
  const lines = [
    `${prefix}${connector} ${node.key} [${node.risk_level} ${node.risk_score.toFixed(2)}]`,
  ]
  const childPrefix = prefix.length === 0 ? '  ' : `${prefix}${isLast ? '  ' : '│ '}`

  node.dependencies.forEach((dependency, index) => {
    lines.push(...renderTree(dependency, childPrefix, index === node.dependencies.length - 1))
  })

  return lines
}

export async function renderInk(result: ScanResult): Promise<void> {
  const app = render(<ScanResultView result={result} />)
  await app.waitUntilExit()
}
