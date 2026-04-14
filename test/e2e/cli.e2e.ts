import assert from 'node:assert/strict'
import { spawn } from 'node:child_process'
import { access, mkdtemp, readFile, writeFile } from 'node:fs/promises'
import { join, resolve } from 'node:path'
import { tmpdir } from 'node:os'
import test from 'node:test'

import type { ScanResult } from '../src/domain/entities.js'

const CLI_ENTRYPOINT = resolve(process.cwd(), 'dist/cli/index.js')

test('built CLI completes a package-lock project scan and degrades unresolved dependency metadata honestly', async () => {
  await assertBuiltCliExists()

  const projectRoot = await mkdtemp(join(tmpdir(), 'depgraph-e2e-'))
  const packageLockPath = join(projectRoot, 'package-lock.json')

  await writeFile(
    packageLockPath,
    JSON.stringify({
      name: 'depgraph-e2e-fixture',
      version: '1.0.0',
      lockfileVersion: 3,
      packages: {
        '': {
          name: 'depgraph-e2e-fixture',
          version: '1.0.0',
          dependencies: {
            '@depgraph/e2e-hermetic-alpha-9d3f0a5c': '^1.0.0',
          },
        },
        'node_modules/@depgraph/e2e-hermetic-alpha-9d3f0a5c': {
          version: '1.0.0',
          resolved: 'https://registry.example/@depgraph/e2e-hermetic-alpha-9d3f0a5c/-/alpha-1.0.0.tgz',
          integrity: 'sha512-alpha',
          dependencies: {
            '@depgraph/e2e-hermetic-beta-9d3f0a5c': '^1.0.0',
          },
        },
        'node_modules/@depgraph/e2e-hermetic-beta-9d3f0a5c': {
          version: '1.0.0',
          resolved: 'https://registry.example/@depgraph/e2e-hermetic-beta-9d3f0a5c/-/beta-1.0.0.tgz',
          integrity: 'sha512-beta',
        },
      },
    }),
    'utf8',
  )

  const command = await runCli(
    ['scan', '--package-lock', packageLockPath, '--json', '--depth', '2'],
    projectRoot,
  )

  assert.equal(command.exitCode, 0, command.stderr || 'expected successful scan exit code')
  assert.equal(command.stderr.trim(), '')

  const result = JSON.parse(command.stdout) as ScanResult

  assert.equal(result.scan_mode, 'package_lock')
  assert.equal(result.scan_target, 'depgraph-e2e-fixture')
  assert.equal(result.baseline_record_id, null)
  assert.equal(result.requested_depth, 2)
  assert.match(result.record_id, /depgraph-e2e-fixture@1\.0\.0:depth=2$/)
  assert.equal(result.root.key, 'depgraph-e2e-fixture@1.0.0')
  assert.equal(result.root.is_project_root, true)
  assert.equal(result.root.metadata_status, 'synthetic_project_root')
  assert.equal(result.root.metadata_warning, null)
  assert.equal(result.total_scanned, 3)
  assert.deepEqual(result.edge_findings, [])
  assert.equal(result.findings.length, 0)
  assert.equal(result.suspicious_count, 0)
  assert.equal(result.overall_risk_level, 'safe')
  assert.equal(result.root.dependencies.length, 1)
  assert.equal(result.root.dependencies[0]?.key, '@depgraph/e2e-hermetic-alpha-9d3f0a5c@1.0.0')
  assert.equal(result.root.dependencies[0]?.metadata_status, 'unresolved_registry_lookup')
  assert.equal(
    result.root.dependencies[0]?.lockfile_resolved_url,
    'https://registry.example/@depgraph/e2e-hermetic-alpha-9d3f0a5c/-/alpha-1.0.0.tgz',
  )
  assert.equal(result.root.dependencies[0]?.lockfile_integrity, 'sha512-alpha')
  assert.equal(
    result.root.dependencies[0]?.dependencies[0]?.key,
    '@depgraph/e2e-hermetic-beta-9d3f0a5c@1.0.0',
  )
  assert.equal(
    result.root.dependencies[0]?.dependencies[0]?.metadata_status,
    'unresolved_registry_lookup',
  )
  assert.equal(
    result.root.dependencies[0]?.dependencies[0]?.lockfile_resolved_url,
    'https://registry.example/@depgraph/e2e-hermetic-beta-9d3f0a5c/-/beta-1.0.0.tgz',
  )
  assert.ok(
    result.warnings.some((warning) => warning.kind === 'unresolved_registry_lookup'),
    'expected unresolved registry lookup warning(s) for hermetic fixture packages',
  )

  const scanHistoryPath = join(projectRoot, '.depgraph', 'scans.jsonl')
  const persistedHistory = await readFile(scanHistoryPath, 'utf8')
  const persistedLines = persistedHistory.trim().split('\n')
  const persistedRecord = JSON.parse(persistedLines[0] ?? '') as ScanResult & { scan_mode: string }

  assert.equal(persistedLines.length, 1)
  assert.equal(persistedRecord.scan_mode, 'package_lock')
  assert.equal(persistedRecord.scan_target, 'depgraph-e2e-fixture')
})

async function assertBuiltCliExists(): Promise<void> {
  try {
    await access(CLI_ENTRYPOINT)
  } catch {
    assert.fail(`Built CLI not found at ${CLI_ENTRYPOINT}. Run "pnpm run build" before "pnpm run test:e2e".`)
  }
}

async function runCli(
  args: string[],
  cwd: string,
): Promise<{ exitCode: number | null; stdout: string; stderr: string }> {
  return new Promise((resolvePromise, rejectPromise) => {
    const child = spawn(process.execPath, [CLI_ENTRYPOINT, ...args], {
      cwd,
      env: {
        ...process.env,
        CI: 'true',
        FORCE_COLOR: '0',
      },
      stdio: ['ignore', 'pipe', 'pipe'],
    })
    let stdout = ''
    let stderr = ''

    child.stdout.on('data', (chunk: Buffer | string) => {
      stdout += chunk.toString()
    })

    child.stderr.on('data', (chunk: Buffer | string) => {
      stderr += chunk.toString()
    })

    child.on('error', (error) => {
      rejectPromise(error)
    })

    child.on('close', (exitCode) => {
      resolvePromise({
        exitCode,
        stdout: stdout.trim(),
        stderr: stderr.trim(),
      })
    })
  })
}
