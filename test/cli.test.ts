import assert from 'node:assert/strict'
import test from 'node:test'

import { run } from '../src/cli/index.js'
import { NetworkFailureError } from '../src/domain/errors.js'
import type { ScanResult } from '../src/domain/entities.js'

class MemoryStream {
  buffer = ''

  write(text: string): void {
    this.buffer += text
  }
}

function createResult(suspiciousCount = 0): ScanResult {
  return {
    scan_target: 'root',
    requested_depth: 3,
    threshold: 0.4,
    root: {
      name: 'root',
      version: '1.0.0',
      key: 'root@1.0.0',
      depth: 0,
      age_days: 10,
      weekly_downloads: 1000,
      dependents_count: null,
      deprecated_message: null,
      is_security_tombstone: false,
      published_at: '2026-03-01T00:00:00.000Z',
      first_published: '2026-01-01T00:00:00.000Z',
      last_published: '2026-03-01T00:00:00.000Z',
      total_versions: 3,
      dependency_count: 1,
      publish_events_last_30_days: 1,
      has_advisories: false,
      dependents_count: null,
      risk_score: suspiciousCount > 0 ? 0.8 : 0.1,
      risk_level: suspiciousCount > 0 ? 'critical' : 'safe',
      signals: [],
      recommendation: suspiciousCount > 0 ? 'do_not_install' : 'install',
      dependencies: [],
    },
    findings:
      suspiciousCount > 0
        ? [
            {
              key: 'root@1.0.0',
              name: 'root',
              version: '1.0.0',
              depth: 0,
              path: {
                packages: [{ name: 'root', version: '1.0.0' }],
              },
              risk_score: 0.8,
              risk_level: 'critical',
              recommendation: 'do_not_install',
              signals: [],
              explanation: 'test',
            },
          ]
        : [],
    total_scanned: 1,
    suspicious_count: suspiciousCount,
    safe_count: suspiciousCount > 0 ? 0 : 1,
    overall_risk_score: suspiciousCount > 0 ? 0.8 : 0.1,
    overall_risk_level: suspiciousCount > 0 ? 'critical' : 'safe',
    scan_duration_ms: 0,
    timestamp: '2026-04-01T00:00:00.000Z',
  }
}

test('CLI uses plain text renderer for --no-tui and returns suspicious exit code', async () => {
  const stdout = new MemoryStream()
  const stderr = new MemoryStream()
  let inkCalls = 0
  let plainCalls = 0

  const exitCode = await run(['scan', 'root', '--no-tui'], {
    scanPackage: async () => createResult(1),
    renderJson: () => {
      throw new Error('JSON renderer should not be used.')
    },
    renderPlainText: () => {
      plainCalls += 1
      return 'plain text output'
    },
    renderInk: async () => {
      inkCalls += 1
    },
    stdout,
    stderr,
    isTty: true,
  })

  assert.equal(exitCode, 1)
  assert.equal(plainCalls, 1)
  assert.equal(inkCalls, 0)
  assert.match(stdout.buffer, /plain text output/)
  assert.equal(stderr.buffer, '')
})

test('CLI returns invalid usage exit code for malformed arguments', async () => {
  const stdout = new MemoryStream()
  const stderr = new MemoryStream()

  const exitCode = await run(['scan'], {
    scanPackage: async () => createResult(),
    renderJson: () => '',
    renderPlainText: () => '',
    renderInk: async () => {},
    stdout,
    stderr,
    isTty: true,
  })

  assert.equal(exitCode, 2)
})

test('CLI maps network failures to exit code 3', async () => {
  const stdout = new MemoryStream()
  const stderr = new MemoryStream()

  const exitCode = await run(['scan', 'root', '--json'], {
    scanPackage: async () => {
      throw new NetworkFailureError('registry down')
    },
    renderJson: () => JSON.stringify(createResult()),
    renderPlainText: () => '',
    renderInk: async () => {},
    stdout,
    stderr,
    isTty: true,
  })

  assert.equal(exitCode, 3)
  assert.match(stderr.buffer, /registry down/)
})
