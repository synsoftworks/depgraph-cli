import assert from 'node:assert/strict'
import test from 'node:test'

import { createFieldReliabilityReport } from '../src/domain/field-reliability-policy.js'
import type { ScanResult } from '../src/domain/entities.js'
import { renderPlainText } from '../src/interface/plain-text-renderer.js'

test('plain text renderer adds a user-facing summary block after overall risk', () => {
  const output = renderPlainText(createResult())

  assert.match(
    output,
    /Overall risk: critical \(0\.81\)\n\nSummary:\n- Packages scanned: 3\n- Packages requiring review: 2\n- Findings with security-related signals: 1\n- Packages that appear safe: 1/,
  )
  assert.match(output, /Warnings: 1\n\nWarnings:/)
  assert.match(output, /Changed dependencies:/)
  assert.match(output, /Priority findings:/)
  assert.match(output, /Routine findings:/)
  assert.match(output, /Dependency tree:/)
})

test('plain text renderer surfaces security-related findings before routine findings', () => {
  const output = renderPlainText(createResult())
  const securityIndex = output.indexOf('- vulnerable-child@2.0.0 [critical 0.81]')
  const routineIndex = output.indexOf('- noisy-child@1.1.0 [review 0.52]')

  assert.ok(securityIndex > -1)
  assert.ok(routineIndex > -1)
  assert.ok(securityIndex < routineIndex)
})

test('plain text renderer collapses duplicate deprecation and security language into one user-facing reason', () => {
  const output = renderPlainText(createResult())

  assert.match(
    output,
    /- deprecated due to a security vulnerability \(CVE-2025-66478 referenced\)/,
  )
  assert.doesNotMatch(output, /package is deprecated: This version has a security vulnerability/i)
  assert.doesNotMatch(output, /deprecation message contains security-related language/i)
})

test('plain text renderer does not include internal mode or policy language', () => {
  const output = renderPlainText(createUnresolvedNoFindingResult())

  assert.doesNotMatch(output, /Mode:/)
  assert.doesNotMatch(output, /Field reliability policy/i)
  assert.doesNotMatch(output, /ADR-012/)
  assert.doesNotMatch(output, /below the configured threshold/)
  assert.match(output, /Summary:\n- Packages scanned: 2\n- Packages requiring review: 0\n- Findings with security-related signals: 0\n- Packages that appear safe: 2/)
  assert.match(output, /Packages that appear safe: 2/)
  assert.match(output, /Warnings: 1\n\nWarnings:/)
  assert.match(output, /Routine findings:\n- none/)
})

test('plain text renderer omits the warnings section when there are no warnings', () => {
  const result = createResult()
  result.warnings = []
  const output = renderPlainText(result)

  assert.match(output, /Warnings: 0/)
  assert.doesNotMatch(output, /\nWarnings:\n- none/)
})

test('plain text renderer does not mutate finding explanations or signals', () => {
  const result = createResult()
  const before = JSON.parse(JSON.stringify(result))

  renderPlainText(result)

  assert.deepEqual(result.findings, before.findings)
  assert.deepEqual(result.root, before.root)
})

function createResult(): ScanResult {
  return {
    record_id: '2026-04-01T00:00:00.000Z:root@1.0.0:depth=3',
    scan_mode: 'registry_package',
    scan_target: 'root',
    baseline_record_id: 'baseline-record',
    requested_depth: 3,
    threshold: 0.4,
    field_reliability: createFieldReliabilityReport(),
    root: {
      name: 'root',
      version: '1.0.0',
      key: 'root@1.0.0',
      depth: 0,
      is_project_root: false,
      metadata_status: 'enriched',
      metadata_warning: null,
      lockfile_resolved_url: null,
      lockfile_integrity: null,
      age_days: 10,
      weekly_downloads: 1000,
      dependents_count: null,
      deprecated_message: null,
      is_security_tombstone: false,
      published_at: '2026-03-01T00:00:00.000Z',
      first_published: '2026-01-01T00:00:00.000Z',
      last_published: '2026-03-01T00:00:00.000Z',
      total_versions: 3,
      dependency_count: 2,
      publish_events_last_30_days: 1,
      has_advisories: false,
      risk_score: 0.81,
      risk_level: 'critical',
      signals: [
        {
          type: 'new_direct_dependency_edge',
          value: 'root@1.0.0->vulnerable-child@2.0.0',
          weight: 'high',
          reason: 'new direct dependency edge root@1.0.0 -> vulnerable-child@2.0.0',
        },
      ],
      recommendation: 'review',
      dependencies: [
        {
          name: 'vulnerable-child',
          version: '2.0.0',
          key: 'vulnerable-child@2.0.0',
          depth: 1,
          is_project_root: false,
          metadata_status: 'enriched',
          metadata_warning: null,
          lockfile_resolved_url: null,
          lockfile_integrity: null,
          age_days: 90,
          weekly_downloads: 125,
          dependents_count: 2,
          deprecated_message:
            'This version has a security vulnerability. Please upgrade. See CVE-2025-66478.',
          is_security_tombstone: false,
          published_at: '2026-01-01T00:00:00.000Z',
          first_published: '2025-01-01T00:00:00.000Z',
          last_published: '2026-01-01T00:00:00.000Z',
          total_versions: 4,
          dependency_count: 0,
          publish_events_last_30_days: 0,
          has_advisories: false,
          risk_score: 0.81,
          risk_level: 'critical',
          signals: [
            {
              type: 'deprecated_package',
              value:
                'This version has a security vulnerability. Please upgrade. See CVE-2025-66478.',
              weight: 'medium',
              reason:
                'package is deprecated: This version has a security vulnerability. Please upgrade. See CVE-2025-66478.',
            },
            {
              type: 'security_deprecation_language',
              value:
                'This version has a security vulnerability. Please upgrade. See CVE-2025-66478.',
              weight: 'high',
              reason: 'deprecation message contains security-related language',
            },
          ],
          recommendation: 'do_not_install',
          dependencies: [],
        },
        {
          name: 'noisy-child',
          version: '1.1.0',
          key: 'noisy-child@1.1.0',
          depth: 1,
          is_project_root: false,
          metadata_status: 'enriched',
          metadata_warning: null,
          lockfile_resolved_url: null,
          lockfile_integrity: null,
          age_days: 2,
          weekly_downloads: 0,
          dependents_count: null,
          deprecated_message: null,
          is_security_tombstone: false,
          published_at: '2026-03-30T00:00:00.000Z',
          first_published: '2026-03-30T00:00:00.000Z',
          last_published: '2026-03-30T00:00:00.000Z',
          total_versions: 1,
          dependency_count: 0,
          publish_events_last_30_days: 3,
          has_advisories: false,
          risk_score: 0.52,
          risk_level: 'review',
          signals: [
            {
              type: 'new_package_age',
              value: 2,
              weight: 'high',
              reason: 'package was published 2 day(s) ago',
            },
            {
              type: 'low_version_history',
              value: 1,
              weight: 'medium',
              reason: 'package has only 1 published version(s)',
            },
            {
              type: 'zero_downloads',
              value: 0,
              weight: 'high',
              reason: 'package has never been downloaded — no ecosystem adoption',
            },
            {
              type: 'rapid_publish_churn',
              value: 3,
              weight: 'medium',
              reason: '3 version publish events happened in the last 30 days',
            },
          ],
          recommendation: 'review',
          dependencies: [],
        },
      ],
    },
    edge_findings: [
      {
        parent_key: 'root@1.0.0',
        child_key: 'vulnerable-child@2.0.0',
        path: ['root@1.0.0', 'vulnerable-child@2.0.0'],
        depth: 1,
        edge_type: 'direct',
        review_target: {
          kind: 'edge_finding',
          record_id: '2026-04-01T00:00:00.000Z:root@1.0.0:depth=3',
          target_id: 'edge_finding:direct:root@1.0.0->vulnerable-child@2.0.0',
          edge_finding_key: 'edge_finding:direct:root@1.0.0->vulnerable-child@2.0.0',
          parent_key: 'root@1.0.0',
          child_key: 'vulnerable-child@2.0.0',
          edge_type: 'direct',
        },
        baseline_record_id: 'baseline-record',
        baseline_identity: {
          scan_mode: 'registry_package',
          scan_target: 'root',
          requested_depth: 3,
          workspace_identity: '/tmp/workspace',
        },
        reason:
          'new direct dependency edge root@1.0.0 -> vulnerable-child@2.0.0 via root@1.0.0 > vulnerable-child@2.0.0 compared with baseline 2026-03-31T00:00:00.000Z',
        recommendation: 'review',
      },
    ],
    findings: [
      {
        key: 'noisy-child@1.1.0',
        name: 'noisy-child',
        version: '1.1.0',
        depth: 1,
        review_target: {
          kind: 'package_finding',
          record_id: '2026-04-01T00:00:00.000Z:root@1.0.0:depth=3',
          target_id: 'package_finding:noisy-child@1.1.0',
          finding_key: 'package_finding:noisy-child@1.1.0',
          package_key: 'noisy-child@1.1.0',
        },
        path: {
          packages: [
            { name: 'root', version: '1.0.0' },
            { name: 'noisy-child', version: '1.1.0' },
          ],
        },
        risk_score: 0.52,
        risk_level: 'review',
        recommendation: 'review',
        signals: [
          {
            type: 'new_package_age',
            value: 2,
            weight: 'high',
            reason: 'package was published 2 day(s) ago',
          },
          {
            type: 'low_version_history',
            value: 1,
            weight: 'medium',
            reason: 'package has only 1 published version(s)',
          },
          {
            type: 'zero_downloads',
            value: 0,
            weight: 'high',
            reason: 'package has never been downloaded — no ecosystem adoption',
          },
          {
            type: 'rapid_publish_churn',
            value: 3,
            weight: 'medium',
            reason: '3 version publish events happened in the last 30 days',
          },
        ],
        explanation:
          'package was published 2 day(s) ago; package has only 1 published version(s); package has never been downloaded — no ecosystem adoption; 3 version publish events happened in the last 30 days',
      },
      {
        key: 'vulnerable-child@2.0.0',
        name: 'vulnerable-child',
        version: '2.0.0',
        depth: 1,
        review_target: {
          kind: 'package_finding',
          record_id: '2026-04-01T00:00:00.000Z:root@1.0.0:depth=3',
          target_id: 'package_finding:vulnerable-child@2.0.0',
          finding_key: 'package_finding:vulnerable-child@2.0.0',
          package_key: 'vulnerable-child@2.0.0',
        },
        path: {
          packages: [
            { name: 'root', version: '1.0.0' },
            { name: 'vulnerable-child', version: '2.0.0' },
          ],
        },
        risk_score: 0.81,
        risk_level: 'critical',
        recommendation: 'do_not_install',
        signals: [
          {
            type: 'deprecated_package',
            value:
              'This version has a security vulnerability. Please upgrade. See CVE-2025-66478.',
            weight: 'medium',
            reason:
              'package is deprecated: This version has a security vulnerability. Please upgrade. See CVE-2025-66478.',
          },
          {
            type: 'security_deprecation_language',
            value:
              'This version has a security vulnerability. Please upgrade. See CVE-2025-66478.',
            weight: 'high',
            reason: 'deprecation message contains security-related language',
          },
        ],
        explanation:
          'package is deprecated: This version has a security vulnerability. Please upgrade. See CVE-2025-66478.; deprecation message contains security-related language',
      },
    ],
    total_scanned: 3,
    suspicious_count: 2,
    safe_count: 1,
    overall_risk_score: 0.81,
    overall_risk_level: 'critical',
    warnings: [
      {
        kind: 'unresolved_registry_lookup',
        package_key: 'root@1.0.0',
        package_name: 'root',
        package_version: '1.0.0',
        message: 'Registry metadata unavailable',
        lockfile_resolved_url: 'https://vendor.example/root.tgz',
        lockfile_integrity: null,
      },
    ],
    scan_duration_ms: 0,
    timestamp: '2026-04-01T00:00:00.000Z',
  }
}

function createUnresolvedNoFindingResult(): ScanResult {
  return {
    record_id: '2026-04-01T00:00:00.000Z:project@1.0.0:depth=3',
    scan_mode: 'package_lock',
    scan_target: 'project',
    baseline_record_id: null,
    requested_depth: 3,
    threshold: 0.4,
    field_reliability: createFieldReliabilityReport(),
    root: {
      name: 'project',
      version: '1.0.0',
      key: 'project@1.0.0',
      depth: 0,
      is_project_root: true,
      metadata_status: 'synthetic_project_root',
      metadata_warning: null,
      lockfile_resolved_url: null,
      lockfile_integrity: null,
      age_days: null,
      weekly_downloads: null,
      dependents_count: null,
      deprecated_message: null,
      is_security_tombstone: false,
      published_at: null,
      first_published: null,
      last_published: null,
      total_versions: null,
      dependency_count: 1,
      publish_events_last_30_days: null,
      has_advisories: false,
      risk_score: 0,
      risk_level: 'safe',
      signals: [],
      recommendation: 'install',
      dependencies: [
        {
          name: '@gsap/simply',
          version: '3.13.0',
          key: '@gsap/simply@3.13.0',
          depth: 1,
          is_project_root: false,
          metadata_status: 'unresolved_registry_lookup',
          metadata_warning: 'Registry metadata unavailable',
          lockfile_resolved_url: 'https://vendor.example/@gsap/simply/-/simply-3.13.0.tgz',
          lockfile_integrity: 'sha512-example',
          age_days: null,
          weekly_downloads: null,
          dependents_count: null,
          deprecated_message: null,
          is_security_tombstone: false,
          published_at: null,
          first_published: null,
          last_published: null,
          total_versions: null,
          dependency_count: 0,
          publish_events_last_30_days: null,
          has_advisories: false,
          risk_score: 0.08,
          risk_level: 'safe',
          signals: [
            {
              type: 'unresolved_registry_lookup',
              value: '@gsap/simply@3.13.0',
              weight: 'low',
              reason: 'Registry metadata unavailable',
            },
          ],
          recommendation: 'install',
          dependencies: [],
        },
      ],
    },
    edge_findings: [],
    findings: [],
    total_scanned: 2,
    suspicious_count: 0,
    safe_count: 2,
    overall_risk_score: 0.08,
    overall_risk_level: 'safe',
    warnings: [
      {
        kind: 'unresolved_registry_lookup',
        package_key: '@gsap/simply@3.13.0',
        package_name: '@gsap/simply',
        package_version: '3.13.0',
        message: 'Registry metadata unavailable',
        lockfile_resolved_url: 'https://vendor.example/@gsap/simply/-/simply-3.13.0.tgz',
        lockfile_integrity: 'sha512-example',
      },
    ],
    scan_duration_ms: 0,
    timestamp: '2026-04-01T00:00:00.000Z',
  }
}
