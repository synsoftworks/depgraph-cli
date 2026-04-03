import assert from 'node:assert/strict'
import test from 'node:test'

import type { ScanResult } from '../src/domain/entities.js'
import { renderPlainText } from '../src/interface/plain-text-renderer.js'

test('plain text renderer surfaces changed edges from the current tree projection before package findings', () => {
  const output = renderPlainText(createResult())

  assert.match(output, /Mode: registry_package/)
  assert.match(output, /Target: root/)
  assert.match(output, /Warnings: 1/)
  assert.match(output, /root@1\.0\.0 \[unresolved_registry_lookup\] Registry metadata unavailable/)
  assert.match(output, /Changed edges in current tree view:/)
  assert.match(output, /root@1\.0\.0 -> child@1\.0\.0 \[direct\] via root@1\.0\.0 > child@1\.0\.0/)
  assert.match(output, /target: edge_finding:direct:root@1\.0\.0->child@1\.0\.0/)
  assert.match(output, /Findings:/)
})

test('plain text renderer surfaces warnings even when unresolved nodes do not produce findings', () => {
  const output = renderPlainText(createUnresolvedNoFindingResult())

  assert.match(output, /Warnings: 1/)
  assert.match(output, /Warnings:/)
  assert.match(output, /@gsap\/simply@3\.13\.0 \[unresolved_registry_lookup\] Registry metadata unavailable/)
  assert.match(output, /Findings:\n- none/)
  assert.match(output, /@gsap\/simply@3\.13\.0 \[registry metadata unavailable\] \[safe 0\.08\]/)
})

function createResult(): ScanResult {
  return {
    record_id: '2026-04-01T00:00:00.000Z:root@1.0.0:depth=3',
    scan_mode: 'registry_package',
    scan_target: 'root',
    baseline_record_id: 'baseline-record',
    requested_depth: 3,
    threshold: 0.4,
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
      dependency_count: 1,
      publish_events_last_30_days: 1,
      has_advisories: false,
      risk_score: 0.64,
      risk_level: 'review',
      signals: [
        {
          type: 'new_direct_dependency_edge',
          value: 'root@1.0.0->child@1.0.0',
          weight: 'high',
          reason: 'new direct dependency edge root@1.0.0 -> child@1.0.0',
        },
      ],
      recommendation: 'review',
      dependencies: [],
    },
    edge_findings: [
      {
        parent_key: 'root@1.0.0',
        child_key: 'child@1.0.0',
        path: ['root@1.0.0', 'child@1.0.0'],
        depth: 1,
        edge_type: 'direct',
        review_target: {
          kind: 'edge_finding',
          record_id: '2026-04-01T00:00:00.000Z:root@1.0.0:depth=3',
          target_id: 'edge_finding:direct:root@1.0.0->child@1.0.0',
          edge_finding_key: 'edge_finding:direct:root@1.0.0->child@1.0.0',
          parent_key: 'root@1.0.0',
          child_key: 'child@1.0.0',
          edge_type: 'direct',
        },
        baseline_record_id: 'baseline-record',
        baseline_identity: {
          scan_mode: 'registry_package',
          scan_target: 'root',
          requested_depth: 3,
          workspace_identity: '/tmp/workspace',
        },
        reason: 'new direct dependency edge root@1.0.0 -> child@1.0.0',
        recommendation: 'review',
      },
    ],
    findings: [],
    total_scanned: 1,
    suspicious_count: 1,
    safe_count: 0,
    overall_risk_score: 0.64,
    overall_risk_level: 'review',
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
