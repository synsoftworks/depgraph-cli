import assert from 'node:assert/strict'
import test from 'node:test'

import {
  getPackageNodeMetadataFieldState,
  isObservedMetadataField,
  notApplicableMetadataFieldState,
  observedAbsentMetadataFieldState,
  observedPresentMetadataFieldState,
  unavailableMetadataFieldState,
} from '../src/domain/metadata-field-state.js'
import type { PackageNode } from '../src/domain/entities.js'

test('metadata field state treats dependents_count null as unavailable instead of observed data', () => {
  const state = getPackageNodeMetadataFieldState(createNode(), 'dependents_count')

  assert.deepEqual(state, unavailableMetadataFieldState('not_collected_yet'))
  assert.equal(isObservedMetadataField(state), false)
})

test('metadata field state preserves genuinely observed dependents_count values', () => {
  const state = getPackageNodeMetadataFieldState(
    createNode({
      dependents_count: 42,
    }),
    'dependents_count',
  )

  assert.deepEqual(state, observedPresentMetadataFieldState(42))
  assert.equal(isObservedMetadataField(state), true)
})

test('metadata field state treats has_advisories false as unavailable until advisories are collected', () => {
  const state = getPackageNodeMetadataFieldState(createNode(), 'has_advisories')

  assert.deepEqual(state, unavailableMetadataFieldState('not_collected_yet'))
  assert.equal(isObservedMetadataField(state), false)
})

test('metadata field state preserves genuinely observed advisory evidence when present', () => {
  const state = getPackageNodeMetadataFieldState(
    createNode({
      has_advisories: true,
    }),
    'has_advisories',
  )

  assert.deepEqual(state, observedPresentMetadataFieldState(true))
  assert.equal(isObservedMetadataField(state), true)
})

test('metadata field state marks synthetic project roots as not applicable', () => {
  const node = createNode({
    is_project_root: true,
    metadata_status: 'synthetic_project_root',
  })

  assert.deepEqual(
    getPackageNodeMetadataFieldState(node, 'dependents_count'),
    notApplicableMetadataFieldState(),
  )
  assert.deepEqual(
    getPackageNodeMetadataFieldState(node, 'has_advisories'),
    notApplicableMetadataFieldState(),
  )
})

test('metadata field state marks unresolved registry metadata as unavailable for ambiguous fields', () => {
  const node = createNode({
    metadata_status: 'unresolved_registry_lookup',
  })

  assert.deepEqual(
    getPackageNodeMetadataFieldState(node, 'dependents_count'),
    unavailableMetadataFieldState('registry_metadata_unavailable'),
  )
  assert.deepEqual(
    getPackageNodeMetadataFieldState(node, 'has_advisories'),
    unavailableMetadataFieldState('registry_metadata_unavailable'),
  )
})

test('metadata field state contract distinguishes observed absent from unavailable', () => {
  const observedAbsent = observedAbsentMetadataFieldState(false)
  const unavailable = unavailableMetadataFieldState<boolean>('not_collected_yet')

  assert.equal(isObservedMetadataField(observedAbsent), true)
  assert.equal(isObservedMetadataField(unavailable), false)
  assert.equal(observedAbsent.observation, 'observed_absent')
  assert.equal(unavailable.observation, 'unavailable')
})

function createNode(overrides: Partial<PackageNode> = {}): PackageNode {
  return {
    name: 'pkg',
    version: '1.0.0',
    key: 'pkg@1.0.0',
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
    published_at: '2026-04-01T00:00:00.000Z',
    first_published: '2026-04-01T00:00:00.000Z',
    last_published: '2026-04-01T00:00:00.000Z',
    total_versions: 2,
    dependency_count: 0,
    publish_events_last_30_days: 0,
    has_advisories: false,
    risk_score: 0,
    risk_level: 'safe',
    signals: [],
    recommendation: 'install',
    dependencies: [],
    ...overrides,
  }
}
