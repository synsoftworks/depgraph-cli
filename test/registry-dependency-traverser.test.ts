import assert from 'node:assert/strict'
import test from 'node:test'

import { RegistryDependencyTraverser } from '../src/adapters/registry-dependency-traverser.js'
import type { PackageMetadata, PackageSpec } from '../src/domain/contracts.js'
import type { PackageMetadataSource } from '../src/domain/ports.js'

class StubPackageMetadataSource implements PackageMetadataSource {
  constructor(private readonly metadataBySpec: Record<string, PackageMetadata>) {}

  async resolvePackage(spec: PackageSpec): Promise<PackageMetadata> {
    const key = spec.version_range === undefined ? spec.name : `${spec.name}@${spec.version_range}`
    const metadata = this.metadataBySpec[key]

    assert.ok(metadata, `Missing metadata for ${key}`)

    return metadata
  }
}

function createMetadata(
  name: string,
  version: string,
  dependencies: Record<string, string> = {},
): PackageMetadata {
  return {
    package: { name, version },
    dependencies,
    published_at: '2026-03-01T00:00:00.000Z',
    first_published_at: '2026-01-01T00:00:00.000Z',
    last_published_at: '2026-03-01T00:00:00.000Z',
    total_versions: 3,
    publish_events_last_30_days: 1,
    weekly_downloads: 5000,
    has_advisories: false,
    dependents_count: null,
  }
}

test('BFS traverser returns closest path first and respects visited keys', async () => {
  const traverser = new RegistryDependencyTraverser(
    new StubPackageMetadataSource({
      root: createMetadata('root', '1.0.0', {
        a: '^1.0.0',
        b: '^1.0.0',
      }),
      'a@^1.0.0': createMetadata('a', '1.0.0', {
        shared: '^1.0.0',
      }),
      'b@^1.0.0': createMetadata('b', '1.0.0', {
        shared: '^1.0.0',
      }),
      'shared@^1.0.0': createMetadata('shared', '1.0.0'),
    }),
  )

  const graph = await traverser.traverse({ name: 'root' }, 3)

  assert.equal(graph.root_key, 'root@1.0.0')
  assert.deepEqual(
    graph.nodes.map((node) => node.key),
    ['root@1.0.0', 'a@1.0.0', 'b@1.0.0', 'shared@1.0.0'],
  )

  const sharedNode = graph.nodes.at(-1)
  assert.equal(sharedNode?.parent_key, 'a@1.0.0')
  assert.deepEqual(
    sharedNode?.path.packages.map((pkg) => `${pkg.name}@${pkg.version}`),
    ['root@1.0.0', 'a@1.0.0', 'shared@1.0.0'],
  )
})

test('BFS traverser enforces max depth using resolved name@version keys', async () => {
  const traverser = new RegistryDependencyTraverser(
    new StubPackageMetadataSource({
      root: createMetadata('root', '1.0.0', {
        a: '^1.0.0',
      }),
      'a@^1.0.0': createMetadata('a', '1.0.0', {
        b: '^1.0.0',
      }),
      'b@^1.0.0': createMetadata('b', '1.0.0'),
    }),
  )

  const graph = await traverser.traverse({ name: 'root' }, 1)

  assert.deepEqual(
    graph.nodes.map((node) => ({
      key: node.key,
      depth: node.depth,
    })),
    [
      { key: 'root@1.0.0', depth: 0 },
      { key: 'a@1.0.0', depth: 1 },
    ],
  )
})
