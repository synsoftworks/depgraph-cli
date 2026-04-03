import assert from 'node:assert/strict'
import { mkdtemp, writeFile } from 'node:fs/promises'
import { join } from 'node:path'
import { tmpdir } from 'node:os'
import test from 'node:test'

import { PackageLockDependencyTraverser } from '../src/adapters/package-lock-dependency-traverser.js'
import type { PackageMetadata, PackageSpec } from '../src/domain/contracts.js'
import type { PackageMetadataSource } from '../src/domain/ports.js'

class StubPackageMetadataSource implements PackageMetadataSource {
  constructor(private readonly metadataByKey: Record<string, PackageMetadata>) {}

  async resolvePackage(spec: PackageSpec): Promise<PackageMetadata> {
    const key = `${spec.name}@${spec.version_range ?? 'latest'}`
    const metadata = this.metadataByKey[key]

    assert.ok(metadata, `Missing metadata for ${key}`)

    return metadata
  }
}

test('package-lock traverser reads package-lock.json and resolves hoisted dependency paths from the lockfile structure', async () => {
  const workingDirectory = await mkdtemp(join(tmpdir(), 'depgraph-package-lock-'))
  const packageLockPath = join(workingDirectory, 'package-lock.json')

  await writeFile(
    packageLockPath,
    JSON.stringify({
      name: 'example-project',
      version: '1.0.0',
      lockfileVersion: 3,
      packages: {
        '': {
          name: 'example-project',
          version: '1.0.0',
          dependencies: {
            alpha: '^1.0.0',
            delta: '^1.0.0',
          },
        },
        'node_modules/alpha': {
          version: '1.0.0',
          dependencies: {
            beta: '^1.0.0',
          },
        },
        'node_modules/beta': {
          version: '1.0.0',
        },
        'node_modules/delta': {
          version: '1.0.0',
          dependencies: {
            beta: '^1.0.0',
          },
        },
      },
    }),
    'utf8',
  )

  const traverser = new PackageLockDependencyTraverser(
    new StubPackageMetadataSource({
      'alpha@1.0.0': createMetadata('alpha', '1.0.0', { beta: '1.0.0' }),
      'beta@1.0.0': createMetadata('beta', '1.0.0'),
      'delta@1.0.0': createMetadata('delta', '1.0.0', { beta: '1.0.0' }),
    }),
  )

  const graph = await traverser.traverse(packageLockPath, 3)

  assert.equal(graph.root_key, 'example-project@1.0.0')
  assert.equal(graph.nodes[0]?.is_virtual_root, true)
  assert.deepEqual(
    graph.nodes.map((node) => ({
      key: node.key,
      depth: node.depth,
      parent_key: node.parent_key,
      path: node.path.packages.map((pkg) => `${pkg.name}@${pkg.version}`),
    })),
    [
      {
        key: 'example-project@1.0.0',
        depth: 0,
        parent_key: null,
        path: ['example-project@1.0.0'],
      },
      {
        key: 'alpha@1.0.0',
        depth: 1,
        parent_key: 'example-project@1.0.0',
        path: ['example-project@1.0.0', 'alpha@1.0.0'],
      },
      {
        key: 'delta@1.0.0',
        depth: 1,
        parent_key: 'example-project@1.0.0',
        path: ['example-project@1.0.0', 'delta@1.0.0'],
      },
      {
        key: 'beta@1.0.0',
        depth: 2,
        parent_key: 'alpha@1.0.0',
        path: ['example-project@1.0.0', 'alpha@1.0.0', 'beta@1.0.0'],
      },
    ],
  )
})

test('package-lock traverser rejects unsupported lockfile versions without a packages map', async () => {
  const workingDirectory = await mkdtemp(join(tmpdir(), 'depgraph-package-lock-'))
  const packageLockPath = join(workingDirectory, 'package-lock.json')

  await writeFile(
    packageLockPath,
    JSON.stringify({
      name: 'legacy-project',
      version: '1.0.0',
      lockfileVersion: 1,
      dependencies: {},
    }),
    'utf8',
  )

  const traverser = new PackageLockDependencyTraverser(new StubPackageMetadataSource({}))

  await assert.rejects(
    () => traverser.traverse(packageLockPath, 3),
    /lockfileVersion 2 or newer/,
  )
})

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
    weekly_downloads: 1000,
    deprecated_message: null,
    is_security_tombstone: false,
    has_advisories: false,
    dependents_count: null,
  }
}
