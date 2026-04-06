import assert from 'node:assert/strict'
import { mkdir, mkdtemp, writeFile } from 'node:fs/promises'
import { join } from 'node:path'
import { tmpdir } from 'node:os'
import test from 'node:test'

import { PnpmLockDependencyTraverser } from '../src/adapters/pnpm-lock-dependency-traverser.js'
import type { PackageMetadata, PackageSpec } from '../src/domain/contracts.js'
import { NetworkFailureError } from '../src/domain/errors.js'
import type { PackageMetadataSource } from '../src/domain/ports.js'

class StubPackageMetadataSource implements PackageMetadataSource {
  constructor(
    private readonly metadataByKey: Record<string, PackageMetadata>,
    private readonly missingKeys: string[] = [],
  ) {}

  async resolvePackage(spec: PackageSpec): Promise<PackageMetadata> {
    const key = `${spec.name}@${spec.version_range ?? 'latest'}`

    if (this.missingKeys.includes(key)) {
      throw new NetworkFailureError(`Package "${spec.name}" was not found in the npm registry.`)
    }

    const metadata = this.metadataByKey[key]

    assert.ok(metadata, `Missing metadata for ${key}`)

    return metadata
  }
}

test('pnpm traverser reads pnpm-lock.yaml and preserves first-seen BFS projection paths', async () => {
  const workspaceRoot = await mkdtemp(join(tmpdir(), 'depgraph-pnpm-lock-'))
  const projectRoot = join(workspaceRoot, 'packages', 'app')
  await mkdir(projectRoot, {
    recursive: true,
  })
  await writeFile(
    join(projectRoot, 'package.json'),
    JSON.stringify({ name: 'app', version: '1.0.0' }),
    'utf8',
  )
  await writeFile(
    join(workspaceRoot, 'pnpm-lock.yaml'),
    [
      'lockfileVersion: "9.0"',
      'importers:',
      '  .: {}',
      '  packages/app:',
      '    dependencies:',
      '      alpha:',
      '        specifier: ^1.0.0',
      '        version: 1.0.0',
      '      delta:',
      '        specifier: ^1.0.0',
      '        version: 1.0.0',
      'packages:',
      '  alpha@1.0.0:',
      '    resolution:',
      '      integrity: sha512-alpha',
      '    dependencies:',
      '      beta: 1.0.0',
      '  beta@1.0.0:',
      '    resolution:',
      '      integrity: sha512-beta',
      '  delta@1.0.0:',
      '    resolution:',
      '      integrity: sha512-delta',
      '    dependencies:',
      '      beta: 1.0.0',
    ].join('\n'),
    'utf8',
  )

  const traverser = new PnpmLockDependencyTraverser(
    new StubPackageMetadataSource({
      'alpha@1.0.0': createMetadata('alpha', '1.0.0', { beta: '1.0.0' }),
      'beta@1.0.0': createMetadata('beta', '1.0.0'),
      'delta@1.0.0': createMetadata('delta', '1.0.0', { beta: '1.0.0' }),
    }),
  )

  const graph = await traverser.traverse(join(workspaceRoot, 'pnpm-lock.yaml'), projectRoot, 3)

  assert.equal(graph.root_key, 'app@1.0.0')
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
        key: 'app@1.0.0',
        depth: 0,
        parent_key: null,
        path: ['app@1.0.0'],
      },
      {
        key: 'alpha@1.0.0',
        depth: 1,
        parent_key: 'app@1.0.0',
        path: ['app@1.0.0', 'alpha@1.0.0'],
      },
      {
        key: 'delta@1.0.0',
        depth: 1,
        parent_key: 'app@1.0.0',
        path: ['app@1.0.0', 'delta@1.0.0'],
      },
      {
        key: 'beta@1.0.0',
        depth: 2,
        parent_key: 'alpha@1.0.0',
        path: ['app@1.0.0', 'alpha@1.0.0', 'beta@1.0.0'],
      },
    ],
  )
})

test('pnpm traverser preserves unresolved registry lookups honestly', async () => {
  const projectRoot = await mkdtemp(join(tmpdir(), 'depgraph-pnpm-lock-'))
  await writeFile(
    join(projectRoot, 'package.json'),
    JSON.stringify({ name: 'app', version: '1.0.0' }),
    'utf8',
  )
  await writeFile(
    join(projectRoot, 'pnpm-lock.yaml'),
    [
      'lockfileVersion: "9.0"',
      'importers:',
      '  .:',
      '    dependencies:',
      '      alpha:',
      '        specifier: ^1.0.0',
      '        version: 1.0.0',
      'packages:',
      '  alpha@1.0.0:',
      '    resolution:',
      '      integrity: sha512-alpha',
      '      tarball: https://registry.npmjs.org/alpha/-/alpha-1.0.0.tgz',
    ].join('\n'),
    'utf8',
  )

  const traverser = new PnpmLockDependencyTraverser(
    new StubPackageMetadataSource({}, ['alpha@1.0.0']),
  )

  const graph = await traverser.traverse(join(projectRoot, 'pnpm-lock.yaml'), projectRoot, 3)
  const unresolvedNode = graph.nodes.find((node) => node.key === 'alpha@1.0.0')

  assert.ok(unresolvedNode)
  assert.equal(unresolvedNode.metadata, null)
  assert.equal(unresolvedNode.metadata_status, 'unresolved_registry_lookup')
  assert.equal(
    unresolvedNode.lockfile_resolved_url,
    'https://registry.npmjs.org/alpha/-/alpha-1.0.0.tgz',
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
