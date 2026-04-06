import assert from 'node:assert/strict'
import { mkdir, mkdtemp, writeFile } from 'node:fs/promises'
import { join } from 'node:path'
import { tmpdir } from 'node:os'
import test from 'node:test'

import { parsePnpmLockfile } from '../src/adapters/parsers/pnpm-lockfile-parser.js'

test('pnpm parser selects the correct importer and normalizes package snapshots', async () => {
  const workspaceRoot = await mkdtemp(join(tmpdir(), 'depgraph-pnpm-parser-'))
  const projectRoot = join(workspaceRoot, 'packages', 'app')
  await mkdir(projectRoot, {
    recursive: true,
  })
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
      'packages:',
      '  alpha@1.0.0:',
      '    resolution:',
      '      integrity: sha512-alpha',
      '      tarball: https://registry.npmjs.org/alpha/-/alpha-1.0.0.tgz',
      '    dependencies:',
      '      beta: 1.0.0',
      '  beta@1.0.0(peer@2.0.0):',
      '    resolution:',
      '      integrity: sha512-beta',
    ].join('\n'),
    'utf8',
  )
  await writeFile(
    join(projectRoot, 'package.json'),
    JSON.stringify({ name: 'app', version: '1.0.0' }),
    'utf8',
  )

  const project = parsePnpmLockfile(join(workspaceRoot, 'pnpm-lock.yaml'), projectRoot)
  const alpha = project.resolve_root_dependency('alpha')
  const beta = alpha === null ? null : project.resolve_entry_dependency(alpha, 'beta')

  assert.deepEqual(project.root_package, {
    name: 'app',
    version: '1.0.0',
  })
  assert.deepEqual(project.root_dependencies, {
    alpha: '1.0.0',
  })
  assert.equal(alpha?.entry_id, 'alpha@1.0.0')
  assert.equal(alpha?.resolved, 'https://registry.npmjs.org/alpha/-/alpha-1.0.0.tgz')
  assert.equal(beta?.name, 'beta')
  assert.equal(beta?.version, '1.0.0')
})

test('pnpm parser rejects local workspace dependency references it cannot project honestly', async () => {
  const workspaceRoot = await mkdtemp(join(tmpdir(), 'depgraph-pnpm-parser-'))
  const projectRoot = join(workspaceRoot, 'packages', 'app')
  await mkdir(projectRoot, {
    recursive: true,
  })
  await writeFile(
    join(workspaceRoot, 'pnpm-lock.yaml'),
    [
      'lockfileVersion: "9.0"',
      'importers:',
      '  packages/app:',
      '    dependencies:',
      '      lib:',
      '        specifier: workspace:*',
      '        version: link:../lib',
    ].join('\n'),
    'utf8',
  )
  await writeFile(
    join(projectRoot, 'package.json'),
    JSON.stringify({ name: 'app', version: '1.0.0' }),
    'utf8',
  )

  assert.throws(
    () => parsePnpmLockfile(join(workspaceRoot, 'pnpm-lock.yaml'), projectRoot),
    /contains local dependency "lib" \(link:\.\.\/lib\), which DepGraph does not project yet/,
  )
})
