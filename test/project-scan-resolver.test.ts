import assert from 'node:assert/strict'
import { mkdtemp, writeFile } from 'node:fs/promises'
import { join } from 'node:path'
import { tmpdir } from 'node:os'
import test from 'node:test'

import {
  NodeProjectScanResolver,
  resolvePackageLockScan,
} from '../src/adapters/project-scan-resolver.js'

test('project scan resolver detects package-lock.json in a project root', async () => {
  const projectRoot = await mkdtemp(join(tmpdir(), 'depgraph-project-'))
  await writeFile(join(projectRoot, 'package-lock.json'), '{}', 'utf8')
  const resolver = new NodeProjectScanResolver()

  const resolved = await resolver.resolve(projectRoot)

  assert.deepEqual(resolved, {
    scan_mode: 'package_lock',
    package_lock_path: join(projectRoot, 'package-lock.json'),
    project_root: projectRoot,
  })
})

test('project scan resolver fails clearly when no supported lockfile exists', async () => {
  const projectRoot = await mkdtemp(join(tmpdir(), 'depgraph-project-'))
  const resolver = new NodeProjectScanResolver()

  await assert.rejects(
    () => resolver.resolve(projectRoot),
    /supports package-lock\.json only/,
  )
})

test('explicit package-lock resolution normalizes the lockfile path and project root', () => {
  const resolved = resolvePackageLockScan('./package-lock.json')

  assert.equal(resolved.scan_mode, 'package_lock')
  assert.match(resolved.package_lock_path, /package-lock\.json$/)
  assert.match(resolved.project_root, /depgraph-cli$/)
})
