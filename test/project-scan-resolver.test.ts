import assert from 'node:assert/strict'
import { mkdir, mkdtemp, writeFile } from 'node:fs/promises'
import { join } from 'node:path'
import { tmpdir } from 'node:os'
import test from 'node:test'

import {
  NodeProjectScanResolver,
  resolvePackageLockScan,
  resolvePnpmLockScan,
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
    /supports package-lock\.json and pnpm-lock\.yaml/,
  )
})

test('project scan resolver detects pnpm-lock.yaml in a project root', async () => {
  const projectRoot = await mkdtemp(join(tmpdir(), 'depgraph-project-'))
  await writeFile(join(projectRoot, 'pnpm-lock.yaml'), 'lockfileVersion: "9.0"\nimporters:\n  .: {}\n', 'utf8')
  const resolver = new NodeProjectScanResolver()

  const resolved = await resolver.resolve(projectRoot)

  assert.deepEqual(resolved, {
    scan_mode: 'pnpm_lock',
    pnpm_lock_path: join(projectRoot, 'pnpm-lock.yaml'),
    project_root: projectRoot,
  })
})

test('project scan resolver detects shared pnpm-lock.yaml from a workspace package path', async () => {
  const workspaceRoot = await mkdtemp(join(tmpdir(), 'depgraph-project-'))
  const projectRoot = join(workspaceRoot, 'packages', 'app')
  await mkdir(projectRoot, {
    recursive: true,
  })
  await writeFile(
    join(workspaceRoot, 'pnpm-lock.yaml'),
    'lockfileVersion: "9.0"\nimporters:\n  packages/app: {}\n',
    'utf8',
  )
  await writeFile(join(projectRoot, 'package.json'), '{"name":"app","version":"1.0.0"}', 'utf8')
  const resolver = new NodeProjectScanResolver()

  const resolved = await resolver.resolve(projectRoot)

  assert.deepEqual(resolved, {
    scan_mode: 'pnpm_lock',
    pnpm_lock_path: join(workspaceRoot, 'pnpm-lock.yaml'),
    project_root: projectRoot,
  })
})

test('project scan resolver rejects ambiguous local lockfiles', async () => {
  const projectRoot = await mkdtemp(join(tmpdir(), 'depgraph-project-'))
  await writeFile(join(projectRoot, 'package-lock.json'), '{}', 'utf8')
  await writeFile(join(projectRoot, 'pnpm-lock.yaml'), 'lockfileVersion: "9.0"\nimporters:\n  .: {}\n', 'utf8')
  const resolver = new NodeProjectScanResolver()

  await assert.rejects(
    () => resolver.resolve(projectRoot),
    /Multiple supported lockfiles found/,
  )
})

test('explicit package-lock resolution normalizes the lockfile path and project root', () => {
  const resolved = resolvePackageLockScan('./package-lock.json')

  assert.equal(resolved.scan_mode, 'package_lock')
  assert.match(resolved.package_lock_path, /package-lock\.json$/)
  assert.match(resolved.project_root, /depgraph-cli$/)
})

test('explicit pnpm-lock resolution normalizes the lockfile path and project root', () => {
  const resolved = resolvePnpmLockScan('./pnpm-lock.yaml')

  assert.equal(resolved.scan_mode, 'pnpm_lock')
  assert.match(resolved.pnpm_lock_path ?? '', /pnpm-lock\.yaml$/)
  assert.match(resolved.project_root, /depgraph-cli$/)
})
