import { readFileSync } from 'node:fs'
import { basename, dirname, posix as pathPosix, relative, resolve } from 'node:path'

import { parse as parseYaml } from 'yaml'

import type { PackageMetadata } from '../../domain/contracts.js'
import { InvalidUsageError, StorageFailureError } from '../../domain/errors.js'
import type {
  NormalizedLockfileEntry,
  NormalizedLockfileProject,
} from '../lockfile-dependency-traversal.js'

interface PnpmLockfile {
  lockfileVersion?: string | number
  importers?: Record<string, PnpmImporterSnapshot>
  packages?: Record<string, PnpmPackageSnapshot>
}

interface PnpmImporterSnapshot {
  dependencies?: Record<string, PnpmDependencyReference>
}

interface PnpmPackageSnapshot {
  version?: string
  dependencies?: Record<string, string>
  resolution?: {
    integrity?: string
    tarball?: string
  }
}

type PnpmDependencyReference =
  | string
  | {
      version?: string
      specifier?: string
    }

export function parsePnpmLockfile(
  pnpmLockPath: string,
  projectRoot: string,
): NormalizedLockfileProject {
  const lockfile = readPnpmLockfile(pnpmLockPath)
  const lockfileRoot = dirname(resolve(pnpmLockPath))
  const resolvedProjectRoot = resolve(projectRoot)
  const importerId = resolveImporterId(lockfileRoot, resolvedProjectRoot)
  const importer = lockfile.importers?.[importerId]

  if (importer === undefined) {
    throw new InvalidUsageError(
      `pnpm-lock.yaml at ${pnpmLockPath} does not contain an importer for "${importerId}".`,
    )
  }

  const packageEntries = indexPackageSnapshots(lockfile.packages ?? {}, pnpmLockPath)
  const rootDependencies = normalizeDependencyReferences(
    importer.dependencies ?? {},
    pnpmLockPath,
    importerId,
  )
  const rootPackage = resolveProjectPackage(projectRoot)

  return {
    root_package: rootPackage,
    root_dependencies: rootDependencies,
    resolve_root_dependency(dependencyName: string): NormalizedLockfileEntry | null {
      return resolveDependencyEntry(
        dependencyName,
        rootDependencies[dependencyName],
        packageEntries,
        pnpmLockPath,
        importerId,
      )
    },
    resolve_entry_dependency(entry: NormalizedLockfileEntry, dependencyName: string): NormalizedLockfileEntry | null {
      return resolveDependencyEntry(
        dependencyName,
        entry.dependencies[dependencyName],
        packageEntries,
        pnpmLockPath,
        entry.entry_id,
      )
    },
  }
}

function readPnpmLockfile(pnpmLockPath: string): PnpmLockfile {
  let contents = ''

  try {
    contents = readFileSync(pnpmLockPath, 'utf8')
  } catch (error) {
    throw new StorageFailureError(
      `Unable to read pnpm-lock.yaml at ${pnpmLockPath}: ${getErrorMessage(error)}`,
    )
  }

  let parsed: unknown

  try {
    parsed = parseYaml(contents)
  } catch (error) {
    throw new InvalidUsageError(
      `pnpm-lock.yaml at ${pnpmLockPath} is not valid YAML: ${getErrorMessage(error)}`,
    )
  }

  const lockfile = parsed as PnpmLockfile

  if (lockfile.importers === undefined || typeof lockfile.importers !== 'object') {
    throw new InvalidUsageError(
      `pnpm-lock.yaml at ${pnpmLockPath} must include an importers map.`,
    )
  }

  return lockfile
}

function resolveImporterId(lockfileRoot: string, projectRoot: string): string {
  const relativePath = relative(lockfileRoot, projectRoot)

  if (relativePath.length === 0) {
    return '.'
  }

  return relativePath.split('\\').join(pathPosix.sep)
}

function resolveProjectPackage(projectRoot: string): PackageMetadata['package'] {
  const packageJsonPath = resolve(projectRoot, 'package.json')

  try {
    const parsed = JSON.parse(readFileSync(packageJsonPath, 'utf8')) as {
      name?: string
      version?: string
    }
    const fallbackName = basename(projectRoot).trim()
    const name = parsed.name?.trim() || fallbackName
    const version = parsed.version?.trim() || '0.0.0'

    if (name.length === 0) {
      throw new InvalidUsageError(
        `package.json at ${packageJsonPath} is missing a project name and cannot be scanned.`,
      )
    }

    return { name, version }
  } catch (error) {
    if (error instanceof InvalidUsageError) {
      throw error
    }

    const fallbackName = basename(projectRoot).trim()

    if (fallbackName.length === 0) {
      throw new InvalidUsageError(
        `Project root "${projectRoot}" is missing package.json and cannot be scanned.`,
      )
    }

    return {
      name: fallbackName,
      version: '0.0.0',
    }
  }
}

function indexPackageSnapshots(
  snapshots: Record<string, PnpmPackageSnapshot>,
  pnpmLockPath: string,
): Map<string, NormalizedLockfileEntry> {
  const entries = new Map<string, NormalizedLockfileEntry>()
  const peerlessAliases = new Map<string, NormalizedLockfileEntry | null>()

  for (const [snapshotId, snapshot] of Object.entries(snapshots)) {
    const normalizedSnapshotId = normalizeSnapshotId(snapshotId)
    const { name, version } = parseSnapshotIdentity(normalizedSnapshotId, pnpmLockPath)
    const entry: NormalizedLockfileEntry = {
      entry_id: normalizedSnapshotId,
      name,
      version: snapshot.version?.trim() || version,
      dependencies: sortDependencies(snapshot.dependencies ?? {}),
      resolved: snapshot.resolution?.tarball?.trim() || null,
      integrity: snapshot.resolution?.integrity?.trim() || null,
    }

    entries.set(normalizedSnapshotId, entry)

    const peerlessSnapshotId = stripPeerSuffix(normalizedSnapshotId)

    if (peerlessSnapshotId !== normalizedSnapshotId) {
      const existingAlias = peerlessAliases.get(peerlessSnapshotId)

      if (existingAlias === undefined) {
        peerlessAliases.set(peerlessSnapshotId, entry)
      } else if (existingAlias?.entry_id !== entry.entry_id) {
        peerlessAliases.set(peerlessSnapshotId, null)
      }
    }
  }

  for (const [alias, entry] of peerlessAliases.entries()) {
    if (entry !== null && !entries.has(alias)) {
      entries.set(alias, entry)
    }
  }

  return entries
}

function normalizeDependencyReferences(
  dependencies: Record<string, PnpmDependencyReference>,
  pnpmLockPath: string,
  ownerId: string,
): Record<string, string> {
  return Object.fromEntries(
    Object.entries(dependencies)
      .sort(([left], [right]) => left.localeCompare(right))
      .map(([dependencyName, reference]) => [
        dependencyName,
        normalizeDependencyReference(dependencyName, reference, pnpmLockPath, ownerId),
      ]),
  )
}

function normalizeDependencyReference(
  dependencyName: string,
  reference: PnpmDependencyReference,
  pnpmLockPath: string,
  ownerId: string,
): string {
  const resolvedReference =
    typeof reference === 'string' ? reference.trim() : reference.version?.trim() ?? ''

  if (resolvedReference.length === 0) {
    throw new InvalidUsageError(
      `pnpm-lock.yaml at ${pnpmLockPath} importer "${ownerId}" is missing a resolved version for "${dependencyName}".`,
    )
  }

  if (isLocalDependencyReference(resolvedReference)) {
    throw new InvalidUsageError(
      `pnpm-lock.yaml at ${pnpmLockPath} importer "${ownerId}" contains local dependency "${dependencyName}" (${resolvedReference}), which DepGraph does not project yet.`,
    )
  }

  return resolvedReference
}

function resolveDependencyEntry(
  dependencyName: string,
  reference: string | undefined,
  packageEntries: ReadonlyMap<string, NormalizedLockfileEntry>,
  pnpmLockPath: string,
  ownerId: string,
): NormalizedLockfileEntry | null {
  if (reference === undefined) {
    return null
  }

  if (isLocalDependencyReference(reference)) {
    throw new InvalidUsageError(
      `pnpm-lock.yaml at ${pnpmLockPath} importer "${ownerId}" contains local dependency "${dependencyName}" (${reference}), which DepGraph does not project yet.`,
    )
  }

  const normalizedReference = normalizeSnapshotId(reference)
  const direct = packageEntries.get(normalizedReference)

  if (direct !== undefined) {
    return direct
  }

  const dependencyScopedReference = normalizeSnapshotId(`${dependencyName}@${normalizedReference}`)

  return packageEntries.get(dependencyScopedReference) ?? null
}

function parseSnapshotIdentity(
  snapshotId: string,
  pnpmLockPath: string,
): {
  name: string
  version: string
} {
  const withoutPeerSuffix = stripPeerSuffix(snapshotId)
  const separatorIndex = withoutPeerSuffix.lastIndexOf('@')

  if (separatorIndex <= 0) {
    throw new InvalidUsageError(
      `pnpm-lock.yaml at ${pnpmLockPath} has an unsupported package snapshot key "${snapshotId}".`,
    )
  }

  const name = withoutPeerSuffix.slice(0, separatorIndex).trim()
  const version = withoutPeerSuffix.slice(separatorIndex + 1).trim()

  if (name.length === 0 || version.length === 0) {
    throw new InvalidUsageError(
      `pnpm-lock.yaml at ${pnpmLockPath} has an invalid package snapshot key "${snapshotId}".`,
    )
  }

  return { name, version }
}

function stripPeerSuffix(snapshotId: string): string {
  let normalized = snapshotId

  while (normalized.endsWith(')')) {
    let depth = 0
    let openIndex = -1

    for (let index = normalized.length - 1; index >= 0; index -= 1) {
      const character = normalized[index]

      if (character === ')') {
        depth += 1
      } else if (character === '(') {
        depth -= 1

        if (depth === 0) {
          openIndex = index
          break
        }
      }
    }

    if (openIndex === -1) {
      break
    }

    normalized = normalized.slice(0, openIndex)
  }

  return normalized
}

function normalizeSnapshotId(snapshotId: string): string {
  return snapshotId.startsWith('/') ? snapshotId.slice(1) : snapshotId
}

function isLocalDependencyReference(reference: string): boolean {
  return (
    reference.startsWith('link:') ||
    reference.startsWith('workspace:') ||
    reference.startsWith('file:')
  )
}

function sortDependencies(
  dependencies: Record<string, string>,
): Record<string, string> {
  return Object.fromEntries(
    Object.entries(dependencies).sort(([left], [right]) => left.localeCompare(right)),
  )
}

function getErrorMessage(error: unknown): string {
  return error instanceof Error ? error.message : String(error)
}
