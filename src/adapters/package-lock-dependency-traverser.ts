import { readFile } from 'node:fs/promises'
import { basename, dirname, posix as pathPosix } from 'node:path'

import type { PackageMetadata, PackageSpec } from '../domain/contracts.js'
import { InvalidUsageError, StorageFailureError } from '../domain/errors.js'
import type {
  PackageLockDependencyTraverser as PackageLockDependencyTraverserPort,
  PackageMetadataSource,
  TraversedDependencyGraph,
  TraversedPackageNode,
} from '../domain/ports.js'
import { packageKey } from '../domain/value-objects.js'

interface PackageLockFile {
  name?: string
  version?: string
  lockfileVersion?: number
  packages?: Record<string, PackageLockPackage>
  dependencies?: Record<string, PackageLockDependency>
}

interface PackageLockPackage {
  name?: string
  version?: string
  dependencies?: Record<string, string>
}

interface PackageLockDependency {
  version?: string
}

interface IndexedPackageEntry {
  path: string
  name: string
  version: string
  dependencies: string[]
}

interface QueueItem {
  entry_path: string
  package_name: string
  package_version: string
  depth: number
  parent_key: string | null
  path_packages: TraversedPackageNode['path']['packages']
}

// The project root is not a published npm package. These sentinel values exist only
// to satisfy the internal traversed-node metadata shape before the application layer
// converts the root into an explicit project-root PackageNode with nullable package metadata.
const SYNTHETIC_ROOT_PUBLISHED_AT = '1970-01-01T00:00:00.000Z'

export class PackageLockDependencyTraverser implements PackageLockDependencyTraverserPort {
  constructor(private readonly metadataSource: PackageMetadataSource) {}

  async traverse(package_lock_path: string, max_depth: number): Promise<TraversedDependencyGraph> {
    const lockfile = await readPackageLockFile(package_lock_path)
    const packageEntries = indexPackageEntries(lockfile)
    const rootPackage = resolveRootPackage(lockfile, package_lock_path)
    const rootDependencies = resolveRootDependencies(lockfile)
    const metadataCache = new Map<string, Promise<PackageMetadata>>()
    const queue: QueueItem[] = [
      {
        entry_path: '',
        package_name: rootPackage.name,
        package_version: rootPackage.version,
        depth: 0,
        parent_key: null,
        path_packages: [],
      },
    ]
    const visited = new Set<string>()
    const nodes: TraversedPackageNode[] = []

    while (queue.length > 0) {
      const item = queue.shift()

      if (item === undefined) {
        break
      }

      const metadata =
        item.entry_path === ''
          ? createSyntheticRootMetadata(rootPackage, rootDependencies, packageEntries)
          : await resolveExactPackageMetadata(
              metadataCache,
              this.metadataSource,
              item.package_name,
              item.package_version,
            )
      const key = packageKey(metadata.package)

      if (visited.has(key)) {
        continue
      }

      visited.add(key)

      const path = {
        packages: [...item.path_packages, metadata.package],
      }

      nodes.push({
        key,
        package: metadata.package,
        metadata,
        depth: item.depth,
        parent_key: item.parent_key,
        path,
        is_virtual_root: item.entry_path === '',
      })

      if (item.depth >= max_depth) {
        continue
      }

      const dependencyNames =
        item.entry_path === ''
          ? rootDependencies
          : packageEntries.get(item.entry_path)?.dependencies ?? []

      for (const dependencyName of dependencyNames) {
        const resolvedEntryPath = resolveDependencyEntryPath(
          item.entry_path,
          dependencyName,
          packageEntries,
        )

        if (resolvedEntryPath === null) {
          continue
        }

        const dependencyEntry = packageEntries.get(resolvedEntryPath)

        if (dependencyEntry === undefined) {
          continue
        }

        queue.push({
          entry_path: resolvedEntryPath,
          package_name: dependencyEntry.name,
          package_version: dependencyEntry.version,
          depth: item.depth + 1,
          parent_key: key,
          path_packages: path.packages,
        })
      }
    }

    return {
      root_key: nodes[0]?.key ?? '',
      nodes,
    }
  }
}

async function readPackageLockFile(packageLockPath: string): Promise<PackageLockFile> {
  let contents = ''

  try {
    contents = await readFile(packageLockPath, 'utf8')
  } catch (error) {
    throw new StorageFailureError(
      `Unable to read package-lock.json at ${packageLockPath}: ${getErrorMessage(error)}`,
    )
  }

  let parsed: unknown

  try {
    parsed = JSON.parse(contents)
  } catch (error) {
    throw new InvalidUsageError(
      `package-lock.json at ${packageLockPath} is not valid JSON: ${getErrorMessage(error)}`,
    )
  }

  const lockfile = parsed as PackageLockFile

  if (typeof lockfile.lockfileVersion !== 'number' || lockfile.lockfileVersion < 2) {
    throw new InvalidUsageError(
      `package-lock.json at ${packageLockPath} must use lockfileVersion 2 or newer.`,
    )
  }

  if (lockfile.packages === undefined) {
    throw new InvalidUsageError(
      `package-lock.json at ${packageLockPath} must include a packages map.`,
    )
  }

  return lockfile
}

function indexPackageEntries(lockfile: PackageLockFile): Map<string, IndexedPackageEntry> {
  const packageEntries = new Map<string, IndexedPackageEntry>()

  for (const [entryPath, entry] of Object.entries(lockfile.packages ?? {})) {
    if (entryPath === '') {
      continue
    }

    const name = resolvePackageEntryName(entryPath, entry)
    const version = entry.version?.trim() ?? ''

    if (name.length === 0 || version.length === 0) {
      throw new InvalidUsageError(
        `package-lock.json entry "${entryPath}" is missing required name/version information.`,
      )
    }

    packageEntries.set(entryPath, {
      path: entryPath,
      name,
      version,
      dependencies: Object.keys(entry.dependencies ?? {}),
    })
  }

  return packageEntries
}

function resolveRootPackage(
  lockfile: PackageLockFile,
  packageLockPath: string,
): PackageMetadata['package'] {
  const rootEntry = lockfile.packages?.['']
  const fallbackName = basename(dirname(packageLockPath)).trim()
  const name = lockfile.name?.trim() || rootEntry?.name?.trim() || fallbackName
  const version = lockfile.version?.trim() || rootEntry?.version?.trim() || '0.0.0'

  if (name.length === 0) {
    throw new InvalidUsageError(
      `package-lock.json at ${packageLockPath} is missing a project name and cannot be scanned.`,
    )
  }

  return { name, version }
}

function resolveRootDependencies(lockfile: PackageLockFile): string[] {
  const rootEntryDependencies = Object.keys(lockfile.packages?.['']?.dependencies ?? {})

  if (rootEntryDependencies.length > 0) {
    return rootEntryDependencies
  }

  return Object.keys(lockfile.dependencies ?? {})
}

function createSyntheticRootMetadata(
  rootPackage: PackageMetadata['package'],
  rootDependencies: string[],
  packageEntries: ReadonlyMap<string, IndexedPackageEntry>,
): PackageMetadata {
  const dependencies = Object.fromEntries(
    rootDependencies.map((dependencyName) => {
      const entryPath = resolveDependencyEntryPath('', dependencyName, packageEntries)
      const resolvedVersion = entryPath === null ? '*' : packageEntries.get(entryPath)?.version ?? '*'

      return [dependencyName, resolvedVersion]
    }),
  )

  return {
    package: rootPackage,
    dependencies,
    published_at: SYNTHETIC_ROOT_PUBLISHED_AT,
    first_published_at: SYNTHETIC_ROOT_PUBLISHED_AT,
    last_published_at: SYNTHETIC_ROOT_PUBLISHED_AT,
    total_versions: 1,
    publish_events_last_30_days: 0,
    weekly_downloads: null,
    deprecated_message: null,
    is_security_tombstone: false,
    has_advisories: false,
    dependents_count: null,
  }
}

async function resolveExactPackageMetadata(
  metadataCache: Map<string, Promise<PackageMetadata>>,
  metadataSource: PackageMetadataSource,
  packageName: string,
  packageVersion: string,
): Promise<PackageMetadata> {
  const key = `${packageName}@${packageVersion}`
  const existing = metadataCache.get(key)

  if (existing !== undefined) {
    return existing
  }

  const metadataPromise = metadataSource.resolvePackage({
    name: packageName,
    version_range: packageVersion,
  })
  metadataCache.set(key, metadataPromise)

  return metadataPromise
}

function resolvePackageEntryName(entryPath: string, entry: PackageLockPackage): string {
  const explicitName = entry.name?.trim()

  if (explicitName !== undefined && explicitName.length > 0) {
    return explicitName
  }

  const marker = 'node_modules/'
  const markerIndex = entryPath.lastIndexOf(marker)

  if (markerIndex === -1) {
    return ''
  }

  return entryPath.slice(markerIndex + marker.length)
}

function resolveDependencyEntryPath(
  currentEntryPath: string,
  dependencyName: string,
  packageEntries: ReadonlyMap<string, IndexedPackageEntry>,
): string | null {
  let searchPath: string | null = currentEntryPath

  while (searchPath !== null) {
    const candidate =
      searchPath.length === 0
        ? pathPosix.join('node_modules', dependencyName)
        : pathPosix.join(searchPath, 'node_modules', dependencyName)

    if (packageEntries.has(candidate)) {
      return candidate
    }

    searchPath = parentPackagePath(searchPath)
  }

  return null
}

function parentPackagePath(packagePath: string): string | null {
  if (packagePath.length === 0) {
    return null
  }

  const nestedMarkerIndex = packagePath.lastIndexOf('/node_modules/')

  if (nestedMarkerIndex === -1) {
    return ''
  }

  return packagePath.slice(0, nestedMarkerIndex)
}

function getErrorMessage(error: unknown): string {
  return error instanceof Error ? error.message : String(error)
}
