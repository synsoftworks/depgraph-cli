import type { PackageMetadata } from '../domain/contracts.js'
import { InvalidUsageError, NetworkFailureError } from '../domain/errors.js'
import type {
  PackageMetadataSource,
  TraversedDependencyGraph,
  TraversedPackageNode,
} from '../domain/ports.js'
import { packageKey } from '../domain/value-objects.js'

/** Normalized dependency entry extracted from a lockfile snapshot. */
export interface NormalizedLockfileEntry {
  entry_id: string
  name: string
  version: string
  dependencies: Record<string, string>
  resolved: string | null
  integrity: string | null
}

/** Shared lockfile traversal interface consumed by lockfile adapters. */
export interface NormalizedLockfileProject {
  root_package: PackageMetadata['package']
  root_dependencies: Record<string, string>
  resolve_root_dependency(dependency_name: string): NormalizedLockfileEntry | null
  resolve_entry_dependency(
    entry: NormalizedLockfileEntry,
    dependency_name: string,
  ): NormalizedLockfileEntry | null
}

interface QueueItem {
  entry: NormalizedLockfileEntry | null
  depth: number
  parent_key: string | null
  path_packages: TraversedPackageNode['path']['packages']
}

// The project root is not a published npm package. These sentinel values exist only
// to satisfy the internal traversed-node metadata shape before the application layer
// converts the root into an explicit project-root PackageNode with nullable package metadata.
const SYNTHETIC_ROOT_PUBLISHED_AT = '1970-01-01T00:00:00.000Z'

/**
 * Traverses a normalized lockfile project into the shared traversed-graph shape.
 *
 * @param project Normalized lockfile project.
 * @param metadataSource Metadata source for exact package enrichment.
 * @param maxDepth Maximum dependency depth to traverse.
 * @returns Traversed dependency graph.
 */
export async function traverseNormalizedLockfileProject(
  project: NormalizedLockfileProject,
  metadataSource: PackageMetadataSource,
  maxDepth: number,
): Promise<TraversedDependencyGraph> {
  const metadataCache = new Map<string, Promise<PackageMetadata>>()
  const queue: QueueItem[] = [
    {
      entry: null,
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

    const enrichment =
      item.entry === null
        ? createSyntheticRootMetadata(project)
        : await resolveExactPackageMetadata(
            metadataCache,
            metadataSource,
            item.entry.name,
            item.entry.version,
            item.entry.dependencies,
          ).catch((error) =>
            createUnresolvedPackageMetadata(
              item.entry!.name,
              item.entry!.version,
              item.entry!.dependencies,
              error,
            ),
          )
    const key = packageKey(enrichment.package)

    if (visited.has(key)) {
      continue
    }

    visited.add(key)

    const path = {
      packages: [...item.path_packages, enrichment.package],
    }

    nodes.push({
      key,
      package: enrichment.package,
      metadata: enrichment.metadata,
      resolved_dependencies: enrichment.resolved_dependencies,
      metadata_status: enrichment.metadata_status,
      metadata_warning: enrichment.metadata_warning,
      lockfile_resolved_url: item.entry?.resolved ?? null,
      lockfile_integrity: item.entry?.integrity ?? null,
      depth: item.depth,
      parent_key: item.parent_key,
      path,
      is_virtual_root: item.entry === null,
    })

    if (item.depth >= maxDepth) {
      continue
    }

    const dependencyNames =
      item.entry === null
        ? Object.keys(project.root_dependencies)
        : Object.keys(item.entry.dependencies)

    for (const dependencyName of dependencyNames) {
      const dependencyEntry =
        item.entry === null
          ? project.resolve_root_dependency(dependencyName)
          : project.resolve_entry_dependency(item.entry, dependencyName)

      if (dependencyEntry === null) {
        continue
      }

      queue.push({
        entry: dependencyEntry,
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

function createSyntheticRootMetadata(project: NormalizedLockfileProject): {
  package: PackageMetadata['package']
  metadata: PackageMetadata
  resolved_dependencies: Record<string, string>
  metadata_status: 'synthetic_project_root'
  metadata_warning: null
} {
  const resolvedDependencies = Object.fromEntries(
    Object.keys(project.root_dependencies).map((dependencyName) => {
      const resolvedEntry = project.resolve_root_dependency(dependencyName)

      return [dependencyName, resolvedEntry?.version ?? '*']
    }),
  )

  return {
    package: project.root_package,
    resolved_dependencies: resolvedDependencies,
    metadata_status: 'synthetic_project_root',
    metadata_warning: null,
    metadata: {
      package: project.root_package,
      dependencies: resolvedDependencies,
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
    },
  }
}

async function resolveExactPackageMetadata(
  metadataCache: Map<string, Promise<PackageMetadata>>,
  metadataSource: PackageMetadataSource,
  packageName: string,
  packageVersion: string,
  resolvedDependencies: Record<string, string>,
): Promise<{
  package: PackageMetadata['package']
  metadata: PackageMetadata
  resolved_dependencies: Record<string, string>
  metadata_status: 'enriched'
  metadata_warning: null
}> {
  const key = `${packageName}@${packageVersion}`
  const existing = metadataCache.get(key)

  if (existing !== undefined) {
    const metadata = await existing

    return {
      package: metadata.package,
      metadata,
      resolved_dependencies: resolvedDependencies,
      metadata_status: 'enriched',
      metadata_warning: null,
    }
  }

  const metadataPromise = metadataSource.resolvePackage({
    name: packageName,
    version_range: packageVersion,
  })
  metadataCache.set(key, metadataPromise)
  const metadata = await metadataPromise

  return {
    package: metadata.package,
    metadata,
    resolved_dependencies: resolvedDependencies,
    metadata_status: 'enriched',
    metadata_warning: null,
  }
}

function createUnresolvedPackageMetadata(
  packageName: string,
  packageVersion: string,
  resolvedDependencies: Record<string, string>,
  error: unknown,
): {
  package: PackageMetadata['package']
  metadata: null
  resolved_dependencies: Record<string, string>
  metadata_status: 'unresolved_registry_lookup'
  metadata_warning: string
} {
  if (!(error instanceof NetworkFailureError || error instanceof InvalidUsageError)) {
    throw error
  }

  return {
    package: {
      name: packageName,
      version: packageVersion,
    },
    metadata: null,
    resolved_dependencies: resolvedDependencies,
    metadata_status: 'unresolved_registry_lookup',
    metadata_warning: error.message,
  }
}
