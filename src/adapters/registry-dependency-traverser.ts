import type { PackageSpec } from '../domain/contracts.js'
import type {
  PackageMetadataSource,
  RegistryDependencyTraverser as RegistryDependencyTraverserPort,
  TraversedDependencyGraph,
  TraversedPackageNode,
} from '../domain/ports.js'
import { packageKey } from '../domain/value-objects.js'

interface QueueItem {
  spec: PackageSpec
  depth: number
  parent_key: string | null
  path_packages: TraversedPackageNode['path']['packages']
}

/** Breadth-first registry dependency traverser using resolved package metadata. */
export class RegistryDependencyTraverser implements RegistryDependencyTraverserPort {
  constructor(private readonly metadataSource: PackageMetadataSource) {}

  async traverse(root: PackageSpec, max_depth: number): Promise<TraversedDependencyGraph> {
    const queue: QueueItem[] = [
      {
        spec: root,
        depth: 0,
        parent_key: null,
        path_packages: [],
      },
    ]
    const visited = new Set<string>()
    const nodes: TraversedPackageNode[] = []

    while (queue.length > 0) {
      const currentDepth = queue[0]?.depth

      if (currentDepth === undefined) {
        break
      }

      const levelItems = this.takeLevel(queue, currentDepth)
      const levelMetadata = await Promise.all(
        levelItems.map(async (item) => ({
          item,
          metadata: await this.metadataSource.resolvePackage(item.spec),
        })),
      )

      for (const { item, metadata } of levelMetadata) {
        const key = packageKey(metadata.package)

        // v1 keeps the first parent/path discovered in BFS order and does not preserve additional parents.
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
          resolved_dependencies: metadata.dependencies,
          metadata_status: 'enriched',
          metadata_warning: null,
          lockfile_resolved_url: null,
          lockfile_integrity: null,
          depth: item.depth,
          parent_key: item.parent_key,
          path,
        })

        if (item.depth >= max_depth) {
          continue
        }

        for (const [dependency_name, version_range] of Object.entries(metadata.dependencies)) {
          queue.push({
            spec: {
              name: dependency_name,
              version_range,
            },
            depth: item.depth + 1,
            parent_key: key,
            path_packages: path.packages,
          })
        }
      }
    }

    return {
      root_key: nodes[0]?.key ?? '',
      nodes,
    }
  }

  private takeLevel(queue: QueueItem[], depth: number): QueueItem[] {
    const levelItems: QueueItem[] = []

    while (queue[0]?.depth === depth) {
      const item = queue.shift()

      if (item === undefined) {
        break
      }

      levelItems.push(item)
    }

    return levelItems
  }
}
