import type { PackageSpec } from '../domain/contracts.js'
import type {
  DependencyTraverser,
  PackageMetadataSource,
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

export class BfsDependencyTraverser implements DependencyTraverser {
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
      const current = queue.shift()

      if (current === undefined) {
        break
      }

      const metadata = await this.metadataSource.resolvePackage(current.spec)
      const key = packageKey(metadata.package)

      if (visited.has(key)) {
        continue
      }

      visited.add(key)

      const path = {
        packages: [...current.path_packages, metadata.package],
      }

      nodes.push({
        key,
        package: metadata.package,
        metadata,
        depth: current.depth,
        parent_key: current.parent_key,
        path,
      })

      if (current.depth >= max_depth) {
        continue
      }

      for (const [dependency_name, version_range] of Object.entries(metadata.dependencies)) {
        queue.push({
          spec: {
            name: dependency_name,
            version_range,
          },
          depth: current.depth + 1,
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
