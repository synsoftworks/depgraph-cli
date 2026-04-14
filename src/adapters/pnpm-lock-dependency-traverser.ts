import type {
  PackageMetadataSource,
  PnpmLockDependencyTraverser as PnpmLockDependencyTraverserPort,
  TraversedDependencyGraph,
} from '../domain/ports.js'
import { parsePnpmLockfile } from './parsers/pnpm-lockfile-parser.js'
import { traverseNormalizedLockfileProject } from './lockfile-dependency-traversal.js'

/** `pnpm-lock.yaml` traverser that projects importer dependencies into the shared graph shape. */
export class PnpmLockDependencyTraverser implements PnpmLockDependencyTraverserPort {
  constructor(private readonly metadataSource: PackageMetadataSource) {}

  async traverse(
    pnpm_lock_path: string,
    project_root: string,
    max_depth: number,
  ): Promise<TraversedDependencyGraph> {
    const project = parsePnpmLockfile(pnpm_lock_path, project_root)

    return traverseNormalizedLockfileProject(project, this.metadataSource, max_depth)
  }
}
