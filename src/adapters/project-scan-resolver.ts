import { access } from 'node:fs/promises'
import { dirname, join, resolve } from 'node:path'

import type { PackageLockScanRequest } from '../domain/contracts.js'
import { InvalidUsageError } from '../domain/errors.js'

export interface ProjectScanResolution {
  scan_mode: PackageLockScanRequest['scan_mode']
  package_lock_path: string
  project_root: string
}

export class NodeProjectScanResolver {
  async resolve(projectPath: string): Promise<ProjectScanResolution> {
    const projectRoot = resolve(projectPath)
    const packageLockPath = join(projectRoot, 'package-lock.json')

    try {
      await access(packageLockPath)
    } catch {
      throw new InvalidUsageError(
        `No supported lockfile found in "${projectRoot}". DepGraph v1 project scanning currently supports package-lock.json only.`,
      )
    }

    return {
      scan_mode: 'package_lock',
      package_lock_path: packageLockPath,
      project_root: projectRoot,
    }
  }
}

export function resolvePackageLockScan(packageLockPath: string): ProjectScanResolution {
  const resolvedPackageLockPath = resolve(packageLockPath)

  return {
    scan_mode: 'package_lock',
    package_lock_path: resolvedPackageLockPath,
    project_root: dirname(resolvedPackageLockPath),
  }
}
