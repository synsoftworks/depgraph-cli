import { access } from 'node:fs/promises'
import { dirname, join, resolve } from 'node:path'

import { InvalidUsageError } from '../domain/errors.js'

/** Resolved project scan request for `package-lock.json`. */
export interface PackageLockScanResolution {
  scan_mode: 'package_lock'
  project_root: string
  package_lock_path: string
}

/** Resolved project scan request for `pnpm-lock.yaml`. */
export interface PnpmLockScanResolution {
  scan_mode: 'pnpm_lock'
  project_root: string
  pnpm_lock_path: string
}

/** Any supported resolved project scan request. */
export type ProjectScanResolution = PackageLockScanResolution | PnpmLockScanResolution

/** Filesystem-based resolver for local project scan inputs. */
export class NodeProjectScanResolver {
  async resolve(projectPath: string): Promise<ProjectScanResolution> {
    const projectRoot = resolve(projectPath)
    const packageLockPath = join(projectRoot, 'package-lock.json')
    const localPnpmLockPath = join(projectRoot, 'pnpm-lock.yaml')
    const hasPackageLock = await pathExists(packageLockPath)
    const hasLocalPnpmLock = await pathExists(localPnpmLockPath)

    if (hasPackageLock && hasLocalPnpmLock) {
      throw new InvalidUsageError(
        `Multiple supported lockfiles found in "${projectRoot}". Use --package-lock or --pnpm-lock explicitly.`,
      )
    }

    if (hasPackageLock) {
      return {
        scan_mode: 'package_lock',
        package_lock_path: packageLockPath,
        project_root: projectRoot,
      }
    }

    const pnpmLockPath = hasLocalPnpmLock ? localPnpmLockPath : await findNearestPnpmLockPath(projectRoot)

    if (pnpmLockPath !== null) {
      return {
        scan_mode: 'pnpm_lock',
        pnpm_lock_path: pnpmLockPath,
        project_root: projectRoot,
      }
    }

    throw new InvalidUsageError(
      `No supported lockfile found in "${projectRoot}". DepGraph v1 project scanning currently supports package-lock.json and pnpm-lock.yaml.`,
    )
  }
}

/**
 * Creates an explicit package-lock scan resolution from a file path.
 *
 * @param packageLockPath Path to `package-lock.json`.
 * @returns Resolved package-lock scan input.
 */
export function resolvePackageLockScan(packageLockPath: string): PackageLockScanResolution {
  const resolvedPackageLockPath = resolve(packageLockPath)

  return {
    scan_mode: 'package_lock',
    package_lock_path: resolvedPackageLockPath,
    project_root: dirname(resolvedPackageLockPath),
  }
}

/**
 * Creates an explicit pnpm-lock scan resolution from a file path.
 *
 * @param pnpmLockPath Path to `pnpm-lock.yaml`.
 * @returns Resolved pnpm-lock scan input.
 */
export function resolvePnpmLockScan(pnpmLockPath: string): PnpmLockScanResolution {
  const resolvedPnpmLockPath = resolve(pnpmLockPath)

  return {
    scan_mode: 'pnpm_lock',
    pnpm_lock_path: resolvedPnpmLockPath,
    project_root: dirname(resolvedPnpmLockPath),
  }
}

async function findNearestPnpmLockPath(projectRoot: string): Promise<string | null> {
  let currentPath = projectRoot

  while (true) {
    const pnpmLockPath = join(currentPath, 'pnpm-lock.yaml')

    if (await pathExists(pnpmLockPath)) {
      return pnpmLockPath
    }

    const parentPath = dirname(currentPath)

    if (parentPath === currentPath) {
      return null
    }

    currentPath = parentPath
  }
}

async function pathExists(path: string): Promise<boolean> {
  try {
    await access(path)
    return true
  } catch {
    return false
  }
}
