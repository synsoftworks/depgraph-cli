import semver from 'semver'

import type { PackageMetadata, PackageSpec } from '../domain/contracts.js'
import { InvalidUsageError, NetworkFailureError } from '../domain/errors.js'
import type { PackageMetadataSource } from '../domain/ports.js'

interface NpmVersionManifest {
  version: string
  dependencies?: Record<string, string>
}

interface NpmPackument {
  name: string
  versions?: Record<string, NpmVersionManifest>
  time?: Record<string, string>
  'dist-tags'?: {
    latest?: string
  }
}

interface DownloadResponse {
  downloads?: number
}

export class NpmPackageMetadataSource implements PackageMetadataSource {
  constructor(private readonly fetcher: typeof fetch = fetch) {}

  async resolvePackage(spec: PackageSpec): Promise<PackageMetadata> {
    const packument = await this.fetchPackument(spec.name)
    const version = this.resolveVersion(packument, spec)
    const manifest = packument.versions?.[version]

    if (manifest === undefined) {
      throw new NetworkFailureError(`Registry metadata for ${spec.name}@${version} is incomplete.`)
    }

    const versionTimes = this.collectVersionTimes(packument)
    const publishedAt = packument.time?.[version] ?? versionTimes.at(-1) ?? new Date(0).toISOString()
    const firstPublishedAt = versionTimes[0] ?? publishedAt
    const lastPublishedAt = versionTimes.at(-1) ?? publishedAt
    const publishEventsLast30Days = this.countRecentPublishes(versionTimes, 30)
    const weeklyDownloads = await this.fetchWeeklyDownloads(spec.name)

    return {
      package: {
        name: packument.name,
        version,
      },
      dependencies: this.sortDependencies(manifest.dependencies),
      published_at: publishedAt,
      first_published_at: firstPublishedAt,
      last_published_at: lastPublishedAt,
      total_versions: Object.keys(packument.versions ?? {}).length,
      publish_events_last_30_days: publishEventsLast30Days,
      weekly_downloads: weeklyDownloads,
      has_advisories: false,
    }
  }

  private async fetchPackument(name: string): Promise<NpmPackument> {
    const url = `https://registry.npmjs.org/${encodeURIComponent(name)}`

    let response: Response

    try {
      response = await this.fetcher(url, {
        headers: {
          accept: 'application/vnd.npm.install-v1+json',
        },
      })
    } catch (error) {
      throw new NetworkFailureError(
        `Unable to reach the npm registry for "${name}": ${this.getErrorMessage(error)}`,
      )
    }

    if (response.status === 404) {
      throw new NetworkFailureError(`Package "${name}" was not found in the npm registry.`)
    }

    if (!response.ok) {
      throw new NetworkFailureError(
        `npm registry request for "${name}" failed with status ${response.status}.`,
      )
    }

    return (await response.json()) as NpmPackument
  }

  private resolveVersion(packument: NpmPackument, spec: PackageSpec): string {
    const versions = Object.keys(packument.versions ?? {}).filter((version) => semver.valid(version))

    if (versions.length === 0) {
      throw new NetworkFailureError(`Package "${spec.name}" has no published versions.`)
    }

    if (spec.version_range !== undefined) {
      if (packument.versions?.[spec.version_range] !== undefined) {
        return spec.version_range
      }

      const resolved = semver.maxSatisfying(versions, spec.version_range, {
        includePrerelease: true,
      })

      if (resolved !== null) {
        return resolved
      }

      throw new InvalidUsageError(
        `No version of "${spec.name}" satisfies "${spec.version_range}".`,
      )
    }

    const latest = packument['dist-tags']?.latest

    if (latest !== undefined && packument.versions?.[latest] !== undefined) {
      return latest
    }

    const highestVersion = semver.rsort(versions)[0]

    if (highestVersion === undefined) {
      throw new NetworkFailureError(`Unable to resolve a version for "${spec.name}".`)
    }

    return highestVersion
  }

  private collectVersionTimes(packument: NpmPackument): string[] {
    const versionSet = new Set(Object.keys(packument.versions ?? {}))

    return Object.entries(packument.time ?? {})
      .filter(([key, value]) => {
        return (
          key !== 'created' &&
          key !== 'modified' &&
          versionSet.has(key) &&
          !Number.isNaN(Date.parse(value))
        )
      })
      .map(([, value]) => value)
      .sort((left, right) => Date.parse(left) - Date.parse(right))
  }

  private countRecentPublishes(versionTimes: string[], windowDays: number): number {
    const windowMs = windowDays * 86_400_000
    const now = Date.now()

    return versionTimes.filter((value) => now - Date.parse(value) <= windowMs).length
  }

  private async fetchWeeklyDownloads(name: string): Promise<number | null> {
    const url = `https://api.npmjs.org/downloads/point/last-week/${encodeURIComponent(name)}`

    try {
      const response = await this.fetcher(url)

      if (!response.ok) {
        return null
      }

      const payload = (await response.json()) as DownloadResponse

      return typeof payload.downloads === 'number' ? payload.downloads : null
    } catch {
      return null
    }
  }

  private sortDependencies(
    dependencies: Record<string, string> | undefined,
  ): Record<string, string> {
    return Object.fromEntries(
      Object.entries(dependencies ?? {}).sort(([left], [right]) => left.localeCompare(right)),
    )
  }

  private getErrorMessage(error: unknown): string {
    if (error instanceof Error) {
      return error.message
    }

    return String(error)
  }
}
