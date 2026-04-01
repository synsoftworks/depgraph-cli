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
  time?: {
    created?: string
    modified?: string
    [version: string]: string | undefined
  }
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
    const publishDates = this.resolvePublishDates(packument, version, spec.name, versionTimes)
    const publishEventsLast30Days = this.countRecentPublishes(versionTimes, 30)
    const weeklyDownloads = await this.fetchWeeklyDownloads(spec.name)

    return {
      package: {
        name: packument.name,
        version,
      },
      dependencies: this.sortDependencies(manifest.dependencies),
      published_at: publishDates.published_at,
      first_published_at: publishDates.first_published_at,
      last_published_at: publishDates.last_published_at,
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
      response = await this.fetcher(url)
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
      .flatMap(([key, value]) => {
        if (
          key === 'created' ||
          key === 'modified' ||
          value === undefined ||
          !versionSet.has(key) ||
          Number.isNaN(Date.parse(value))
        ) {
          return []
        }

        return [value]
      })
      .sort((left, right) => Date.parse(left) - Date.parse(right))
  }

  private resolvePublishDates(
    packument: NpmPackument,
    version: string,
    packageName: string,
    versionTimes: string[],
  ): {
    published_at: string
    first_published_at: string
    last_published_at: string
  } {
    // v1 treats publish timestamps as required metadata instead of guessing or null-filling.
    const createdAt = this.validTimestamp(packument.time?.created)
    const modifiedAt = this.validTimestamp(packument.time?.modified)
    const versionPublishedAt = this.validTimestamp(packument.time?.[version])
    const firstPublishedAt = createdAt ?? versionTimes[0] ?? versionPublishedAt
    const lastPublishedAt = modifiedAt ?? versionTimes.at(-1) ?? versionPublishedAt ?? firstPublishedAt
    const publishedAt = versionPublishedAt ?? lastPublishedAt ?? firstPublishedAt

    if (
      publishedAt === undefined ||
      firstPublishedAt === undefined ||
      lastPublishedAt === undefined
    ) {
      throw new NetworkFailureError(
        `Registry metadata for "${packageName}@${version}" does not include publish timestamps.`,
      )
    }

    return {
      published_at: publishedAt,
      first_published_at: firstPublishedAt,
      last_published_at: lastPublishedAt,
    }
  }

  private countRecentPublishes(versionTimes: string[], windowDays: number): number {
    const windowMs = windowDays * 86_400_000
    const now = Date.now()

    return versionTimes.filter((value) => now - Date.parse(value) <= windowMs).length
  }

  private validTimestamp(value: string | undefined): string | undefined {
    if (value === undefined || Number.isNaN(Date.parse(value))) {
      return undefined
    }

    return value
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
