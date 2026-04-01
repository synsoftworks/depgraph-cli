declare module 'semver' {
  interface SemverOptions {
    includePrerelease?: boolean
  }

  interface SemverModule {
    valid(version: string): string | null
    maxSatisfying(
      versions: readonly string[],
      range: string,
      options?: SemverOptions,
    ): string | null
    rsort(versions: readonly string[]): string[]
  }

  const semver: SemverModule

  export default semver
}
