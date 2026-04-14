# Contributing

Thanks for contributing to DepGraph.

## Development Setup

```bash
pnpm install
pnpm run lint
pnpm test
pnpm run build
pnpm run test:e2e
```

Run the CLI locally:

```bash
pnpm run dev -- scan axios --no-tui --depth 2
```

## Benchmark Runner

The benchmark runner reads from `.internal/benchmarks/benchmark-manifest.json`.
This file is not tracked in the repository.

To run benchmarks, create `.internal/benchmarks/benchmark-manifest.json`
with your benchmark cases. See internal documentation for the schema.

## Project Rules

- preserve the architecture boundaries in `AGENTS.md`
- use [ARCHITECTURE.md](ARCHITECTURE.md) as the repo-level source of truth for layer boundaries and storage model
- keep CLI parsing in `src/cli`
- keep business logic in `src/application` and `src/domain`
- keep npm, traversal, and scoring logic in `src/adapters`
- keep renderers in `src/interface`
- keep JSON output deterministic
- keep scan records immutable and review history append-only

## Pull Requests

- open an issue first for larger feature changes
- keep changes scoped and explain the behavior change clearly
- add or update tests when behavior changes
- run `pnpm run lint`, `pnpm test`, `pnpm run build`, and `pnpm run test:e2e` before submitting

## Release Readiness

Use the built-artifact verification path before cutting or publishing a release:

```bash
pnpm run release:check
```

This verifies the source test suite, the compiled CLI entrypoint at `dist/cli/index.js`, and the package contents that would be published.

## Release Automation

DepGraph uses Release Please on pushes to `main`. Release Please maintains the release PR, and merging that PR creates the version bump commit, `v*` tag, and GitHub Release. The npm publish workflow remains separate and runs from the resulting GitHub Release event.

Repository settings required for the Release Please app:

- Variable: `RELEASE_PLEASE_APP_ID`
- Secret: `RELEASE_PLEASE_APP_PRIVATE_KEY`

If you previously used `RP_APP_ID` / `RP_APP_PRIVATE_KEY`, rename them in **Settings → Secrets and variables → Actions** to the names above so the workflow can resolve them.

GitHub App permissions should be limited to:

- `Contents`: read and write
- `Pull requests`: read and write
- `Issues`: read and write

If the repository uses protected tag or ref rulesets, allow the app identity to create `v*` tags and update the `release-please--branches--main` release branch.

## Commit Quality

Prefer small, reviewable changes. If a change affects scoring, output contracts, or exit codes, call that out explicitly in the pull request description.
