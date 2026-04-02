# Contributing

Thanks for contributing to DepGraph.

## Development Setup

```bash
pnpm install
pnpm run lint
pnpm test
pnpm run build
```

Run the CLI locally:

```bash
pnpm run dev -- scan axios --no-tui --depth 2
```

## Project Rules

- preserve the architecture boundaries in `AGENTS.md`
- keep CLI parsing in `src/cli`
- keep business logic in `src/application` and `src/domain`
- keep npm, traversal, and scoring logic in `src/adapters`
- keep renderers in `src/interface`
- keep JSON output deterministic

## Pull Requests

- open an issue first for larger feature changes
- keep changes scoped and explain the behavior change clearly
- add or update tests when behavior changes
- run `pnpm run lint`, `pnpm test`, and `pnpm run build` before submitting

## Commit Quality

Prefer small, reviewable changes. If a change affects scoring, output contracts, or exit codes, call that out explicitly in the pull request description.
