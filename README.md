<h1 align="center">
  DepGraph CLI
</h1>

<p align="center">
  <a href="https://www.npmjs.com/package/@synsoftworks/depgraph-cli"><img alt="npm version" src="https://img.shields.io/npm/v/%40synsoftworks%2Fdepgraph-cli?style=flat-square"></a>
  <a href="https://www.npmjs.com/package/@synsoftworks/depgraph-cli"><img alt="npm downloads per month" src="https://img.shields.io/npm/dm/%40synsoftworks%2Fdepgraph-cli?style=flat-square"></a>
  <a href="https://nodejs.org/"><img alt="node version" src="https://img.shields.io/node/v/%40synsoftworks%2Fdepgraph-cli?style=flat-square"></a>
  <a href="https://github.com/synsoftworks/depgraph-cli/actions/workflows/ci.yml"><img alt="CI" src="https://github.com/synsoftworks/depgraph-cli/actions/workflows/ci.yml/badge.svg"></a>
  <a href="https://github.com/synsoftworks/depgraph-cli/blob/main/LICENSE"><img alt="License" src="https://img.shields.io/github/license/synsoftworks/depgraph-cli?style=flat-square"></a>
</p>

DepGraph is a supply chain security tool that lives in your terminal, scans an npm package plus its current registry-resolved dependency tree projection for attack signals, and tells you why a package looks suspicious before you ship it.

Run it before every install. Use the JSON output in CI. Agent friendly 🤖

## Get Started

Install globally:

```bash
npm install -g @synsoftworks/depgraph-cli
```

Run without installing:

```bash
npx -p @synsoftworks/depgraph-cli depgraph --help
```

## Quick Start

Show help:

```bash
depgraph --help
```

Scan a package with plain terminal output:

```bash
depgraph scan axios --no-tui --depth 2
```

Scan the same package with JSON output:

```bash
depgraph scan axios --json --depth 2
```

Scan a local project from an explicit lockfile path:

```bash
depgraph scan --package-lock ./package-lock.json
depgraph scan --pnpm-lock ./pnpm-lock.yaml
```

Detect a supported lockfile in the current project root:

```bash
depgraph scan --project . --json
```

`--project` will resolve either `package-lock.json` or `pnpm-lock.yaml` when present.

Append a review outcome to a stored scan finding:

```bash
depgraph review <record_id> --target package_finding:axios@1.14.0 --outcome benign --notes "reviewed by analyst"
```

Inspect local dataset coverage and readiness:

```bash
depgraph eval
```

## Plain-Text Example

Plain-text output from a real scan:

```text
Scan: plain-crypto-js@0.0.1-security.0
Mode: registry_package
Target: plain-crypto-js
Overall risk: critical (1.00)
Total scanned: 1
Suspicious packages: 1

Changed edges in current tree view:
- none

Findings:
- plain-crypto-js@0.0.1-security.0 [critical 1.00] via plain-crypto-js@0.0.1-security.0
  target: package_finding:plain-crypto-js@0.0.1-security.0
  explanation: package was published 1 day(s) ago; package has only 1 published version(s); package is an npm security placeholder or tombstone for a previously malicious package

Current tree view:
- plain-crypto-js@0.0.1-security.0 [critical 1.00]
```

## JSON Example

Use `--json` when DepGraph is being called from CI, scripts, or agents. JSON mode bypasses terminal rendering and emits a deterministic result shape.

```bash
depgraph scan axios --json --depth 2
```

Trimmed example:

```json
{
  "record_id": "2026-04-02T00:00:00.000Z:axios@1.14.0:depth=2",
  "scan_mode": "registry_package",
  "scan_target": "axios",
  "baseline_record_id": null,
  "requested_depth": 2,
  "threshold": 0.4,
  "root": {
    "name": "axios",
    "version": "1.14.0",
    "risk_score": 0.32,
    "risk_level": "safe"
  },
  "findings": [],
  "total_scanned": 9,
  "suspicious_count": 0,
  "overall_risk_score": 0.32,
  "overall_risk_level": "safe"
}
```

This mode is intended for automation, CI checks, and agent tooling that needs machine-readable output instead of terminal formatting.

## Current Scan Modes

- `registry_package` scans start from an npm package spec and resolve structure from registry metadata
- `package_lock` scans start from a local `package-lock.json` and read dependency structure from the lockfile itself
- `pnpm_lock` scans start from a local `pnpm-lock.yaml` importer view and normalize it into the same dependency graph shape used by other scan modes

`package_lock` scanning currently supports `package-lock.json` with `lockfileVersion >= 2` and a `packages` map only.

`pnpm_lock` scanning currently supports `pnpm-lock.yaml` importer-backed project scans with a `packages` snapshot map. Local `workspace:`, `link:`, and `file:` dependency references are reported as unsupported rather than projected dishonestly.

## Local Data Model

DepGraph now persists repo-local history under `.depgraph/`:

- `scans.jsonl` for immutable scan records
- `review-events.jsonl` for append-only review annotations

## Status

DepGraph is pre-v1 and under active development. Core scanning works.
Some dependency types degrade gracefully rather than fully enriching.
See the roadmap for what's coming.

## Roadmap

### Shipped

- [x] npm package scanning with traversal
- [x] rich Ink terminal UI and plain text mode
- [x] deterministic JSON output for agents and CI
- [x] local scan persistence and append-only review history
- [x] projected dependency edge delta against prior baseline
- [x] package-lock.json project scanning
- [x] pnpm-lock.yaml project scanning
- [x] graceful degradation for private and non-registry dependencies
- [x] finding-level review targets and source-precedence label integrity
- [x] local dataset evaluation
- [x] depgraph.sh

### Coming Soon

- [ ] yarn lockfile support
- [ ] sensitive import analysis
- [ ] explain command
- [ ] CI/CD GitHub Action

### Future

- [ ] maintainer history signals
- [ ] organization-level scan aggregation

## Philosophy

DepGraph follows a simple rule: data first, presentation second.

Each command produces structured scan data first, then renders it for either a human terminal session or an agent-oriented JSON consumer. The CLI is designed to work well for both without mixing business logic into presentation.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for local setup, workflow, and contribution guidelines.

## Security

If you believe you found a security issue in DepGraph itself, see [SECURITY.md](SECURITY.md).

## License

DepGraph is available under the [MIT License](LICENSE).
