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

DepGraph is a supply chain security tool that lives in your terminal, sniffs your npm dependency tree for attack signals, and tells you exactly why a package looks suspicious before you ship it.

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

Append a review outcome to a stored scan record:

```bash
depgraph review <record_id> --outcome benign --notes "reviewed by analyst"
```

Inspect local dataset coverage:

```bash
depgraph eval
```

## Plain-Text Example

Plain-text output from a real scan:

```text
Scan: plain-crypto-js@0.0.1-security.0
Overall risk: critical (1.00)
Total scanned: 1
Suspicious packages: 1

Findings:
- plain-crypto-js@0.0.1-security.0 [critical 1.00] via plain-crypto-js@0.0.1-security.0
  explanation: package was published 1 day(s) ago; package has only 1 published version(s); package is an npm security placeholder or tombstone for a previously malicious package

Tree:
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

## How Risk Scoring Works

DepGraph uses explainable metadata-based signals instead of opaque output. Current signals include:

- very new package age
- low version history
- low or zero weekly downloads when available
- unusual publish churn
- large dependency surface
- npm security tombstones and deprecations
- newly introduced direct and transitive dependency edges relative to the latest local baseline scan

Human review is captured separately from heuristic scoring so the stored dataset can become durable ground truth over time.

## Local Data Model

DepGraph now persists repo-local history under `.depgraph/`:

- `scans.jsonl` for immutable scan records
- `review-events.jsonl` for append-only review annotations

This keeps the local dataset inspectable, scriptable, and cheap to evolve without introducing a database yet.

## Current Scope

DepGraph is an MVP focused on npm registry metadata and dependency graph traversal.

Current limitations:

- no lockfile scanning yet
- no tarball or source inspection
- no advisory database integration beyond package metadata
- no sensitive import analysis yet
- no learned or ML-based scoring yet
- local dataset evaluation is intentionally basic today

## Roadmap

- [x] npm package scanning MVP
- [x] rich Ink terminal UI
- [x] deterministic JSON output for agents and CI
- [x] breadth-first traversal with shortest suspicious paths
- [x] local scan persistence and append-only review capture
- [x] dependency graph delta against prior local baseline
- [x] basic local dataset evaluation
- [ ] lockfile scanning
- [ ] advisory integration
- [ ] stronger composite signals
- [ ] sensitive import analysis
- [ ] explain command

## Philosophy

DepGraph follows a simple rule: data first, presentation second.

Each command produces structured scan data first, then renders it for either a human terminal session or an agent-oriented JSON consumer. The CLI is designed to work well for both without mixing business logic into presentation.

For the system structure, storage model, and architectural invariants, see [ARCHITECTURE.md](ARCHITECTURE.md).

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for local setup, workflow, and contribution guidelines.

## Security

If you believe you found a security issue in DepGraph itself, see [SECURITY.md](SECURITY.md).

## License

DepGraph is available under the [MIT License](LICENSE).
