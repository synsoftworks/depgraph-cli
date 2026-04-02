<h1 align="center">
  <img src="docs/assets/node.png" alt="DepGraph mascot" width="88"><br>
  DepGraph CLI
</h1>

<p align="center">
  <a href="https://github.com/synsoftworks/depgraph-cli"><img alt="GitHub Repo stars" src="https://img.shields.io/github/stars/synsoftworks/depgraph-cli?style=flat-square"></a>
  <a href="https://www.npmjs.com/package/@synsoftworks/depgraph-cli"><img alt="npm version" src="https://img.shields.io/npm/v/%40synsoftworks%2Fdepgraph-cli?style=flat-square"></a>
  <a href="https://github.com/synsoftworks/depgraph-cli/actions/workflows/ci.yml"><img alt="CI" src="https://github.com/synsoftworks/depgraph-cli/actions/workflows/ci.yml/badge.svg"></a>
  <a href="https://github.com/synsoftworks/depgraph-cli/blob/main/LICENSE"><img alt="License" src="https://img.shields.io/github/license/synsoftworks/depgraph-cli?style=flat-square"></a>
</p>

DepGraph is a graph-first CLI for scanning npm packages and dependency trees for supply chain risk.

It resolves a package, walks its dependency graph breadth-first, scores metadata-based risk signals, and explains why a node was flagged. The output is designed for both humans in a terminal and agents that need stable JSON.

## Install

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
  "scan_target": "axios",
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

## Current Scope

DepGraph is an MVP focused on npm registry metadata and dependency graph traversal.

Current limitations:

- no lockfile scanning yet
- no tarball or source inspection
- no advisory database integration beyond package metadata
- no sensitive import analysis yet
- no learned or ML-based scoring

## Roadmap

- [x] npm package scanning MVP
- [x] rich Ink terminal UI
- [x] deterministic JSON output for agents and CI
- [x] breadth-first traversal with shortest suspicious paths
- [ ] lockfile scanning
- [ ] advisory integration
- [ ] stronger composite signals
- [ ] sensitive import analysis
- [ ] explain command

## Philosophy

DepGraph follows a simple rule: data first, presentation second.

Each command produces structured scan data first, then renders it for either a human terminal session or an agent-oriented JSON consumer. The CLI is designed to work well for both without mixing business logic into presentation.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for local setup, workflow, and contribution guidelines.

## Security

If you believe you found a security issue in DepGraph itself, see [SECURITY.md](SECURITY.md).

## License

DepGraph is available under the [MIT License](LICENSE).
