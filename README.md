[![GitHub Repo stars](https://img.shields.io/github/stars/synsoftworks/depgraph-cli?style=flat-square)](https://github.com/synsoftworks/depgraph-cli)
[![npm version](https://img.shields.io/npm/v/%40synsoftworks%2Fdepgraph-cli?style=flat-square)](https://www.npmjs.com/package/@synsoftworks/depgraph-cli)

# DepGraph CLI

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

## Example Output

Plain-text output from a scan:

```text
Scan: plain-crypto-js@0.0.1-security.0
Overall risk: review (0.48)
Total scanned: 1
Suspicious packages: 1

Findings:
- plain-crypto-js@0.0.1-security.0 [review 0.48] via plain-crypto-js@0.0.1-security.0
  explanation: package was published 1 day(s) ago; package has only 1 published version(s)

Tree:
- plain-crypto-js@0.0.1-security.0 [review 0.48]
```

## JSON Mode

Use `--json` when DepGraph is being called from CI, scripts, or agents. JSON mode bypasses terminal rendering and emits a deterministic result shape.

```bash
depgraph scan axios --json --depth 2
```

Trimmed example:

```json
{
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

## Philosophy

DepGraph follows a simple rule: data first, presentation second.

Each command produces structured scan data first, then renders it for either a human terminal session or an agent-oriented JSON consumer. The CLI is designed to work well for both without mixing business logic into presentation.

## Contributing

Issues and pull requests are welcome. If you want to contribute, open an issue first for larger changes so the command behavior, JSON shape, and architecture stay aligned.

## License

MIT
