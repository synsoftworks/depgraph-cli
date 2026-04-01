# DepGraph CLI

Graph-first dependency risk analysis for npm. DepGraph walks a package’s dependency tree, collects security-relevant signals, scores risk, and explains **why** something was flagged—useful for catching supply-chain anomalies, not only known CVEs.

**Built for two audiences:** a rich terminal experience for humans, and stable **`--json`** output for CI and agents.

---

## Install

```bash
npm install -g depgraph-cli
# or run without global install:
npx depgraph-cli --help
```

The executable name on your PATH is defined by this package’s `bin` field (often `depgraph` or `depgraph-cli`). Below, `depgraph` means whichever binary your install provides.

---

## Usage

Scan a package (name and optional version, npm-style):

```bash
depgraph-cli scan lodash@4.17.21
npx depgraph-cli scan lodash@4.17.21
```

**Automation / agents** — deterministic JSON, no TUI:

```bash
depgraph-cli scan lodash@4.17.21 --json
depgraph-cli  scan lodash --no-tui
```

**Common flags** (see `depgraph scan --help` for the full set):

| Flag          | Purpose                                     |
| ------------- | ------------------------------------------- |
| `--json`      | Structured output for pipelines and tooling |
| `--no-tui`    | Non-interactive / plain-friendly output     |
| `--depth`     | Cap how far the graph is traversed          |
| `--threshold` | Adjust when a node counts as suspicious     |
| `--verbose`   | Extra detail for debugging                  |

Explain a previous result or focus node (when implemented):

```bash
depgraph-cli explain <package[@version]> [flags]
```

---

## Example (human-oriented)

Illustrative shape of tree output—not guaranteed to match your exact build:

```text
my-package@1.0.0 ✓ safe
├─ dep-a@2.1.0 ✓ safe
├─ dep-b@1.3.0 ✓ safe
└─ dep-c@0.0.1 ⚠ suspicious
   • age: 1 day old
   • downloads: 0 / week
   • imports: fs, os, child_process
   • risk score: 0.94
```

## Exit codes

| Code | Meaning                      |
| ---- | ---------------------------- |
| `0`  | Success; no threats reported |
| `1`  | Suspicious packages found    |
| `2`  | Invalid usage                |
| `3`  | Network or auth failure      |

---

## Development

This repo uses **pnpm** and **TypeScript**. From the project root:

```bash
pnpm install
```
