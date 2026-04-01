# DepGraph

Dependency graph analysis with risk scoring for npm packages.

DepGraph scans a package and its dependency tree to detect suspicious behavior associated with software supply-chain attacks. It surfaces risks as close to the root as possible and explains why a package was flagged.

---

## Usage

```bash
npx depgraph-cli my-package@1.0.0
```

⸻

Example Output:

my-package@1.0.0 ✓ safe
├─ dep-a@2.1.0 ✓ safe
├─ dep-b@1.3.0 ✓ safe
└─ dep-c@0.0.1 ✗ suspicious
• age: 1 day old
• downloads: 0 / week
• imports: fs, os, child_process
• risk score: 0.94

⸻

JSON Mode (for automation)

depgraph-cli pkgname@@1.14.1 --json

Outputs structured JSON for use in CI pipelines or agents.

⸻

Features
• Traverses dependency trees (BFS)
• Surfaces nearest risky dependency paths
• Computes explainable risk signals
• Dual output:
• Human-readable (CLI)
• Machine-readable (--json)

⸻

Roadmap
• Lockfile scanning (package-lock.json)
• CI integration
• Improved scoring (ML-based)
• Live watch mode

⸻

Philosophy

DepGraph is designed for both humans and agents.

The CLI emits structured data first, and renders it for humans second.
