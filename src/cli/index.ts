#!/usr/bin/env node

import { dirname } from 'node:path'

import { Command, CommanderError, InvalidArgumentError } from 'commander'

import type {
  EvaluationSummary,
  ProjectScanRequest,
  ReviewEvent,
  ReviewScanRequest,
  ScanRequest,
} from '../domain/contracts.js'
import type { FailureSurfacingSummary } from '../domain/failure-surfacing.js'
import type { ReviewOutcome, ReviewSource, ScanResult } from '../domain/entities.js'
import { InvalidUsageError, NetworkFailureError, StorageFailureError } from '../domain/errors.js'
import { DEFAULT_MAX_DEPTH, DEFAULT_THRESHOLD } from '../domain/value-objects.js'

interface WritableStreamLike {
  write(text: string): void
}

export interface CliRuntime {
  scanPackage: (request: ScanRequest) => Promise<ScanResult>
  resolveProjectScan: (projectPath: string) => Promise<ProjectScanRequest>
  reviewScan: (request: ReviewScanRequest) => Promise<ReviewEvent>
  evaluateScans: () => Promise<EvaluationSummary>
  evaluateFailures: () => Promise<FailureSurfacingSummary>
  renderJson: (result: ScanResult) => string
  renderPlainText: (result: ScanResult) => string
  renderReviewJson: (event: ReviewEvent) => string
  renderReviewPlainText: (event: ReviewEvent) => string
  renderEvaluationJson: (summary: EvaluationSummary) => string
  renderEvaluationPlainText: (summary: EvaluationSummary) => string
  renderFailureJson: (summary: FailureSurfacingSummary) => string
  renderFailurePlainText: (summary: FailureSurfacingSummary) => string
  renderInk: (result: ScanResult) => Promise<void>
  stdout: WritableStreamLike
  stderr: WritableStreamLike
  isTty: boolean
}

export async function run(argv: string[], overrides: Partial<CliRuntime> = {}): Promise<number> {
  const runtime = await createRuntime(overrides)
  const program = new Command()
  let exitCode = 0

  program
    .name('depgraph')
    .description('Graph-first dependency risk analysis for npm packages and resolved dependency tree projections.')
    .configureOutput({
      writeOut: (text) => runtime.stdout.write(text),
      writeErr: (text) => runtime.stderr.write(text),
    })
    .showHelpAfterError()
    .showSuggestionAfterError()
    .exitOverride()

  program
    .command('scan')
    .description('Scan an npm package spec or a local lockfile-backed project dependency view for suspicious metadata patterns.')
    .argument('[package_spec]', 'Package name with optional version or range, for example lodash@4.17.21')
    .option('--package-lock <path>', 'Scan a local package-lock.json explicitly')
    .option('--pnpm-lock <path>', 'Scan a local pnpm-lock.yaml explicitly')
    .option('--project <path>', 'Detect a supported lockfile in a project directory and scan it')
    .option('--json', 'Emit deterministic JSON output')
    .option('--no-tui', 'Emit deterministic plain text instead of Ink output')
    .option('--depth <number>', 'Cap how far the resolved dependency tree projection is traversed', parseDepth, DEFAULT_MAX_DEPTH)
    .option(
      '--threshold <number>',
      'Adjust when a node counts as suspicious',
      parseThreshold,
      DEFAULT_THRESHOLD,
    )
    .option('--verbose', 'Include extra detail for debugging', false)
    .addHelpText(
      'after',
      [
        '',
        'Notes:',
        '  Package-spec scans use registry metadata.',
        '  Project scans currently support package-lock.json and pnpm-lock.yaml.',
        '  Shared packages may appear under a single path in the current view.',
        '',
        'Examples:',
        '  depgraph scan lodash@4.17.21',
        '  depgraph scan lodash --json',
        '  depgraph scan --package-lock ./package-lock.json --json',
        '  depgraph scan --pnpm-lock ./pnpm-lock.yaml --json',
        '  depgraph scan --project . --no-tui',
        '  depgraph scan @types/node --no-tui --depth 2',
      ].join('\n'),
    )
    .action(async (packageSpec: string | undefined, options) => {
      try {
        const result = await runtime.scanPackage(
          await resolveScanRequest(packageSpec, options, runtime),
        )

        if (options.json === true) {
          runtime.stdout.write(`${runtime.renderJson(result)}\n`)
        } else if (options.tui === false || !runtime.isTty) {
          runtime.stdout.write(`${runtime.renderPlainText(result)}\n`)
        } else {
          await runtime.renderInk(result)
        }

        exitCode = result.suspicious_count > 0 ? 1 : 0
      } catch (error) {
        exitCode = mapErrorToExitCode(error)
        runtime.stderr.write(`${getErrorMessage(error)}\n`)
      }
    })

  program
    .command('review')
    .description('Append a human or external review event for a specific stored scan record.')
    .argument('<record_id>', 'Stored scan record id returned by depgraph scan')
    .option('--target <target_id>', 'Explicit review target id from scan findings or changed edges')
    .requiredOption(
      '--outcome <outcome>',
      'Review outcome: malicious, benign, or needs_review',
      parseReviewOutcome,
    )
    .option('--notes <text>', 'Reviewer notes to persist with the review event')
    .option('--source <source>', 'Review source: human, auto, or external', parseReviewSource, 'human')
    .option('--confidence <number>', 'Optional review confidence from 0 to 1', parseConfidence)
    .option('--json', 'Emit deterministic JSON output')
    .addHelpText(
      'after',
      [
        '',
        'Examples:',
        '  depgraph review 2026-04-02T00:00:00.000Z:lodash@4.17.21:depth=3 --target package_finding:lodash@4.17.21 --outcome benign',
        '  depgraph review scan-record-id --target edge_finding:direct:root@1.0.0->new-child@1.0.0 --outcome needs_review --notes "edge changed unexpectedly"',
        '  depgraph review scan-record-id --target package_finding:child@1.0.0 --outcome malicious --source external --confidence 0.92 --json',
      ].join('\n'),
    )
    .action(async (recordId: string, options) => {
      try {
        const result = await runtime.reviewScan({
          record_id: recordId,
          target_id: typeof options.target === 'string' ? options.target : undefined,
          outcome: options.outcome,
          notes: typeof options.notes === 'string' ? options.notes : null,
          review_source: options.source,
          confidence: options.confidence ?? null,
        })

        if (options.json === true) {
          runtime.stdout.write(`${runtime.renderReviewJson(result)}\n`)
        } else {
          runtime.stdout.write(`${runtime.renderReviewPlainText(result)}\n`)
        }

        exitCode = 0
      } catch (error) {
        exitCode = mapErrorToExitCode(error)
        runtime.stderr.write(`${getErrorMessage(error)}\n`)
      }
    })

  program
    .command('eval')
    .description('Summarize stored scan and review coverage for the local dataset.')
    .option('--json', 'Emit deterministic JSON output')
    .option('--failures', 'Surface known failure-pattern matches from persisted scan history')
    .action(async (options) => {
      try {
        if (options.failures === true) {
          const result = await runtime.evaluateFailures()

          if (options.json === true) {
            runtime.stdout.write(`${runtime.renderFailureJson(result)}\n`)
          } else {
            runtime.stdout.write(`${runtime.renderFailurePlainText(result)}\n`)
          }
        } else {
          const result = await runtime.evaluateScans()

          if (options.json === true) {
            runtime.stdout.write(`${runtime.renderEvaluationJson(result)}\n`)
          } else {
            runtime.stdout.write(`${runtime.renderEvaluationPlainText(result)}\n`)
          }
        }

        exitCode = 0
      } catch (error) {
        exitCode = mapErrorToExitCode(error)
        runtime.stderr.write(`${getErrorMessage(error)}\n`)
      }
    })

  try {
    await program.parseAsync(argv, {
      from: 'user',
    })
    return exitCode
  } catch (error) {
    if (error instanceof CommanderError) {
      if (error.code === 'commander.helpDisplayed') {
        return 0
      }

      return 2
    }

    throw error
  }
}

async function createRuntime(overrides: Partial<CliRuntime>): Promise<CliRuntime> {
  if (isCompleteRuntime(overrides)) {
    return overrides
  }

  const [
    { JsonlScanReviewStore, defaultScanReviewStorePaths },
    { PackageLockDependencyTraverser },
    { NodeProjectScanResolver },
    { PnpmLockDependencyTraverser },
    { RegistryDependencyTraverser },
    { HeuristicRiskScorer },
    { createEvaluateFailuresUseCase },
    { createResolveReviewStateIndexUseCase },
    { NpmPackageMetadataSource },
    { createEvaluateScansUseCase },
    { createReviewScanUseCase },
    { createScanPackageUseCase },
    { renderInk },
    { renderFailureSurfacingJson, renderFailureSurfacingPlainText },
    { renderEvaluationJson, renderEvaluationPlainText },
    { renderJson },
    { renderPlainText },
    { renderReviewJson, renderReviewPlainText },
  ] = await Promise.all([
    import('../adapters/jsonl-scan-review-store.js'),
    import('../adapters/package-lock-dependency-traverser.js'),
    import('../adapters/project-scan-resolver.js'),
    import('../adapters/pnpm-lock-dependency-traverser.js'),
    import('../adapters/registry-dependency-traverser.js'),
    import('../adapters/heuristic-risk-scorer.js'),
    import('../application/evaluate-failures.js'),
    import('../application/resolve-review-state-index.js'),
    import('../adapters/npm-package-metadata-source.js'),
    import('../application/evaluate-scans.js'),
    import('../application/review-scan.js'),
    import('../application/scan-package.js'),
    import('../interface/console-renderer.js'),
    import('../interface/evaluation-failure-renderer.js'),
    import('../interface/evaluation-renderer.js'),
    import('../interface/json-renderer.js'),
    import('../interface/plain-text-renderer.js'),
    import('../interface/review-renderer.js'),
  ])

  const reviewStore = new JsonlScanReviewStore(defaultScanReviewStorePaths(process.cwd()))
  const resolveReviewStateIndex = createResolveReviewStateIndexUseCase({
    reviewEventSource: reviewStore,
  })
  const metadataSource = new NpmPackageMetadataSource()
  const registryTraverser = new RegistryDependencyTraverser(metadataSource)
  const packageLockTraverser = new PackageLockDependencyTraverser(metadataSource)
  const pnpmLockTraverser = new PnpmLockDependencyTraverser(metadataSource)
  const projectScanResolver = new NodeProjectScanResolver()
  const scorer = new HeuristicRiskScorer()

  return {
    scanPackage: createScanPackageUseCase({
      registryTraverser,
      packageLockTraverser,
      pnpmLockTraverser,
      scorer,
      reviewStore,
    }),
    resolveProjectScan: async (projectPath: string) => {
      const resolved = await projectScanResolver.resolve(projectPath)
      switch (resolved.scan_mode) {
        case 'package_lock':
          return {
            scan_mode: 'package_lock',
            package_lock_path: resolved.package_lock_path!,
            project_root: resolved.project_root,
            max_depth: DEFAULT_MAX_DEPTH,
            threshold: DEFAULT_THRESHOLD,
            verbose: false,
            workspace_identity: resolved.project_root,
          }
        case 'pnpm_lock':
          return {
            scan_mode: 'pnpm_lock',
            pnpm_lock_path: resolved.pnpm_lock_path!,
            project_root: resolved.project_root,
            max_depth: DEFAULT_MAX_DEPTH,
            threshold: DEFAULT_THRESHOLD,
            verbose: false,
            workspace_identity: resolved.project_root,
          }
      }
    },
    reviewScan: createReviewScanUseCase({
      reviewStore,
    }),
    evaluateFailures: createEvaluateFailuresUseCase({
      scanRecordSource: reviewStore,
    }),
    evaluateScans: createEvaluateScansUseCase({
      scanRecordSource: reviewStore,
      rawReviewEventSource: reviewStore,
      resolveReviewStateIndex,
    }),
    renderJson,
    renderPlainText,
    renderReviewJson,
    renderReviewPlainText,
    renderFailureJson: renderFailureSurfacingJson,
    renderFailurePlainText: renderFailureSurfacingPlainText,
    renderEvaluationJson,
    renderEvaluationPlainText,
    renderInk,
    stdout: process.stdout,
    stderr: process.stderr,
    isTty: Boolean(process.stdout.isTTY),
    ...overrides,
  }
}

function isCompleteRuntime(overrides: Partial<CliRuntime>): overrides is CliRuntime {
  return (
    overrides.scanPackage !== undefined &&
    overrides.resolveProjectScan !== undefined &&
    overrides.reviewScan !== undefined &&
    overrides.evaluateScans !== undefined &&
    overrides.evaluateFailures !== undefined &&
    overrides.renderJson !== undefined &&
    overrides.renderPlainText !== undefined &&
    overrides.renderReviewJson !== undefined &&
    overrides.renderReviewPlainText !== undefined &&
    overrides.renderFailureJson !== undefined &&
    overrides.renderFailurePlainText !== undefined &&
    overrides.renderEvaluationJson !== undefined &&
    overrides.renderEvaluationPlainText !== undefined &&
    overrides.renderInk !== undefined &&
    overrides.stdout !== undefined &&
    overrides.stderr !== undefined &&
    overrides.isTty !== undefined
  )
}

async function resolveScanRequest(
  packageSpec: string | undefined,
  options: {
    packageLock?: string
    pnpmLock?: string
    project?: string
    depth: number
    threshold: number
    verbose: boolean
  },
  runtime: CliRuntime,
): Promise<ScanRequest> {
  const selectedInputs = [packageSpec, options.packageLock, options.pnpmLock, options.project].filter(
    (value) => typeof value === 'string' && value.trim().length > 0,
  )

  if (selectedInputs.length !== 1) {
    throw new InvalidUsageError(
      'Provide exactly one of <package_spec>, --package-lock, --pnpm-lock, or --project.',
    )
  }

  if (typeof packageSpec === 'string' && packageSpec.trim().length > 0) {
    return {
      scan_mode: 'registry_package',
      package_spec: packageSpec,
      max_depth: options.depth,
      threshold: options.threshold,
      verbose: Boolean(options.verbose),
      workspace_identity: process.cwd(),
    }
  }

  if (typeof options.packageLock === 'string' && options.packageLock.trim().length > 0) {
    const { resolvePackageLockScan } = await import('../adapters/project-scan-resolver.js')
    const resolved = resolvePackageLockScan(options.packageLock)

    return {
      scan_mode: 'package_lock',
      package_lock_path: resolved.package_lock_path,
      project_root: resolved.project_root,
      max_depth: options.depth,
      threshold: options.threshold,
      verbose: Boolean(options.verbose),
      workspace_identity: dirname(resolved.package_lock_path),
    }
  }

  if (typeof options.pnpmLock === 'string' && options.pnpmLock.trim().length > 0) {
    const { resolvePnpmLockScan } = await import('../adapters/project-scan-resolver.js')
    const resolved = resolvePnpmLockScan(options.pnpmLock)

    return {
      scan_mode: 'pnpm_lock',
      pnpm_lock_path: resolved.pnpm_lock_path!,
      project_root: resolved.project_root,
      max_depth: options.depth,
      threshold: options.threshold,
      verbose: Boolean(options.verbose),
      workspace_identity: resolved.project_root,
    }
  }

  const resolved = await runtime.resolveProjectScan(options.project!)
  switch (resolved.scan_mode) {
    case 'package_lock':
      return {
        scan_mode: 'package_lock',
        package_lock_path: resolved.package_lock_path,
        project_root: resolved.project_root,
        max_depth: options.depth,
        threshold: options.threshold,
        verbose: Boolean(options.verbose),
        workspace_identity: resolved.project_root,
      }
    case 'pnpm_lock':
      return {
        scan_mode: 'pnpm_lock',
        pnpm_lock_path: resolved.pnpm_lock_path,
        project_root: resolved.project_root,
        max_depth: options.depth,
        threshold: options.threshold,
        verbose: Boolean(options.verbose),
        workspace_identity: resolved.project_root,
      }
  }
}

function parseDepth(value: string): number {
  const parsed = Number.parseInt(value, 10)

  if (!Number.isInteger(parsed) || parsed < 0) {
    throw new InvalidArgumentError('Depth must be a non-negative integer.')
  }

  return parsed
}

function parseThreshold(value: string): number {
  const parsed = Number.parseFloat(value)

  if (!Number.isFinite(parsed) || parsed < 0 || parsed > 1) {
    throw new InvalidArgumentError('Threshold must be a number between 0 and 1.')
  }

  return parsed
}

function parseReviewOutcome(value: string): ReviewOutcome {
  if (value === 'malicious' || value === 'benign' || value === 'needs_review') {
    return value
  }

  throw new InvalidArgumentError('Outcome must be one of: malicious, benign, needs_review.')
}

function parseReviewSource(value: string): ReviewSource {
  if (value === 'human' || value === 'auto' || value === 'external') {
    return value
  }

  throw new InvalidArgumentError('Source must be one of: human, auto, external.')
}

function parseConfidence(value: string): number {
  const parsed = Number.parseFloat(value)

  if (!Number.isFinite(parsed) || parsed < 0 || parsed > 1) {
    throw new InvalidArgumentError('Confidence must be a number between 0 and 1.')
  }

  return Number(parsed.toFixed(2))
}

function mapErrorToExitCode(error: unknown): number {
  if (error instanceof InvalidUsageError) {
    return 2
  }

  if (error instanceof NetworkFailureError) {
    return 3
  }

  if (error instanceof StorageFailureError) {
    return 3
  }

  return 3
}

function getErrorMessage(error: unknown): string {
  if (error instanceof Error) {
    return error.message
  }

  return String(error)
}

if (import.meta.main) {
  run(process.argv.slice(2))
    .then((code) => {
      process.exitCode = code
    })
    .catch((error) => {
      process.stderr.write(`${getErrorMessage(error)}\n`)
      process.exitCode = mapErrorToExitCode(error)
    })
}
