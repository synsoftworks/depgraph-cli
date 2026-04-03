#!/usr/bin/env node

import { Command, CommanderError, InvalidArgumentError } from 'commander'

import type {
  EvaluationSummary,
  ReviewEvent,
  ReviewScanRequest,
  ScanRequest,
} from '../domain/contracts.js'
import type { ReviewOutcome, ReviewSource, ScanResult } from '../domain/entities.js'
import { InvalidUsageError, NetworkFailureError, StorageFailureError } from '../domain/errors.js'
import { DEFAULT_MAX_DEPTH, DEFAULT_THRESHOLD } from '../domain/value-objects.js'

interface WritableStreamLike {
  write(text: string): void
}

export interface CliRuntime {
  scanPackage: (request: ScanRequest) => Promise<ScanResult>
  reviewScan: (request: ReviewScanRequest) => Promise<ReviewEvent>
  evaluateScans: () => Promise<EvaluationSummary>
  renderJson: (result: ScanResult) => string
  renderPlainText: (result: ScanResult) => string
  renderReviewJson: (event: ReviewEvent) => string
  renderReviewPlainText: (event: ReviewEvent) => string
  renderEvaluationJson: (summary: EvaluationSummary) => string
  renderEvaluationPlainText: (summary: EvaluationSummary) => string
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
    .description('Scan an npm package and its current resolved dependency tree projection for suspicious metadata patterns.')
    .argument('<package_spec>', 'Package name with optional version or range, for example lodash@4.17.21')
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
        '  v1 scans a resolved dependency tree view from registry metadata.',
        '  Shared packages may appear under a single path in the current view.',
        '',
        'Examples:',
        '  depgraph scan lodash@4.17.21',
        '  depgraph scan lodash --json',
        '  depgraph scan @types/node --no-tui --depth 2',
      ].join('\n'),
    )
    .action(async (packageSpec: string, options) => {
      try {
        const result = await runtime.scanPackage({
          package_spec: packageSpec,
          max_depth: options.depth,
          threshold: options.threshold,
          verbose: Boolean(options.verbose),
          workspace_identity: process.cwd(),
        })

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
    .action(async (options) => {
      try {
        const result = await runtime.evaluateScans()

        if (options.json === true) {
          runtime.stdout.write(`${runtime.renderEvaluationJson(result)}\n`)
        } else {
          runtime.stdout.write(`${runtime.renderEvaluationPlainText(result)}\n`)
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
    { RegistryDependencyTraverser },
    { HeuristicRiskScorer },
    { createResolveReviewStateIndexUseCase },
    { NpmPackageMetadataSource },
    { createEvaluateScansUseCase },
    { createReviewScanUseCase },
    { createScanPackageUseCase },
    { renderInk },
    { renderEvaluationJson, renderEvaluationPlainText },
    { renderJson },
    { renderPlainText },
    { renderReviewJson, renderReviewPlainText },
  ] = await Promise.all([
    import('../adapters/jsonl-scan-review-store.js'),
    import('../adapters/registry-dependency-traverser.js'),
    import('../adapters/heuristic-risk-scorer.js'),
    import('../application/resolve-review-state-index.js'),
    import('../adapters/npm-package-metadata-source.js'),
    import('../application/evaluate-scans.js'),
    import('../application/review-scan.js'),
    import('../application/scan-package.js'),
    import('../interface/console-renderer.js'),
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
  const traverser = new RegistryDependencyTraverser(metadataSource)
  const scorer = new HeuristicRiskScorer()

  return {
    scanPackage: createScanPackageUseCase({
      traverser,
      scorer,
      reviewStore,
    }),
    reviewScan: createReviewScanUseCase({
      reviewStore,
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
    overrides.reviewScan !== undefined &&
    overrides.evaluateScans !== undefined &&
    overrides.renderJson !== undefined &&
    overrides.renderPlainText !== undefined &&
    overrides.renderReviewJson !== undefined &&
    overrides.renderReviewPlainText !== undefined &&
    overrides.renderEvaluationJson !== undefined &&
    overrides.renderEvaluationPlainText !== undefined &&
    overrides.renderInk !== undefined &&
    overrides.stdout !== undefined &&
    overrides.stderr !== undefined &&
    overrides.isTty !== undefined
  )
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
