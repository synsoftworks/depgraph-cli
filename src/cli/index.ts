#!/usr/bin/env node

import { Command, CommanderError, InvalidArgumentError } from 'commander'

import type { ScanRequest } from '../domain/contracts.js'
import type { ScanResult } from '../domain/entities.js'
import { InvalidUsageError, NetworkFailureError } from '../domain/errors.js'
import { DEFAULT_MAX_DEPTH, DEFAULT_THRESHOLD } from '../domain/value-objects.js'

interface WritableStreamLike {
  write(text: string): void
}

export interface CliRuntime {
  scanPackage: (request: ScanRequest) => Promise<ScanResult>
  renderJson: (result: ScanResult) => string
  renderPlainText: (result: ScanResult) => string
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
    .description('Graph-first dependency risk analysis for npm packages and dependency trees.')
    .configureOutput({
      writeOut: (text) => runtime.stdout.write(text),
      writeErr: (text) => runtime.stderr.write(text),
    })
    .showHelpAfterError()
    .showSuggestionAfterError()
    .exitOverride()

  program
    .command('scan')
    .description('Scan an npm package and dependency graph for suspicious metadata patterns.')
    .argument('<package_spec>', 'Package name with optional version or range, for example lodash@4.17.21')
    .option('--json', 'Emit deterministic JSON output')
    .option('--no-tui', 'Emit deterministic plain text instead of Ink output')
    .option('--depth <number>', 'Cap how far the graph is traversed', parseDepth, DEFAULT_MAX_DEPTH)
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
    { RegistryDependencyTraverser },
    { HeuristicRiskScorer },
    { NpmPackageMetadataSource },
    { createScanPackageUseCase },
    { renderInk },
    { renderJson },
    { renderPlainText },
  ] = await Promise.all([
    import('../adapters/registry-dependency-traverser.js'),
    import('../adapters/heuristic-risk-scorer.js'),
    import('../adapters/npm-package-metadata-source.js'),
    import('../application/scan-package.js'),
    import('../interface/console-renderer.js'),
    import('../interface/json-renderer.js'),
    import('../interface/plain-text-renderer.js'),
  ])

  const metadataSource = new NpmPackageMetadataSource()
  const traverser = new RegistryDependencyTraverser(metadataSource)
  const scorer = new HeuristicRiskScorer()

  return {
    scanPackage: createScanPackageUseCase({
      traverser,
      scorer,
    }),
    renderJson,
    renderPlainText,
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
    overrides.renderJson !== undefined &&
    overrides.renderPlainText !== undefined &&
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

function mapErrorToExitCode(error: unknown): number {
  if (error instanceof InvalidUsageError) {
    return 2
  }

  if (error instanceof NetworkFailureError) {
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
