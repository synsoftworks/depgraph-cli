import { spawn } from 'node:child_process'
import { resolve } from 'node:path'

import type { BenchmarkScanRunner } from '../domain/benchmark.js'
import type { ScanResult } from '../domain/entities.js'

export class CliBenchmarkScanRunner implements BenchmarkScanRunner {
  constructor(
    private readonly cliEntryPoint = resolve(process.cwd(), 'dist/cli/index.js'),
    private readonly nodeExecutable = process.execPath,
  ) {}

  async runScan(packageSpec: string): Promise<ScanResult> {
    const commandResult = await runCommand(this.nodeExecutable, [
      this.cliEntryPoint,
      'scan',
      packageSpec,
      '--json',
    ])

    const stdout = commandResult.stdout.trim()

    if (stdout.length === 0) {
      throw new Error(commandResult.stderr.trim() || `scan command exited with code ${commandResult.exitCode}`)
    }

    try {
      return JSON.parse(stdout) as ScanResult
    } catch (error) {
      throw new Error(
        `scan output for "${packageSpec}" was not valid JSON: ${getErrorMessage(error)}`,
      )
    }
  }
}

interface CommandResult {
  exitCode: number | null
  stdout: string
  stderr: string
}

function runCommand(command: string, args: string[]): Promise<CommandResult> {
  return new Promise((resolvePromise, rejectPromise) => {
    const child = spawn(command, args, {
      stdio: ['ignore', 'pipe', 'pipe'],
    })
    let stdout = ''
    let stderr = ''

    child.stdout.on('data', (chunk: Buffer | string) => {
      stdout += chunk.toString()
    })

    child.stderr.on('data', (chunk: Buffer | string) => {
      stderr += chunk.toString()
    })

    child.on('error', (error) => {
      rejectPromise(error)
    })

    child.on('close', (exitCode) => {
      if (exitCode !== 0 && exitCode !== 1 && stdout.trim().length === 0) {
        rejectPromise(new Error(stderr.trim() || `scan command exited with code ${exitCode}`))
        return
      }

      resolvePromise({
        exitCode,
        stdout,
        stderr,
      })
    })
  })
}

function getErrorMessage(error: unknown): string {
  if (error instanceof Error) {
    return error.message
  }

  return String(error)
}
