import type { ResolvedReviewState } from '../domain/contracts.js'
import type { ScanReviewStore } from '../domain/ports.js'
import { buildResolvedReviewStateIndex } from './resolve-review-state.js'

interface ResolveReviewStateIndexDependencies {
  reviewEventSource: Pick<ScanReviewStore, 'listReviewEvents'>
}

/**
 * Label-aware application code should depend on this boundary rather than
 * interpreting raw `ReviewEvent` history directly.
 */
export function createResolveReviewStateIndexUseCase({
  reviewEventSource,
}: ResolveReviewStateIndexDependencies) {
  return async function resolveReviewStateIndex(): Promise<
    ReadonlyMap<string, ResolvedReviewState>
  > {
    const rawReviewEvents = await reviewEventSource.listReviewEvents()

    return buildResolvedReviewStateIndex(rawReviewEvents)
  }
}
