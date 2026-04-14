import type { PackageNode } from './entities.js'

/** Observation state for a metadata field after missingness interpretation. */
export type MetadataFieldObservation =
  | 'observed_present'
  | 'observed_absent'
  | 'unavailable'
  | 'not_applicable'

/** Reason explaining why a metadata field has its current observation state. */
export type MetadataFieldStateReason =
  | 'explicit_value'
  | 'not_collected_yet'
  | 'registry_metadata_unavailable'
  | 'synthetic_project_root'

/** Interpreted metadata-field state for downstream export and modeling code. */
export interface MetadataFieldState<T> {
  observation: MetadataFieldObservation
  value: T | null
  reason: MetadataFieldStateReason
}

/**
 * Central contract for metadata-field missingness.
 *
 * Raw scan fields can look ordinary even when DepGraph has not collected them
 * yet. Downstream export/modeling code must interpret ambiguous fields through
 * these helpers instead of inferring meaning directly from `null` or `false`.
 *
 * This contract distinguishes between "observed absence" and "not collected yet".
 * Fields that are not currently ingested MUST return `unavailable`, not
 * `observed_absent`.
 *
 * `observed_absent` is part of the contract for fields that are explicitly
 * checked clean, but current advisory ingestion does not produce that state yet.
 */
export type PackageNodeMetadataField = 'dependents_count' | 'has_advisories'

/**
 * Creates a state representing an observed non-missing metadata value.
 *
 * @param value Observed field value.
 * @returns Metadata field state marked as observed present.
 */
export function observedPresentMetadataFieldState<T>(value: T): MetadataFieldState<T> {
  return {
    observation: 'observed_present',
    value,
    reason: 'explicit_value',
  }
}

/**
 * Creates a state representing an observed explicit absence.
 *
 * @param value Field value that encodes a checked-clean or otherwise observed absence.
 * @returns Metadata field state marked as observed absent.
 */
export function observedAbsentMetadataFieldState<T>(value: T): MetadataFieldState<T> {
  return {
    observation: 'observed_absent',
    value,
    reason: 'explicit_value',
  }
}

/**
 * Creates a state representing an unavailable metadata value.
 *
 * @param reason Reason the field is unavailable.
 * @returns Metadata field state marked as unavailable.
 */
export function unavailableMetadataFieldState<T>(
  reason: Extract<
    MetadataFieldStateReason,
    'not_collected_yet' | 'registry_metadata_unavailable'
  >,
): MetadataFieldState<T> {
  return {
    observation: 'unavailable',
    value: null,
    reason,
  }
}

/** Creates a state representing a field that does not apply to the current node. */
export function notApplicableMetadataFieldState<T>(): MetadataFieldState<T> {
  return {
    observation: 'not_applicable',
    value: null,
    reason: 'synthetic_project_root',
  }
}

/**
 * Checks whether a metadata field was actually observed.
 *
 * @param state Interpreted metadata field state.
 * @returns `true` when the field was observed present or observed absent.
 */
export function isObservedMetadataField<T>(state: MetadataFieldState<T>): boolean {
  return (
    state.observation === 'observed_present'
    || state.observation === 'observed_absent'
  )
}

export function getPackageNodeMetadataFieldState(
  node: PackageNode,
  field: 'dependents_count',
): MetadataFieldState<number>
export function getPackageNodeMetadataFieldState(
  node: PackageNode,
  field: 'has_advisories',
): MetadataFieldState<boolean>
/**
 * Interprets a raw package-node metadata field through the missingness contract.
 *
 * @param node Package node carrying raw field values.
 * @param field Metadata field to interpret.
 * @returns Interpreted field state suitable for export and modeling code.
 */
export function getPackageNodeMetadataFieldState(
  node: PackageNode,
  field: PackageNodeMetadataField,
): MetadataFieldState<number | boolean> {
  if (node.is_project_root || node.metadata_status === 'synthetic_project_root') {
    return notApplicableMetadataFieldState()
  }

  if (node.metadata_status === 'unresolved_registry_lookup') {
    return unavailableMetadataFieldState('registry_metadata_unavailable')
  }

  switch (field) {
    case 'dependents_count':
      return node.dependents_count === null
        ? unavailableMetadataFieldState('not_collected_yet')
        : observedPresentMetadataFieldState(node.dependents_count)
    case 'has_advisories':
      return node.has_advisories === true
        ? observedPresentMetadataFieldState(true)
        : unavailableMetadataFieldState('not_collected_yet')
  }
}
