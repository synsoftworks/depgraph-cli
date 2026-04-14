// Prefer structured CVE identifiers over bare "cve" so incidental references
// do not count as security-related deprecation evidence without an actual id.
const SECURITY_RELATED_DEPRECATION_PATTERN =
  /\b(?:security|vulnerab(?:ility|ilities)|cve-\d{4}-\d+)\b/i

/**
 * Detects whether a deprecation message should be treated as security-related.
 *
 * @param message Deprecation message from package metadata or persisted history.
 * @returns `true` when the message includes security language or a structured CVE identifier.
 */
export function isSecurityRelatedDeprecation(message: string): boolean {
  return SECURITY_RELATED_DEPRECATION_PATTERN.test(message)
}
