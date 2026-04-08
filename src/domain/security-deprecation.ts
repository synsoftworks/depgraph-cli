// Prefer structured CVE identifiers over bare "cve" so incidental references
// do not count as security-related deprecation evidence without an actual id.
const SECURITY_RELATED_DEPRECATION_PATTERN =
  /\b(?:security|vulnerab(?:ility|ilities)|cve-\d{4}-\d+)\b/i

export function isSecurityRelatedDeprecation(message: string): boolean {
  return SECURITY_RELATED_DEPRECATION_PATTERN.test(message)
}
