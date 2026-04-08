import assert from 'node:assert/strict'
import test from 'node:test'

import { isSecurityRelatedDeprecation } from '../src/domain/security-deprecation.js'

test('shared security-deprecation classifier matches security vulnerability language', () => {
  assert.equal(
    isSecurityRelatedDeprecation('This version has a security vulnerability. Please upgrade.'),
    true,
  )
})

test('shared security-deprecation classifier matches structured CVE identifiers', () => {
  assert.equal(
    isSecurityRelatedDeprecation('See CVE-2025-12345 for details.'),
    true,
  )
})

test('shared security-deprecation classifier does not match bare cve references', () => {
  assert.equal(
    isSecurityRelatedDeprecation('See the cve guidance page for more information.'),
    false,
  )
})
