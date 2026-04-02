import assert from 'node:assert/strict'
import test from 'node:test'

import { NpmPackageMetadataSource } from '../src/adapters/npm-package-metadata-source.js'

test('metadata source uses registry time fields and never falls back to Unix epoch', async () => {
  const source = new NpmPackageMetadataSource(async (input) => {
    const url = String(input)

    if (url.startsWith('https://api.npmjs.org/downloads/')) {
      return new Response(JSON.stringify({ downloads: 42 }), {
        status: 200,
        headers: { 'content-type': 'application/json' },
      })
    }

    return new Response(
      JSON.stringify({
        name: 'demo-package',
        'dist-tags': {
          latest: '1.2.3',
        },
        versions: {
          '1.2.3': {
            version: '1.2.3',
            dependencies: {},
          },
        },
        time: {
          created: '2014-09-02T01:28:28.167Z',
          modified: '2024-01-15T10:22:33.000Z',
          '1.2.3': '2024-01-15T10:22:33.000Z',
        },
      }),
      {
        status: 200,
        headers: { 'content-type': 'application/json' },
      },
    )
  })

  const metadata = await source.resolvePackage({
    name: 'demo-package',
  })

  assert.equal(metadata.published_at, '2024-01-15T10:22:33.000Z')
  assert.equal(metadata.first_published_at, '2014-09-02T01:28:28.167Z')
  assert.equal(metadata.last_published_at, '2024-01-15T10:22:33.000Z')
  assert.equal(metadata.deprecated_message, null)
  assert.equal(metadata.is_security_tombstone, false)
  assert.equal(metadata.dependents_count, null)
  assert.notEqual(metadata.published_at, '1970-01-01T00:00:00.000Z')
})

test('metadata source marks npm security tombstones and ignores inherited download counts', async () => {
  const source = new NpmPackageMetadataSource(async (input) => {
    const url = String(input)

    if (url.startsWith('https://api.npmjs.org/downloads/')) {
      return new Response(JSON.stringify({ downloads: 276062 }), {
        status: 200,
        headers: { 'content-type': 'application/json' },
      })
    }

    return new Response(
      JSON.stringify({
        name: 'plain-crypto-js',
        'dist-tags': {
          latest: '0.0.1-security.0',
        },
        versions: {
          '0.0.1-security.0': {
            version: '0.0.1-security.0',
            dependencies: {},
            deprecated: 'security placeholder package; original package was malicious',
          },
        },
        time: {
          created: '2026-03-31T04:26:32.907Z',
          modified: '2026-03-31T04:26:35.731Z',
          '0.0.1-security.0': '2026-03-31T04:26:33.055Z',
        },
      }),
      {
        status: 200,
        headers: { 'content-type': 'application/json' },
      },
    )
  })

  const metadata = await source.resolvePackage({ name: 'plain-crypto-js' })

  assert.equal(metadata.is_security_tombstone, true)
  assert.match(metadata.deprecated_message ?? '', /security placeholder/i)
  assert.equal(metadata.weekly_downloads, null)
})

test('metadata source throws when publish timestamps are unavailable', async () => {
  const source = new NpmPackageMetadataSource(async (input) => {
    const url = String(input)

    if (url.startsWith('https://api.npmjs.org/downloads/')) {
      return new Response(JSON.stringify({ downloads: 42 }), {
        status: 200,
        headers: { 'content-type': 'application/json' },
      })
    }

    return new Response(
      JSON.stringify({
        name: 'demo-package',
        'dist-tags': {
          latest: '1.2.3',
        },
        versions: {
          '1.2.3': {
            version: '1.2.3',
            dependencies: {},
          },
        },
      }),
      {
        status: 200,
        headers: { 'content-type': 'application/json' },
      },
    )
  })

  await assert.rejects(
    source.resolvePackage({ name: 'demo-package' }),
    /does not include publish timestamps/,
  )
})

test('metadata source fetches packument and downloads concurrently', async () => {
  let activeRequests = 0
  let maxActiveRequests = 0

  const source = new NpmPackageMetadataSource(async (input) => {
    const url = String(input)

    activeRequests += 1
    maxActiveRequests = Math.max(maxActiveRequests, activeRequests)

    await new Promise((resolve) => setTimeout(resolve, 10))

    activeRequests -= 1

    if (url.startsWith('https://api.npmjs.org/downloads/')) {
      return new Response(JSON.stringify({ downloads: 42 }), {
        status: 200,
        headers: { 'content-type': 'application/json' },
      })
    }

    return new Response(
      JSON.stringify({
        name: 'demo-package',
        'dist-tags': {
          latest: '1.2.3',
        },
        versions: {
          '1.2.3': {
            version: '1.2.3',
            dependencies: {},
          },
        },
        time: {
          created: '2014-09-02T01:28:28.167Z',
          modified: '2024-01-15T10:22:33.000Z',
          '1.2.3': '2024-01-15T10:22:33.000Z',
        },
      }),
      {
        status: 200,
        headers: { 'content-type': 'application/json' },
      },
    )
  })

  await source.resolvePackage({ name: 'demo-package' })

  assert.equal(maxActiveRequests, 2)
})
