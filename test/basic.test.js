'use strict'

/**
 * Unit tests for the parts that do not need the network or a DSH host:
 * the credential envelope, the PKCE/authorize-URL builder, the state store and
 * the scope classifier. Run with `node --test test/`.
 */

const test = require('node:test')
const assert = require('node:assert/strict')
const fs = require('node:fs')
const os = require('node:os')
const path = require('node:path')

const { VaultStore } = require('../lib/vault')
const { PendingStates } = require('../lib/state')
const { createPkce, buildAuthorizeUrl, parseScopes } = require('../lib/oauth')
const { classify, summarize, describe } = require('../lib/scopes')

/** @param {string} label */
function tempDir (label) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), `cfo-${label}-`))
  test.after(() => { try { fs.rmSync(dir, { recursive: true, force: true }) } catch {} })
  return dir
}

test('vault encrypts, round-trips and never stores the token in plaintext', () => {
  const dir = tempDir('vault')
  const store = new VaultStore({ dataDir: dir })
  store.ensure()
  store.configureClient({ clientId: 'client-abc', clientSecret: '', redirectUri: 'http://127.0.0.1:3080/plugins/cloudflare/callback', scope: 'zone.read', method: 'pkce' })
  store.setIdentity('u:1', {
    accessToken: 'super-secret-access-token',
    refreshToken: 'super-secret-refresh-token',
    expiresAt: Date.now() + 3600_000,
    grantedScopes: ['zone.read', 'dns.read'],
    user: { id: '1', email: 'a@example.com', name: 'A' },
    accounts: [{ id: 'acc', name: 'Acc' }]
  })

  const raw = fs.readFileSync(path.join(dir, 'vault.json'), 'utf8')
  assert.equal(raw.includes('super-secret-access-token'), false, 'ciphertext must not contain the token')
  assert.equal(raw.includes('a@example.com'), false, 'ciphertext must not contain the email')

  const status = store.status()
  assert.equal(status.state, 'connected')
  assert.equal(status.email, 'a@example.com')
  assert.equal(status.grantedScopes.length, 2)
  assert.equal(store.identity('u:1').accessToken, 'super-secret-access-token')

  const keyMode = fs.statSync(path.join(dir, 'master.key')).mode & 0o777
  assert.equal(keyMode, 0o600, 'master key must be 0600')
})

test('vault reports a wrong master key without throwing out of status()', () => {
  const dir = tempDir('badkey')
  const first = new VaultStore({ dataDir: dir })
  first.ensure()
  first.setIdentity('u:1', { accessToken: 'x', refreshToken: '', expiresAt: 0, grantedScopes: [], user: {}, accounts: [] })

  const keyPath = path.join(dir, 'master.key')
  fs.writeFileSync(keyPath, Buffer.alloc(32, 7).toString('base64'), { mode: 0o600 })

  const second = new VaultStore({ dataDir: dir })
  assert.throws(() => second.read(), (error) => error.code === 'E_VAULT_DECRYPT')
  const status = second.status()
  assert.equal(status.connected, false, 'a broken vault degrades instead of crashing')
  assert.equal(status.state, 'error')
  assert.equal(status.vault.code, 'E_VAULT_DECRYPT')
  assert.ok(status.vault.error.includes('decryption'))
})

test('pending states are single use, expiring and browser-bindable', () => {
  const states = new PendingStates({ ttlMs: 1000, max: 2 })
  const pending = states.create({ verifier: 'v', redirectUri: 'http://x/cb', scope: '', browserBound: true })
  assert.equal(states.size, 1)
  assert.equal(states.peek(pending.state).verifier, 'v')
  assert.notEqual(states.take(pending.state), null)
  assert.equal(states.take(pending.state), null, 'a state cannot be replayed')
  assert.equal(states.size, 0)

  const capped = new PendingStates({ ttlMs: 1000, max: 1 })
  capped.create({ verifier: 'a', redirectUri: '', scope: '', browserBound: false })
  capped.create({ verifier: 'b', redirectUri: '', scope: '', browserBound: false })
  assert.equal(capped.size, 1, 'the oldest pending state is evicted')
})

test('PKCE produces a base64url verifier and an S256 challenge', () => {
  const pkce = createPkce()
  assert.match(pkce.verifier, /^[A-Za-z0-9_-]{43,128}$/)
  assert.match(pkce.challenge, /^[A-Za-z0-9_-]{43}$/)
  assert.equal(pkce.method, 'S256')
  assert.notEqual(createPkce().verifier, pkce.verifier)
})

test('authorize URL carries PKCE only when a challenge exists', () => {
  const withPkce = new URL(buildAuthorizeUrl({
    clientId: 'cid',
    redirectUri: 'http://127.0.0.1:3080/plugins/cloudflare/callback',
    state: 'st',
    scope: 'zone.read dns.read',
    codeChallenge: 'chal'
  }))
  assert.equal(withPkce.searchParams.get('response_type'), 'code')
  assert.equal(withPkce.searchParams.get('code_challenge'), 'chal')
  assert.equal(withPkce.searchParams.get('code_challenge_method'), 'S256')
  assert.equal(withPkce.searchParams.get('scope'), 'zone.read dns.read')

  const withoutPkce = new URL(buildAuthorizeUrl({ clientId: 'cid', redirectUri: 'http://x/cb', state: 'st', scope: '', codeChallenge: '' }))
  assert.equal(withoutPkce.searchParams.has('code_challenge'), false)
  assert.equal(withoutPkce.searchParams.has('scope'), false, 'an empty scope must not be sent')
})

test('scopes classify by word roots and keep unknown strings', () => {
  assert.deepEqual(classify('zone.read'), ['zoneRead'])
  assert.deepEqual(classify('dns.write'), ['dnsWrite'])
  assert.deepEqual(classify('cache.purge'), ['cachePurge'])
  assert.deepEqual(classify('workers-platform.read'), ['workersRead'])
  assert.deepEqual(classify('account-settings.read'), ['accountRead'])
  assert.deepEqual(classify('something-brand-new.read'), [])

  const summary = summarize(['zone.read', 'dns.read', 'weird.scope'])
  assert.equal(summary.capabilities.zoneRead, true)
  assert.equal(summary.capabilities.dnsRead, true)
  assert.equal(summary.capabilities.dnsWrite, false)
  assert.deepEqual(summary.unknown, ['weird.scope'])

  const lines = describe(['zone.read'])
  assert.ok(lines.some((line) => line.startsWith('✓')))
  assert.ok(lines.some((line) => line.startsWith('✗')))
  assert.deepEqual(parseScopes('a b  c '), ['a', 'b', 'c'])
})
