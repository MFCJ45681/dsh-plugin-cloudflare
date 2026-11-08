'use strict'

/**
 * Regression tests for the request-level defences: method allowlists, the JSON
 * content-type requirement, same-origin checks and the Host allowlist that keeps
 * DNS-rebinding pages from talking to the plugin.
 */

const test = require('node:test')
const assert = require('node:assert')
const http = require('node:http')
const fs = require('node:fs')
const os = require('node:os')
const path = require('node:path')

const { VaultStore } = require('../lib/vault')
const { PendingStates } = require('../lib/state')
const { createRoutes } = require('../lib/routes')

/**
 * @returns {Promise<{origin: string, port: number, close: () => Promise<void>, store: VaultStore, dir: string}>}
 */
async function startServer () {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'cf-sec-'))
  const store = new VaultStore({ dataDir: dir })
  store.ensure()
  const { routes } = createRoutes({
    store,
    states: new PendingStates(),
    cache: new Map(),
    port: () => server.address().port
  })
  const server = http.createServer((req, res) => {
    const url = new URL(req.url || '/', 'http://localhost')
    const route = routes.find((item) => item.path === url.pathname)
    if (route === undefined) {
      res.writeHead(404)
      res.end()
      return
    }
    route.handler(req, res)
  })
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve))
  const port = server.address().port
  return {
    origin: `http://127.0.0.1:${port}`,
    port,
    store,
    dir,
    close: () => new Promise((resolve) => server.close(resolve))
  }
}

/**
 * @param {string} origin
 * @param {string} pathname
 * @param {{method?: string, headers?: Record<string, string>, body?: string}} [options]
 */
function request (origin, pathname, options = {}) {
  const url = new URL(pathname, origin)
  return new Promise((resolve, reject) => {
    const req = http.request(url, {
      method: options.method || 'GET',
      headers: options.headers || {}
    }, (res) => {
      const chunks = []
      res.on('data', (chunk) => chunks.push(chunk))
      res.on('end', () => resolve({
        status: res.statusCode,
        headers: res.headers,
        body: Buffer.concat(chunks).toString('utf8')
      }))
    })
    req.on('error', reject)
    if (options.body !== undefined) req.write(options.body)
    req.end()
  })
}

test('state-changing routes reject the wrong method with 405', async () => {
  const server = await startServer()
  try {
    const logout = await request(server.origin, '/plugins/cloudflare/logout')
    assert.equal(logout.status, 405)
    assert.match(String(logout.headers.allow), /POST/)
    assert.match(logout.body, /E_METHOD/)

    // A GET on /config was the classic `<img src=...>` CSRF shape.
    const config = await request(server.origin, '/plugins/cloudflare/config')
    assert.equal(config.status, 200)
    const write = await request(server.origin, '/plugins/cloudflare/config', { method: 'PUT' })
    assert.equal(write.status, 405)
  } finally {
    await server.close()
    fs.rmSync(server.dir, { recursive: true, force: true })
  }
})

test('a non-JSON body is refused so simple-request CSRF cannot pass', async () => {
  const server = await startServer()
  try {
    const body = JSON.stringify({ clientId: 'attacker-client' })
    const plain = await request(server.origin, '/plugins/cloudflare/config', {
      method: 'POST',
      headers: { 'content-type': 'text/plain' },
      body
    })
    assert.equal(plain.status, 415)
    assert.match(plain.body, /E_CONTENT_TYPE/)

    const form = await request(server.origin, '/plugins/cloudflare/config', {
      method: 'POST',
      headers: { 'content-type': 'application/x-www-form-urlencoded' },
      body
    })
    assert.equal(form.status, 415)
  } finally {
    await server.close()
    fs.rmSync(server.dir, { recursive: true, force: true })
  }
})

test('cross-site writes are rejected by the origin check', async () => {
  const server = await startServer()
  try {
    const body = JSON.stringify({ clientId: 'attacker-client' })
    const crossOrigin = await request(server.origin, '/plugins/cloudflare/config', {
      method: 'POST',
      headers: { 'content-type': 'application/json', origin: 'http://evil.example' },
      body
    })
    assert.equal(crossOrigin.status, 403)
    assert.match(crossOrigin.body, /E_ORIGIN/)

    const crossSite = await request(server.origin, '/plugins/cloudflare/config', {
      method: 'POST',
      headers: { 'content-type': 'application/json', 'sec-fetch-site': 'cross-site' },
      body
    })
    assert.equal(crossSite.status, 403)

    const sameOrigin = await request(server.origin, '/plugins/cloudflare/config', {
      method: 'POST',
      headers: {
        'content-type': 'application/json',
        origin: server.origin,
        'sec-fetch-site': 'same-origin'
      },
      body
    })
    assert.equal(sameOrigin.status, 200)
  } finally {
    await server.close()
    fs.rmSync(server.dir, { recursive: true, force: true })
  }
})

test('a rebound domain name in the Host header is refused, literal IPs are fine', async () => {
  const server = await startServer()
  try {
    const rebound = await request(server.origin, '/plugins/cloudflare/status', {
      headers: { host: 'evil.example' }
    })
    assert.equal(rebound.status, 421)
    assert.match(rebound.body, /E_HOST/)

    const lan = await request(server.origin, '/plugins/cloudflare/status', {
      headers: { host: `192.168.1.20:${server.port}` }
    })
    assert.equal(lan.status, 200)

    const loopback = await request(server.origin, '/plugins/cloudflare/status', {
      headers: { host: `127.0.0.1:${server.port}` }
    })
    assert.equal(loopback.status, 200)
  } finally {
    await server.close()
    fs.rmSync(server.dir, { recursive: true, force: true })
  }
})

test('the built-in client id is seeded, encrypted, and overridable', async () => {
  const server = await startServer()
  try {
    const { DEFAULT_CLIENT_ID, DEFAULT_SCOPE } = require('../lib/defaults')
    const seeded = server.store.seedDefaults({ clientId: DEFAULT_CLIENT_ID, scope: DEFAULT_SCOPE })
    assert.equal(seeded.source, 'default')
    assert.equal(seeded.clientId, DEFAULT_CLIENT_ID)

    const onDisk = fs.readFileSync(server.store.vaultPath, 'utf8')
    assert.equal(onDisk.includes(DEFAULT_CLIENT_ID), false, 'vault must not contain the client id in the clear')

    const redirectUri = 'http://127.0.0.1:3080/plugins/cloudflare/callback'
    const user = server.store.configureClient({ clientId: 'user-supplied-id', scope: 'zone.read', redirectUri })
    assert.equal(user.source, 'user')
    const back = server.store.configureClient({ clientId: DEFAULT_CLIENT_ID, scope: 'zone.read', redirectUri, source: 'default' })
    assert.equal(back.source, 'default')
  } finally {
    await server.close()
    fs.rmSync(server.dir, { recursive: true, force: true })
  }
})

test('an identity key never contains token bytes', async () => {
  const { createRoutes } = require('../lib/routes')
  assert.equal(typeof createRoutes, 'function')
  const source = fs.readFileSync(path.join(__dirname, '..', 'lib', 'routes.js'), 'utf8')
  assert.equal(/accessToken\.slice\(/.test(source), false, 'token fragments must not become identity keys')
})
