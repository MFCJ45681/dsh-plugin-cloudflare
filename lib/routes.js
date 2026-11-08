'use strict'

/**
 * HTTP surface of the plugin, mounted on the DSH web server.
 *
 *   GET  /plugins/cloudflare/status       – secret-free connection status
 *   GET  /plugins/cloudflare/bootstrap    – status + capabilities + callback URL (one round trip)
 *   POST /plugins/cloudflare/config       – save OAuth client id / secret / redirect URI / scope
 *   GET  /plugins/cloudflare/start        – create state + PKCE, redirect to Cloudflare
 *   POST /plugins/cloudflare/start        – create state + PKCE, return the authorize URL
 *   GET  /plugins/cloudflare/callback     – exchange the code, store the token, render a result page
 *   GET  /plugins/cloudflare/done         – human-readable result page
 *   POST /plugins/cloudflare/logout       – revoke and forget the stored token
 *   GET  /plugins/cloudflare/accounts     – Cloudflare accounts visible to the token
 *   GET  /plugins/cloudflare/zones        – zones visible to the token
 *   GET  /plugins/cloudflare/scopes       – the scope catalogue Cloudflare publishes
 *   GET  /plugins/cloudflare/preferences  – default account / zone allowlist / readonly
 *   POST /plugins/cloudflare/preferences  – replace those preferences
 *
 * The callback requires the one-time `state` to match both the pending-state
 * store and the HttpOnly cookie set at /start, which blocks login CSRF: a third
 * party cannot make this browser connect to *their* Cloudflare account.
 */

const { discover, createPkce, buildAuthorizeUrl, exchangeCode, fetchUserinfo, revoke, parseScopes, SCOPE_LIST_ENDPOINT } = require('./oauth')
const { AuthError, explainOAuthFailure } = require('./auth')
const { CloudflareApi, CloudflareApiError } = require('./cf-api')
const crypto = require('node:crypto')
const fs = require('node:fs')
const path = require('node:path')
const { VaultError, resolveDataDir } = require('./vault')
const { summarize } = require('./scopes')
const { DEFAULT_CLIENT_ID } = require('./defaults')

const BASE = '/plugins/cloudflare'
const CALLBACK_PATH = `${BASE}/callback`
const STATE_COOKIE = 'cfo_state'
/** Protocol scope Cloudflare requires before it will issue a refresh token. */
const OFFLINE_ACCESS = 'offline_access'
const MAX_BODY_BYTES = 64 * 1024
/** IPv4 dotted quad or an IPv6 address: a client can name an address, but it cannot lie about one. */
const IP_LITERAL = /^(?:(?:\d{1,3}\.){3}\d{1,3}|[0-9a-f]*:[0-9a-f:.]*)$/i

class HttpError extends Error {
  /**
   * @param {number} status
   * @param {string} message
   * @param {string} [code]
   */
  constructor (status, message, code = 'E_REQUEST') {
    super(message)
    this.name = 'HttpError'
    this.status = status
    this.code = code
  }
}

/** @param {import('node:http').ServerResponse} res */
function sendJson (res, status, payload, headers = {}) {
  const body = JSON.stringify(payload)
  res.writeHead(status, {
    'content-type': 'application/json; charset=utf-8',
    'cache-control': 'no-store',
    'x-content-type-options': 'nosniff',
    ...headers
  })
  res.end(body)
}

/** @param {import('node:http').ServerResponse} res */
function sendHtml (res, status, html, headers = {}) {
  res.writeHead(status, {
    'content-type': 'text/html; charset=utf-8',
    'cache-control': 'no-store',
    'x-content-type-options': 'nosniff',
    'content-security-policy': "default-src 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline'",
    'referrer-policy': 'no-referrer',
    ...headers
  })
  res.end(html)
}

/** @param {unknown} value */
function escapeHtml (value) {
  return String(value).replace(/[&<>"']/g, (ch) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[ch]))
}

/**
 * @param {import('node:http').IncomingMessage} req
 * @returns {Promise<Record<string, unknown>>}
 */
async function readJsonBody (req) {
  const chunks = []
  let size = 0
  for await (const chunk of req) {
    size += chunk.length
    if (size > MAX_BODY_BYTES) throw new HttpError(413, 'request body is too large')
    chunks.push(chunk)
  }
  if (size === 0) return {}
  // A cross-origin form or `fetch(..., {mode:'no-cors'})` can only send text/plain,
  // form-encoded or multipart bodies without a preflight. Demanding JSON therefore turns
  // every "simple request" write into a rejected request, which is most of our CSRF defence.
  const contentType = firstHeader(req.headers['content-type']).toLowerCase()
  if (!contentType.startsWith('application/json')) {
    throw new HttpError(415, '请求体必须是 application/json', 'E_CONTENT_TYPE')
  }
  const text = Buffer.concat(chunks).toString('utf8')
  let payload
  try {
    payload = JSON.parse(text)
  } catch {
    throw new HttpError(400, 'request body is not valid JSON')
  }
  if (payload === null || typeof payload !== 'object' || Array.isArray(payload)) {
    throw new HttpError(400, 'request body must be a JSON object')
  }
  return payload
}

/** @param {string|string[]|undefined} value */
function firstHeader (value) {
  if (Array.isArray(value)) return value[0] ? value[0].split(',')[0].trim() : ''
  return typeof value === 'string' ? value.split(',')[0].trim() : ''
}

/**
 * @param {import('node:http').IncomingMessage} req
 * @param {number} port
 */
function requestOrigin (req, port) {
  const forwardedProto = firstHeader(req.headers['x-forwarded-proto'])
  const forwardedHost = firstHeader(req.headers['x-forwarded-host'])
  const protocol = forwardedProto === 'https' ? 'https' : 'http'
  const host = forwardedHost || req.headers.host || `127.0.0.1:${port}`
  return `${protocol}://${host}`
}

/** @param {import('node:http').IncomingMessage} req @returns {Record<string, string>} */
function parseCookies (req) {
  const header = firstHeader(req.headers.cookie)
  /** @type {Record<string, string>} */
  const out = {}
  if (header === '') return out
  for (const part of header.split(';')) {
    const index = part.indexOf('=')
    if (index <= 0) continue
    const name = part.slice(0, index).trim()
    const value = part.slice(index + 1).trim()
    if (name === '') continue
    try {
      out[name] = decodeURIComponent(value)
    } catch {
      // A malformed escape in a cookie is the client's problem, not a server error.
      out[name] = value
    }
  }
  return out
}

/**
 * A DNS-rebinding page resolves its own domain to 127.0.0.1 and then talks to us with
 * `Host: evil.example`, so the Host header — not the peer address — is what tells the two
 * apart. Literal IPs (loopback or LAN) and explicitly allowed hosts pass; other domain
 * names do not.
 * @param {string} hostHeader
 * @param {Set<string>} allowedHosts
 */
function isAcceptableHost (hostHeader, allowedHosts) {
  const name = hostHeader.replace(/:\d+$/, '').replace(/^\[|\]$/g, '').toLowerCase()
  if (name === '') return false
  if (name === 'localhost' || name.endsWith('.localhost')) return true
  if (allowedHosts.has(name)) return true
  return IP_LITERAL.test(name)
}

/** @param {string} state @param {number} maxAgeSeconds */
function stateCookie (state, maxAgeSeconds) {
  return `${STATE_COOKIE}=${encodeURIComponent(state)}; Path=${BASE}; HttpOnly; SameSite=Lax; Max-Age=${Math.max(0, Math.floor(maxAgeSeconds))}`
}

function clearedStateCookie () {
  return `${STATE_COOKIE}=; Path=${BASE}; HttpOnly; SameSite=Lax; Max-Age=0`
}

/**
 * @param {{store: import('./vault').VaultStore, states: import('./state').PendingStates, cache: Map<string, unknown>, port: () => number, api?: CloudflareApi, publicUrl?: string, allowedHosts?: string[]}} deps
 */
function createRoutes ({ store, states, cache, port, api, fetchImpl, publicUrl = '', allowedHosts = [] }) {
  const client = api || new CloudflareApi({ store, cache, fetchImpl })
  const deps = { store, states, cache, port, fetchImpl }

  /** Hosts the browser may legitimately reach DSH on, beyond literal IPs. */
  const permittedHosts = new Set()
  if (typeof publicUrl === 'string' && publicUrl !== '') {
    try {
      permittedHosts.add(new URL(publicUrl).hostname.replace(/^\[|\]$/g, '').toLowerCase())
    } catch {}
  }
  for (const entry of allowedHosts) {
    if (typeof entry === 'string' && entry.trim() !== '') permittedHosts.add(entry.trim().toLowerCase())
  }
  for (const entry of String(process.env.CLOUDFLARE_PLUGIN_ALLOWED_HOSTS || '').split(',')) {
    if (entry.trim() !== '') permittedHosts.add(entry.trim().toLowerCase())
  }

  /** @param {import('node:http').IncomingMessage} req */
  function assertHost (req) {
    const host = firstHeader(req.headers.host)
    if (host === '') {
      // HTTP/1.0 clients without Host: fall back to the configured port, nothing to compare.
      return
    }
    if (!isAcceptableHost(host, permittedHosts)) {
      throw new HttpError(421, `不接受 Host: ${host}（可能是 DNS rebinding）`, 'E_HOST')
    }
  }

  /**
   * Same-origin guard for writes. `Origin` is sent by browsers on every cross-origin request
   * and on same-origin non-GET fetches; `Sec-Fetch-Site` is the modern equivalent from a
   * browser that already decided the request's provenance.
   * @param {import('node:http').IncomingMessage} req
   */
  function assertSameOrigin (req) {
    const origin = firstHeader(req.headers.origin)
    if (origin !== '') {
      const expected = requestOrigin(req, port())
      if (origin !== expected && !permittedOrigins().has(origin)) {
        throw new HttpError(403, `跨站请求被拒绝（Origin ${origin}）`, 'E_ORIGIN')
      }
    }
    const site = firstHeader(req.headers['sec-fetch-site']).toLowerCase()
    if (site !== '' && site !== 'same-origin' && site !== 'none') {
      throw new HttpError(403, `跨站请求被拒绝（Sec-Fetch-Site: ${site}）`, 'E_ORIGIN')
    }
  }

  /** @returns {Set<string>} */
  function permittedOrigins () {
    const out = new Set()
    if (typeof publicUrl === 'string' && publicUrl !== '') {
      try {
        out.add(new URL(publicUrl).origin)
      } catch {}
    }
    return out
  }

  /** @param {import('node:http').IncomingMessage} req */
  function callbackUrlFor (req) {
    const configured = store.client().redirectUri
    if (configured !== '') return configured
    const derived = `${requestOrigin(req, port())}${CALLBACK_PATH}`
    // The one place we accept cloudflared/curl convenience: when the request is
    // plainly not a browser request we still hand back the loopback callback.
    return derived
  }

  async function statusPayload () {
    const status = store.status()
    const capabilities = summarize(status.grantedScopes)
    return { ...status, capabilities }
  }

  /** GET /status */
  async function handleStatus (req, res) {
    sendJson(res, 200, { ok: true, status: await statusPayload() })
  }

  /** GET /bootstrap */
  async function handleBootstrap (req, res) {
    sendJson(res, 200, {
      ok: true,
      status: await statusPayload(),
      callbackUrl: callbackUrlFor(req)
    })
  }

  /** POST /config */
  async function handleConfig (req, res) {
    const body = await readJsonBody(req)
    const current = store.client()
    let clientId = typeof body.clientId === 'string' ? body.clientId.trim() : ''
    /** @type {'default'|'user'} */
    let source
    if (body.useDefaultClient === true) {
      clientId = DEFAULT_CLIENT_ID
      source = 'default'
    } else if (clientId !== '') {
      source = 'user'
    } else if (current.clientId !== '') {
      // A blank field means "keep what is there" — the form only shows a masked id, so
      // echoing the mask back would silently break the client registration.
      clientId = current.clientId
      source = current.source
    } else {
      // Nothing stored yet: fall back to the shipped client instead of refusing to save.
      clientId = DEFAULT_CLIENT_ID
      source = 'default'
    }
    let redirectUri = typeof body.redirectUri === 'string' ? body.redirectUri.trim() : ''
    if (redirectUri === '') redirectUri = callbackUrlFor(req)
    const scope = typeof body.scope === 'string' ? body.scope.trim() : ''
    const clientSecret = typeof body.clientSecret === 'string' ? body.clientSecret : ''
    const method = clientSecret !== '' ? 'secret' : 'pkce'
    store.configureClient({ clientId, clientSecret, redirectUri, scope, method, source })
    sendJson(res, 200, { ok: true, status: await statusPayload(), callbackUrl: redirectUri })
  }

  /**
   * Cloudflare issues a refresh_token only when the authorize request explicitly asks for
   * `offline_access`; enabling the refresh_token grant on the client is necessary but not
   * sufficient. A client without that grant rejects the scope, so `?offline=0` opts out.
   * @param {string} scope
   * @param {boolean} enabled
   * @returns {string}
   */
  function withOfflineAccess (scope, enabled) {
    const parts = String(scope || '').split(/\s+/).filter((part) => part !== '' && part !== OFFLINE_ACCESS)
    if (enabled) parts.push(OFFLINE_ACCESS)
    return parts.join(' ')
  }

  /** @param {import('node:http').IncomingMessage} req */
  function wantsOfflineAccess (req) {
    const value = new URL(req.url || '/', 'http://localhost').searchParams.get('offline')
    return value !== '0' && value !== 'false'
  }

  /**
   * Shared by GET (302) and POST (JSON) /start.
   * @param {import('node:http').IncomingMessage} req
   */
  async function beginAuthorization (req) {
    const config = store.client()
    if (!config.configured) {
      throw new HttpError(409, '还没有配置 OAuth client：请先填写 client_id 与回调地址', 'E_NOT_CONFIGURED')
    }
    if (String(config.scope || '').trim() === '') {
      // Cloudflare's consent screen renders "0 total permissions" and disables Authorize when the
      // authorize request carries no scope, so an empty scope is a dead end rather than a default.
      throw new HttpError(409, 'OAuth 需要至少一个 scope：请在设置页填写 client 上已登记的权限名（空格分隔），否则同意页会显示 0 个权限且无法授权', 'E_SCOPE_REQUIRED')
    }
    const redirectUri = config.redirectUri !== '' ? config.redirectUri : callbackUrlFor(req)
    if (redirectUri !== config.redirectUri && config.redirectUri !== '') {
      throw new HttpError(409, '回调地址与配置不一致', 'E_REDIRECT_URI')
    }
    const scope = withOfflineAccess(config.scope, wantsOfflineAccess(req))
    const endpoints = await discover({ fetchImpl: deps.fetchImpl })
    const pkce = createPkce()
    const pending = states.create({ verifier: pkce.verifier, redirectUri, scope, browserBound: true })
    const url = buildAuthorizeUrl({
      clientId: config.clientId,
      redirectUri,
      state: pending.state,
      scope,
      codeChallenge: config.method === 'secret' ? '' : pkce.challenge,
      endpoint: endpoints.authorize
    })
    return { url, state: pending.state, expiresAt: pending.expiresAt, redirectUri }
  }

  /** GET|POST /start */
  async function handleStart (req, res) {
    const started = await beginAuthorization(req)
    const cookie = { 'set-cookie': stateCookie(started.state, Math.floor((started.expiresAt - Date.now()) / 1000)) }
    if ((req.method || 'GET').toUpperCase() === 'POST') {
      sendJson(res, 200, {
        ok: true,
        url: started.url,
        redirectUri: started.redirectUri,
        expiresAt: started.expiresAt,
        hint: '在浏览器里打开这个地址完成授权；回调会写回本机凭据库'
      }, cookie)
      return
    }
    // A top-level 302 keeps the consent flow one click from the panel.
    sendHtml(res, 302, '', { location: started.url, ...cookie })
  }

  /**
   * Turn the code into a stored identity.
   * @param {{code: string, state: string, cookieState: string, fetchImpl?: typeof fetch}} input
   */
  async function completeAuthorization ({ code, state, cookieState, fetchImpl = fetch }) {
    const pending = states.peek(state)
    if (pending === null) throw new HttpError(400, 'state 无效或已过期：请重新点「连接 Cloudflare」', 'E_STATE')
    if (pending.browserBound && cookieState !== state) {
      throw new HttpError(400, 'state 与浏览器 cookie 不匹配，已拒绝（可能是 CSRF 尝试）', 'E_STATE')
    }
    const consumed = states.take(state)
    if (consumed === null) throw new HttpError(400, 'state 已被使用', 'E_STATE')

    const config = store.client()
    const endpoints = await discover({ fetchImpl })
    let token
    try {
      token = await exchangeCode({
        clientId: config.clientId,
        clientSecret: config.clientSecret,
        code,
        redirectUri: consumed.redirectUri,
        codeVerifier: consumed.verifier,
        endpoint: endpoints.token,
        fetchImpl
      })
    } catch (error) {
      const explained = explainOAuthFailure(error)
      throw new HttpError(400, explained.message, explained.code)
    }

    const userinfo = await fetchUserinfo({ accessToken: token.accessToken, endpoint: endpoints.userinfo, fetchImpl }).catch(() => ({ id: '', email: '', name: '' }))
    const probe = new CloudflareApi({ store, fetchImpl, accessToken: token.accessToken })
    // Listing accounts is what turns "a token" into "an identity we can show", but a token
    // scoped to zones only is perfectly valid: `/accounts` then answers 200 with an empty
    // result, or 403 when the account scope is missing entirely. Either way the code exchange
    // already succeeded, so failing here would throw away a working grant.
    let accounts = []
    try {
      const accountsPage = await probe.paginate('/accounts', { perPage: 50, maxPages: 2 })
      accounts = accountsPage.items
        .filter((item) => item !== null && typeof item === 'object')
        .map((item) => ({ id: typeof item.id === 'string' ? item.id : '', name: typeof item.name === 'string' ? item.name : '' }))
        .filter((item) => item.id !== '')
    } catch {
      accounts = []
    }
    // Never derive an identity key from token bytes: it ends up in status output and tool
    // results, and a partial token is still token material.
    const userKey = userinfo.id !== ''
      ? `u:${userinfo.id}`
      : `t:${crypto.createHash('sha256').update(token.accessToken).digest('hex').slice(0, 16)}`
    store.setIdentity(userKey, {
      accessToken: token.accessToken,
      refreshToken: token.refreshToken,
      expiresAt: token.expiresAt,
      grantedScopes: token.grantedScopes.length > 0 ? token.grantedScopes : parseScopes(config.scope),
      // Cloudflare's /oauth2/userinfo returns only `sub` for a PKCE client, so fall
      // back to the account name it already exposes on the token's own resources.
      user: {
        id: userinfo.id,
        email: userinfo.email,
        name: userinfo.name || (accounts.length > 0 ? accounts[0].name : '')
      },
      accounts
    })
    return { userKey, accounts, grantedScopes: token.grantedScopes, expiresAt: token.expiresAt }
  }

  /** GET /callback */
  async function handleCallback (req, res) {
    const url = new URL(req.url || CALLBACK_PATH, 'http://localhost')
    const clearCookie = { 'set-cookie': clearedStateCookie() }
    logCallback(req, url, store.dataDir)
    const denied = url.searchParams.get('error')
    if (denied !== null) {
      const description = url.searchParams.get('error_description') || denied
      // The one dead end we can explain precisely: we asked for offline_access to get a refresh
      // token, but this client never enabled the refresh_token grant.
      if (denied === 'invalid_scope' && description.toLowerCase().includes(OFFLINE_ACCESS)) {
        sendHtml(res, 400, resultPage({
          title: '这个 client 没有 refresh_token 授权',
          body: '<p>为了长期免授权，插件会在 scope 里加 <code>offline_access</code>；' +
            '你的 OAuth client 只登记了 <code>authorization_code</code>，所以 Cloudflare 拒绝了它。</p>' +
            '<p class="muted">二选一：①到 Manage Account → OAuth clients 给这个 client 加上 ' +
            '<code>refresh_token</code> 授权类型（推荐，之后自动续期）；' +
            '②先不带 offline_access 授权，令牌 1 小时后需要重新授权。</p>',
          tone: 'warn',
          action: { href: `${BASE}/start?offline=0`, label: '先不带 offline_access 授权' },
          autoClose: false
        }), clearCookie)
        return
      }
      sendHtml(res, 400, resultPage({
        title: '授权未完成',
        body: `<p>Cloudflare 返回：<code>${escapeHtml(denied)}</code></p><p class="muted">${escapeHtml(description)}</p>`,
        tone: 'warn'
      }), clearCookie)
      return
    }
    const code = url.searchParams.get('code') || ''
    const state = url.searchParams.get('state') || ''
    if (code === '' || state === '') {
      sendHtml(res, 400, resultPage({
        title: '回调缺少参数',
        body:
          '<p>这个地址只接受 Cloudflare 授权跳转回来的请求，直接打开它不会有任何参数。</p>' +
          '<p class="muted">正确入口是 <code>/plugins/cloudflare/start</code>：它会先种下 state cookie 再跳去同意页。' +
          '如果你刚刚点的是面板上的「连接 Cloudflare」，请把弹窗拦掉的地址栏内容发出来。</p>',
        tone: 'warn',
        action: { href: `${BASE}/start`, label: '重新开始授权' },
        autoClose: false
      }), clearCookie)
      return
    }
    const cookies = parseCookies(req)
    try {
      const result = await completeAuthorization({ code, state, cookieState: cookies[STATE_COOKIE] || '', fetchImpl: deps.fetchImpl })
      sendHtml(res, 200, resultPage({
        title: 'Cloudflare 已连接',
        body:
          `<p>授权成功，凭据已加密写入本机。</p>` +
          `<p class="muted">可见账号：${escapeHtml(result.accounts.map((item) => item.name || item.id).join('、') || '(未列出)')}</p>` +
          `<p class="muted">授权范围：${escapeHtml(result.grantedScopes.join(' ') || '(未报告)')}</p>`,
        tone: 'ok'
      }), clearCookie)
    } catch (error) {
      const message = error && error.message ? error.message : String(error)
      sendHtml(res, error instanceof HttpError ? error.status : 500, resultPage({
        title: '授权失败',
        body: `<p>${escapeHtml(message)}</p>`,
        tone: 'warn'
      }), clearCookie)
    }
  }

  /** GET /done */
  async function handleDone (req, res) {
    sendHtml(res, 200, resultPage({ title: '返回 DSH', body: '<p>可以关闭这个窗口，回到 DSH 面板查看状态。</p>', tone: 'ok' }))
  }

  /** POST /logout */
  async function handleLogout (req, res) {
    const body = await readJsonBody(req).catch(() => ({}))
    const all = body.all === true
    const userKey = typeof body.userKey === 'string' ? body.userKey : ''
    const targets = all ? store.identities().map((item) => item.userKey) : [userKey !== '' ? userKey : store.activeUser()].filter(Boolean)
    const config = store.client()
    const endpoints = await discover({ fetchImpl: deps.fetchImpl }).catch(() => null)
    const revoked = []
    for (const key of targets) {
      const identity = store.identity(key)
      if (identity === null) continue
      for (const token of [identity.accessToken, identity.refreshToken]) {
        if (typeof token !== 'string' || token === '') continue
        try {
          await revoke({ token, clientId: config.clientId, clientSecret: config.clientSecret, endpoint: endpoints ? endpoints.revoke : undefined, fetchImpl: deps.fetchImpl })
        } catch {
          // A failed revoke must not keep a dead token alive locally.
        }
      }
      store.clearIdentity(key)
      revoked.push(key)
    }
    cache.clear()
    sendJson(res, 200, { ok: true, revoked, status: await statusPayload() })
  }

  /** GET /accounts */
  async function handleAccounts (req, res) {
    const page = await client.paginate('/accounts', { perPage: 50, maxPages: 2 })
    sendJson(res, 200, { ok: true, accounts: page.items, truncated: page.truncated })
  }

  /** GET /zones */
  async function handleZones (req, res) {
    const url = new URL(req.url || '/', 'http://localhost')
    const name = url.searchParams.get('name') || ''
    const page = await client.paginate('/zones', { perPage: 50, maxPages: 3, query: name !== '' ? { name } : {} })
    sendJson(res, 200, { ok: true, zones: page.items, truncated: page.truncated })
  }

  /** GET /scopes */
  async function handleScopes (req, res) {
    try {
      const response = await client.get('/oauth/scopes', { useCache: true })
      const list = Array.isArray(response.result) ? response.result : []
      sendJson(res, 200, { ok: true, scopes: list, source: SCOPE_LIST_ENDPOINT })
    } catch (error) {
      sendJson(res, 200, { ok: false, scopes: [], error: error && error.message ? error.message : String(error) })
    }
  }

  /** GET|POST /preferences */
  async function handlePreferences (req, res) {
    if ((req.method || 'GET').toUpperCase() === 'POST') {
      const body = await readJsonBody(req)
      const preferences = store.setPreferences({
        defaultAccountId: typeof body.defaultAccountId === 'string' ? body.defaultAccountId : undefined,
        zoneAllowlist: Array.isArray(body.zoneAllowlist) ? body.zoneAllowlist : undefined,
        readonly: typeof body.readonly === 'boolean' ? body.readonly : undefined
      })
      sendJson(res, 200, { ok: true, preferences })
      return
    }
    sendJson(res, 200, { ok: true, preferences: store.preferences() })
  }

  /**
   * Method allowlist + host/origin guards, then the handler's own error mapping.
   * @param {(req: any, res: any) => Promise<void>} handler
   * @param {{methods?: string[]}} [options]
   */
  function wrap (handler, { methods } = {}) {
    return async (req, res) => {
      try {
        const method = (req.method || 'GET').toUpperCase()
        if (methods !== undefined && !methods.includes(method)) {
          res.writeHead(405, {
            allow: methods.join(', '),
            'content-type': 'application/json; charset=utf-8',
            'cache-control': 'no-store'
          })
          res.end(JSON.stringify({ ok: false, code: 'E_METHOD', error: `只接受 ${methods.join(' / ')}` }))
          return
        }
        assertHost(req)
        if (method !== 'GET' && method !== 'HEAD') assertSameOrigin(req)
        await handler(req, res)
      } catch (error) {
        if (res.headersSent) {
          try { res.end() } catch {}
          return
        }
        const status = error instanceof HttpError
          ? error.status
          : (error instanceof AuthError ? 409 : (error instanceof CloudflareApiError ? (error.status >= 400 ? error.status : 502) : 500))
        const code = error && typeof error.code === 'string' ? error.code : 'E_INTERNAL'
        sendJson(res, status, { ok: false, code, error: error && error.message ? error.message : String(error) })
      }
    }
  }

  return {
    routes: [
      { kind: 'exact', path: `${BASE}/status`, handler: wrap(handleStatus, { methods: ['GET'] }) },
      { kind: 'exact', path: `${BASE}/bootstrap`, handler: wrap(handleBootstrap, { methods: ['GET'] }) },
      { kind: 'exact', path: `${BASE}/config`, handler: wrap(handleConfig, { methods: ['GET', 'POST'] }) },
      { kind: 'exact', path: `${BASE}/start`, handler: wrap(handleStart, { methods: ['GET', 'POST'] }) },
      { kind: 'exact', path: CALLBACK_PATH, handler: wrap(handleCallback, { methods: ['GET'] }) },
      { kind: 'exact', path: `${BASE}/done`, handler: wrap(handleDone, { methods: ['GET'] }) },
      { kind: 'exact', path: `${BASE}/logout`, handler: wrap(handleLogout, { methods: ['POST'] }) },
      { kind: 'exact', path: `${BASE}/accounts`, handler: wrap(handleAccounts, { methods: ['GET'] }) },
      { kind: 'exact', path: `${BASE}/zones`, handler: wrap(handleZones, { methods: ['GET'] }) },
      { kind: 'exact', path: `${BASE}/scopes`, handler: wrap(handleScopes, { methods: ['GET'] }) },
      { kind: 'exact', path: `${BASE}/preferences`, handler: wrap(handlePreferences, { methods: ['GET', 'POST'] }) }
    ],
    BASE,
    CALLBACK_PATH,
    completeAuthorization
  }
}

/**
 * Minimal, self-contained result page: no secrets, no external assets.
 * @param {{title: string, body: string, tone: 'ok'|'warn'}} input
 */
/**
 * Diagnostics: append one sanitised line per callback hit (no code, no token — only which
 * parameters arrived and whether the state cookie was present).
 */
const CALLBACK_LOG_MAX_BYTES = 256 * 1024

/**
 * Diagnostics: append one sanitised line per callback hit (no code, no token — only which
 * parameters arrived and whether the state cookie was present). This file is unbounded input
 * driven (anyone who can reach /callback can hit it), so it refuses to grow past a cap.
 * @param {import('node:http').IncomingMessage} req
 * @param {URL} url
 * @param {string} dataDir
 */
function logCallback (req, url, dataDir) {
  try {
    const target = path.join(dataDir || resolveDataDir(), 'callback.log')
    try {
      if (fs.statSync(target).size > CALLBACK_LOG_MAX_BYTES) return
    } catch {}
    const keys = Array.from(url.searchParams.keys())
    const state = url.searchParams.get('state') || ''
    const hasCookie = (parseCookies(req)[STATE_COOKIE] || '') !== ''
    const line = `${new Date().toISOString()} hit=callback query=[${keys.join(',') || 'none'}] state=${state === '' ? 'none' : state.slice(0, 8)} cookie=${hasCookie ? 'yes' : 'no'} ua=${String(req.headers['user-agent'] || '').slice(0, 60)}\n`
    fs.appendFileSync(target, line, { mode: 0o600 })
  } catch {}
}

function resultPage ({ title, body, tone, action, autoClose = true }) {
  const accent = tone === 'ok' ? '#2da44e' : '#cf222e'
  const button = action
    ? `<p style="margin-top:18px"><a href="${escapeHtml(action.href)}" style="display:inline-block;padding:8px 16px;border-radius:8px;background:${accent};color:#fff;text-decoration:none;font-weight:600">${escapeHtml(action.label)}</a></p>`
    : ''
  const footer = autoClose ? '<p class="muted">可以关闭这个窗口。</p>' : '<p class="muted">这个页面不会自动关闭。</p>'
  const timer = autoClose ? '<script>setTimeout(function(){try{window.close()}catch(e){}},1200)</script>' : ''
  return `<!doctype html><html lang="zh"><head><meta charset="utf-8"><title>${escapeHtml(title)}</title>
<style>
 body{margin:0;min-height:100vh;display:flex;align-items:center;justify-content:center;background:#0d1117;color:#e6edf3;font:14px/1.6 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,"Helvetica Neue",Arial,"PingFang SC","Microsoft YaHei",sans-serif}
 .card{max-width:520px;padding:28px 30px;border:1px solid #30363d;border-radius:14px;background:#161b22}
 h1{margin:0 0 14px;font-size:17px;display:flex;align-items:center;gap:9px}
 .dot{width:9px;height:9px;border-radius:50%;background:${accent}}
 p{margin:8px 0}
 .muted{color:#8b949e;font-size:12.5px}
 code{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:12px;background:#0d1117;padding:1px 5px;border-radius:4px}
 @media (prefers-color-scheme:light){body{background:#fff;color:#1f2328}.card{background:#f6f8fa;border-color:#d0d7de}.muted{color:#57606a}code{background:#fff}}
</style></head><body><div class="card"><h1><span class="dot"></span>${escapeHtml(title)}</h1>${body}
${button}${footer}</div>
${timer}
</body></html>`
}

module.exports = { createRoutes, BASE, CALLBACK_PATH, STATE_COOKIE, MAX_BODY_BYTES, HttpError }
