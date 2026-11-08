'use strict'

/**
 * Cloudflare OAuth 2.0 authorization-code flow with PKCE (S256).
 *
 * Cloudflare only implements the authorization-code grant, so there is no
 * device code and no client-credentials fallback. Because the plugin runs as a
 * local server with a browser in front of it, the natural configuration is a
 * *private* OAuth client with `token_endpoint_auth_method = none` and PKCE: no
 * client secret is ever stored. A confidential client (client_secret) is still
 * supported for users who prefer it.
 *
 * Endpoints are read from the OIDC discovery document and fall back to the
 * documented constants when discovery is unavailable.
 */

const AUTHORIZE_ENDPOINT = 'https://dash.cloudflare.com/oauth2/auth'
const TOKEN_ENDPOINT = 'https://dash.cloudflare.com/oauth2/token'
const REVOKE_ENDPOINT = 'https://dash.cloudflare.com/oauth2/revoke'
const USERINFO_ENDPOINT = 'https://dash.cloudflare.com/oauth2/userinfo'
const DISCOVERY_URL = 'https://dash.cloudflare.com/.well-known/openid-configuration'
const API_BASE = 'https://api.cloudflare.com/client/v4'
const USER_AGENT = 'dsh-cloudflare/0.1.0'
const SCOPE_LIST_ENDPOINT = 'https://api.cloudflare.com/client/v4/oauth/scopes'
const DEFAULT_SCOPE = ''
const DISCOVERY_TTL_MS = 60 * 60 * 1000

class OAuthError extends Error {
  /**
   * @param {string} message
   * @param {{code?: string, status?: number}} [options]
   */
  constructor (message, options = {}) {
    super(message)
    this.name = 'OAuthError'
    this.code = options.code || 'E_OAUTH'
    this.status = Number.isInteger(options.status) ? options.status : 0
  }
}

/** @type {{at: number, endpoints: {authorize: string, token: string, revoke: string, userinfo: string}}|null} */
let discoveryCache = null

/**
 * The discovery document decides where we send the authorization code and the refresh token,
 * so a tampered document would quietly hand both to whoever wrote it. Only Cloudflare over
 * TLS is acceptable; anything else falls back to the documented constant.
 * @param {unknown} value
 * @param {string} fallback
 * @returns {string}
 */
function trustedEndpoint (value, fallback) {
  if (typeof value !== 'string' || value === '') return fallback
  let parsed
  try {
    parsed = new URL(value)
  } catch {
    return fallback
  }
  if (parsed.protocol !== 'https:') return fallback
  const host = parsed.hostname.toLowerCase()
  if (host !== 'cloudflare.com' && !host.endsWith('.cloudflare.com')) return fallback
  return parsed.href
}

/**
 * @param {{fetchImpl?: typeof fetch, force?: boolean}} [options]
 * @returns {Promise<{authorize: string, token: string, revoke: string, userinfo: string, source: string}>}
 */
async function discover ({ fetchImpl = fetch, force = false } = {}) {
  const fallback = {
    authorize: AUTHORIZE_ENDPOINT,
    token: TOKEN_ENDPOINT,
    revoke: REVOKE_ENDPOINT,
    userinfo: USERINFO_ENDPOINT,
    source: 'constants'
  }
  if (!force && discoveryCache !== null && Date.now() - discoveryCache.at < DISCOVERY_TTL_MS) {
    return { ...discoveryCache.endpoints, source: 'discovery' }
  }
  try {
    const response = await fetchImpl(DISCOVERY_URL, {
      headers: { accept: 'application/json', 'user-agent': USER_AGENT },
      signal: AbortSignal.timeout(10000)
    })
    if (!response.ok) return fallback
    const payload = await response.json()
    const endpoints = {
      authorize: trustedEndpoint(payload.authorization_endpoint, AUTHORIZE_ENDPOINT),
      token: trustedEndpoint(payload.token_endpoint, TOKEN_ENDPOINT),
      revoke: trustedEndpoint(payload.revocation_endpoint, REVOKE_ENDPOINT),
      userinfo: trustedEndpoint(payload.userinfo_endpoint, USERINFO_ENDPOINT)
    }
    discoveryCache = { at: Date.now(), endpoints }
    return { ...endpoints, source: 'discovery' }
  } catch {
    return fallback
  }
}

/**
 * PKCE pair. The verifier stays server-side (in the pending-state store); only
 * its SHA-256 challenge travels to Cloudflare.
 * @param {{randomBytes?: (n: number) => Buffer, createHash?: Function}} [deps]
 * @returns {{verifier: string, challenge: string, method: 'S256'}}
 */
function createPkce (deps = {}) {
  const crypto = require('node:crypto')
  const randomBytes = deps.randomBytes || crypto.randomBytes
  const createHash = deps.createHash || crypto.createHash
  const verifier = randomBytes(48).toString('base64url')
  const challenge = createHash('sha256').update(verifier).digest('base64url')
  return { verifier, challenge, method: 'S256' }
}

/**
 * @param {unknown} value
 * @returns {string[]}
 */
function parseScopes (value) {
  if (typeof value !== 'string' || value.trim() === '') return []
  return value.split(/[\s,]+/).filter(Boolean)
}

/**
 * @param {{clientId: string, redirectUri: string, state: string, scope?: string, codeChallenge?: string, endpoint?: string}} input
 * @returns {string}
 */
function buildAuthorizeUrl ({ clientId, redirectUri, state, scope = DEFAULT_SCOPE, codeChallenge = '', endpoint = AUTHORIZE_ENDPOINT }) {
  if (typeof clientId !== 'string' || clientId === '') throw new OAuthError('client id is required', { code: 'E_NOT_CONFIGURED' })
  if (typeof redirectUri !== 'string' || redirectUri === '') throw new OAuthError('redirect URI is required', { code: 'E_REDIRECT_URI' })
  if (typeof state !== 'string' || state === '') throw new OAuthError('state is required', { code: 'E_STATE' })
  const url = new URL(endpoint)
  url.searchParams.set('client_id', clientId)
  url.searchParams.set('redirect_uri', redirectUri)
  url.searchParams.set('response_type', 'code')
  url.searchParams.set('state', state)
  if (typeof scope === 'string' && scope !== '') url.searchParams.set('scope', scope)
  if (codeChallenge !== '') {
    url.searchParams.set('code_challenge', codeChallenge)
    url.searchParams.set('code_challenge_method', 'S256')
  }
  return url.toString()
}

/**
 * @param {unknown} payload
 * @returns {{accessToken: string, tokenType: string, scope: string, grantedScopes: string[], refreshToken: string, expiresAt: number}}
 */
function normalizeTokenResponse (payload) {
  if (payload === null || typeof payload !== 'object') {
    throw new OAuthError('Cloudflare returned a non-object token response', { code: 'E_TOKEN_RESPONSE' })
  }
  const body = payload
  if (typeof body.error === 'string' && body.error !== '') {
    throw new OAuthError(
      typeof body.error_description === 'string' && body.error_description !== '' ? body.error_description : body.error,
      { code: body.error }
    )
  }
  if (typeof body.access_token !== 'string' || body.access_token === '') {
    throw new OAuthError('Cloudflare token response carries no access_token', { code: 'E_TOKEN_RESPONSE' })
  }
  const expiresIn = Number(body.expires_in)
  const scope = typeof body.scope === 'string' ? body.scope : ''
  return {
    accessToken: body.access_token,
    tokenType: typeof body.token_type === 'string' ? body.token_type : 'bearer',
    scope,
    grantedScopes: parseScopes(scope),
    refreshToken: typeof body.refresh_token === 'string' ? body.refresh_token : '',
    expiresAt: Number.isFinite(expiresIn) && expiresIn > 0 ? Date.now() + expiresIn * 1000 : 0
  }
}

/**
 * @param {URLSearchParams} body
 * @param {{endpoint: string, clientId: string, clientSecret: string, fetchImpl: typeof fetch}} options
 */
async function tokenRequest (body, { endpoint, clientId, clientSecret, fetchImpl }) {
  const headers = {
    accept: 'application/json',
    'content-type': 'application/x-www-form-urlencoded',
    'user-agent': USER_AGENT
  }
  // Public client (PKCE): the id travels in the body, no secret is sent.
  // Confidential client: HTTP Basic, which is the method Cloudflare documents.
  body.set('client_id', clientId)
  if (typeof clientSecret === 'string' && clientSecret !== '') {
    headers.authorization = `Basic ${Buffer.from(`${clientId}:${clientSecret}`).toString('base64')}`
  }
  let response
  try {
    response = await fetchImpl(endpoint, {
      method: 'POST',
      headers,
      body: body.toString(),
      signal: AbortSignal.timeout(20000)
    })
  } catch (error) {
    throw new OAuthError(`cannot reach ${new URL(endpoint).host}: ${error.message}`, { code: 'E_NETWORK' })
  }
  const text = await response.text()
  let payload
  try {
    payload = JSON.parse(text)
  } catch {
    throw new OAuthError(`token endpoint returned non-JSON (HTTP ${response.status})`, { code: 'E_TOKEN_RESPONSE', status: response.status })
  }
  if (!response.ok && !(payload && typeof payload.error === 'string')) {
    throw new OAuthError(`token endpoint failed with HTTP ${response.status}`, { code: 'E_HTTP', status: response.status })
  }
  return normalizeTokenResponse(payload)
}

/**
 * @param {{clientId: string, clientSecret?: string, code: string, redirectUri: string, codeVerifier?: string, endpoint?: string, fetchImpl?: typeof fetch}} input
 */
async function exchangeCode ({ clientId, clientSecret = '', code, redirectUri, codeVerifier = '', endpoint = TOKEN_ENDPOINT, fetchImpl = fetch }) {
  const body = new URLSearchParams({ grant_type: 'authorization_code', code, redirect_uri: redirectUri })
  if (codeVerifier !== '') body.set('code_verifier', codeVerifier)
  return tokenRequest(body, { endpoint, clientId, clientSecret, fetchImpl })
}

/**
 * @param {{clientId: string, clientSecret?: string, refreshToken: string, endpoint?: string, fetchImpl?: typeof fetch}} input
 */
async function refreshAccessToken ({ clientId, clientSecret = '', refreshToken, endpoint = TOKEN_ENDPOINT, fetchImpl = fetch }) {
  const body = new URLSearchParams({ grant_type: 'refresh_token', refresh_token: refreshToken })
  return tokenRequest(body, { endpoint, clientId, clientSecret, fetchImpl })
}

/**
 * OIDC userinfo. Cloudflare returns at least `sub`; email/name are not
 * guaranteed, so the caller falls back to GET /client/v4/user.
 * @param {{accessToken: string, endpoint?: string, fetchImpl?: typeof fetch}} input
 * @returns {Promise<{id: string, email: string, name: string}>}
 */
async function fetchUserinfo ({ accessToken, endpoint = USERINFO_ENDPOINT, fetchImpl = fetch }) {
  let response
  try {
    response = await fetchImpl(endpoint, {
      headers: { accept: 'application/json', authorization: `Bearer ${accessToken}`, 'user-agent': USER_AGENT },
      signal: AbortSignal.timeout(15000)
    })
  } catch (error) {
    throw new OAuthError(`cannot reach ${new URL(endpoint).host}: ${error.message}`, { code: 'E_NETWORK' })
  }
  const text = await response.text()
  let payload
  try {
    payload = JSON.parse(text)
  } catch {
    throw new OAuthError(`userinfo returned non-JSON (HTTP ${response.status})`, { code: 'E_RESPONSE', status: response.status })
  }
  if (!response.ok) {
    throw new OAuthError(
      typeof payload.error_description === 'string' ? payload.error_description : `userinfo failed with HTTP ${response.status}`,
      { code: 'E_HTTP', status: response.status }
    )
  }
  return {
    id: typeof payload.sub === 'string' ? payload.sub : (typeof payload.id === 'string' ? payload.id : ''),
    email: typeof payload.email === 'string' ? payload.email : '',
    name: typeof payload.name === 'string' ? payload.name : (typeof payload.preferred_username === 'string' ? payload.preferred_username : '')
  }
}

/**
 * Revoke an access or refresh token. Best effort: the caller deletes local
 * state regardless, because a failed revoke must not resurrect a token.
 * @param {{token: string, clientId: string, clientSecret?: string, endpoint?: string, fetchImpl?: typeof fetch}} input
 */
async function revoke ({ token, clientId, clientSecret = '', endpoint = REVOKE_ENDPOINT, fetchImpl = fetch }) {
  if (typeof token !== 'string' || token === '') return { ok: true, skipped: true }
  const body = new URLSearchParams({ token })
  const headers = {
    accept: 'application/json',
    'content-type': 'application/x-www-form-urlencoded',
    'user-agent': USER_AGENT
  }
  if (clientSecret !== '') headers.authorization = `Basic ${Buffer.from(`${clientId}:${clientSecret}`).toString('base64')}`
  try {
    const response = await fetchImpl(endpoint, { method: 'POST', headers, body: body.toString(), signal: AbortSignal.timeout(15000) })
    return { ok: response.ok, status: response.status }
  } catch (error) {
    throw new OAuthError(`cannot reach ${new URL(endpoint).host}: ${error.message}`, { code: 'E_NETWORK' })
  }
}

module.exports = {
  AUTHORIZE_ENDPOINT,
  TOKEN_ENDPOINT,
  REVOKE_ENDPOINT,
  USERINFO_ENDPOINT,
  DISCOVERY_URL,
  API_BASE,
  SCOPE_LIST_ENDPOINT,
  DEFAULT_SCOPE,
  USER_AGENT,
  OAuthError,
  discover,
  createPkce,
  parseScopes,
  buildAuthorizeUrl,
  normalizeTokenResponse,
  exchangeCode,
  refreshAccessToken,
  fetchUserinfo,
  revoke
}
