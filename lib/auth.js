'use strict'

/**
 * Credential resolution: turn "the active vault identity" into a usable bearer
 * token, refreshing it when it is close to expiry.
 *
 * Everything that talks to Cloudflare goes through `resolveCredential`, so a 401
 * has exactly one repair path (force a refresh, retry once) and a dead refresh
 * token has exactly one outcome (E_INVALID_TOKEN → the user re-authorizes).
 */

const { refreshAccessToken, OAuthError } = require('./oauth')

const REFRESH_WINDOW_MS = 60 * 1000

class AuthError extends Error {
  /**
   * @param {string} message
   * @param {{code?: string, status?: number}} [options]
   */
  constructor (message, options = {}) {
    super(message)
    this.name = 'AuthError'
    this.code = options.code || 'E_AUTH'
    this.status = Number.isInteger(options.status) ? options.status : 0
  }
}

/**
 * Cloudflare rotates the refresh token on use, so two concurrent refreshes with the same
 * token would race: the first succeeds, the second presents a token that no longer exists and
 * gets `invalid_grant`. Callers that arrive while a refresh is in flight therefore await that
 * same promise instead of starting their own.
 * @type {Map<string, Promise<object>>}
 */
const inFlightRefreshes = new Map()

/**
 * Refresh one identity and persist the result.
 * @param {{store: import('./vault').VaultStore, identity: object, fetchImpl?: typeof fetch, endpoint?: string}} input
 * @returns {Promise<object>} the updated identity
 */
async function refreshIdentity ({ store, identity, fetchImpl = fetch, endpoint }) {
  if (typeof identity.refreshToken !== 'string' || identity.refreshToken === '') {
    throw new AuthError('访问令牌已过期，且没有 refresh token；请重新授权', { code: 'E_INVALID_TOKEN' })
  }
  const key = `${identity.userKey}\u0000${identity.refreshToken}`
  const pending = inFlightRefreshes.get(key)
  if (pending !== undefined) return pending
  const task = runRefresh({ store, identity, fetchImpl, endpoint }).finally(() => {
    inFlightRefreshes.delete(key)
  })
  inFlightRefreshes.set(key, task)
  return task
}

/**
 * @param {{store: import('./vault').VaultStore, identity: object, fetchImpl: typeof fetch, endpoint?: string}} input
 * @returns {Promise<object>}
 */
async function runRefresh ({ store, identity, fetchImpl, endpoint }) {
  const client = store.client()
  let token
  try {
    token = await refreshAccessToken({
      clientId: client.clientId,
      clientSecret: client.clientSecret,
      refreshToken: identity.refreshToken,
      endpoint,
      fetchImpl
    })
  } catch (error) {
    const detail = error && error.message ? error.message : String(error)
    throw new AuthError(`刷新访问令牌失败：${detail}`, { code: 'E_INVALID_TOKEN' })
  }
  return store.setIdentity(identity.userKey, {
    accessToken: token.accessToken,
    refreshToken: token.refreshToken || identity.refreshToken,
    expiresAt: token.expiresAt,
    grantedScopes: token.grantedScopes.length > 0 ? token.grantedScopes : identity.grantedScopes,
    user: { id: identity.userId, email: identity.email, name: identity.name },
    accounts: identity.accounts
  })
}

/**
 * @param {{store: import('./vault').VaultStore, force?: boolean, fetchImpl?: typeof fetch, now?: number}} input
 * @returns {Promise<{accessToken: string, identity: object, refreshed: boolean}>}
 */
async function resolveCredential ({ store, force = false, fetchImpl = fetch, now = Date.now() }) {
  const client = store.client()
  if (!client.configured) {
    throw new AuthError('还没有配置 Cloudflare OAuth client（client_id）', { code: 'E_NOT_CONFIGURED' })
  }
  const identity = store.activeIdentity()
  if (identity === null) {
    throw new AuthError('还没有连接 Cloudflare 账号，请先在面板里授权', { code: 'E_NOT_CONNECTED' })
  }
  const expiring = identity.expiresAt > 0 && identity.expiresAt - now <= REFRESH_WINDOW_MS
  if (!force && !expiring) return { accessToken: identity.accessToken, identity, refreshed: false }
  if (identity.expiresAt === 0 && !force) return { accessToken: identity.accessToken, identity, refreshed: false }
  const next = await refreshIdentity({ store, identity, fetchImpl })
  return { accessToken: next.accessToken, identity: next, refreshed: true }
}

/**
 * Explain an OAuthError from the exchange in terms the user can act on.
 * @param {unknown} error
 * @returns {{code: string, message: string}}
 */
function explainOAuthFailure (error) {
  const code = error && typeof error.code === 'string' ? error.code : 'E_OAUTH'
  const message = error && error.message ? error.message : String(error)
  const hints = {
    invalid_request: 'redirect_uri 与 OAuth client 里登记的不一致：请把面板显示的回调地址逐字符复制过去',
    invalid_grant: '授权码或 PKCE 校验失败：通常是中途重启了 DSH，请重新点「连接」',
    access_denied: '你在 Cloudflare 同意页拒绝了授权',
    unauthorized_client: '该 client 不允许这种授权方式：检查 grant type 是否包含 authorization_code',
    invalid_client: 'client_id / client_secret 不正确',
    invalid_scope: '请求的 scope 不被该 client 允许：检查 client 里配置的权限',
    E_NETWORK: '网络不可达：检查本机是否能访问 dash.cloudflare.com'
  }
  return { code, message: hints[code] ? `${hints[code]}（${message}）` : message }
}

module.exports = { AuthError, REFRESH_WINDOW_MS, resolveCredential, refreshIdentity, explainOAuthFailure, OAuthError }
