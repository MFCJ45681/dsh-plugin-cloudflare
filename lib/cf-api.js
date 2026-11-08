'use strict'

/**
 * The one exit toward api.cloudflare.com.
 *
 * Responsibilities that must not be duplicated elsewhere:
 *   - bearer header assembly and the single 401 repair path (refresh, retry once);
 *   - the Cloudflare envelope: `success` first, HTTP status second;
 *   - throttling (token bucket) and 429 backoff using `retry-after`;
 *   - short GET cache so the panel and tools can read the same zone twice for free;
 *   - mapping upstream errors onto stable plugin codes.
 */

const { API_BASE, USER_AGENT } = require('./oauth')
const { AuthError, resolveCredential } = require('./auth')

const GET_CACHE_TTL_MS = 15000
const DEFAULT_TIMEOUT_MS = 20000
const MAX_PER_SECOND = 4
const BURST = 10
const MAX_RETRY_AFTER_MS = 10000

class CloudflareApiError extends Error {
  /**
   * @param {string} message
   * @param {{code?: string, status?: number, errors?: Array<{code: number, message: string}>}} [options]
   */
  constructor (message, options = {}) {
    super(message)
    this.name = 'CloudflareApiError'
    this.code = options.code || 'E_CLOUDFLARE'
    this.status = Number.isInteger(options.status) ? options.status : 0
    this.errors = Array.isArray(options.errors) ? options.errors : []
  }
}

/**
 * Map a Cloudflare error list onto one plugin code, keeping the upstream text.
 * @param {Array<{code: number, message: string}>} errors
 * @param {number} status
 * @returns {string}
 */
function codeForErrors (errors, status) {
  const first = errors.length > 0 ? errors[0] : null
  const upstream = first && Number.isInteger(first.code) ? first.code : 0
  // 9109 / 10000-ish: "no permission". Kept as a list of known permission codes.
  if (status === 401 || upstream === 10000) return 'E_INVALID_TOKEN'
  if (status === 403 || upstream === 9109 || upstream === 10001) return 'E_PERMISSION'
  if (status === 404 || upstream === 7003 || upstream === 81044) return 'E_NOT_FOUND'
  if (status === 429 || upstream === 971 || upstream === 1015) return 'E_RATE_LIMITED'
  if (status >= 500) return 'E_CLOUDFLARE_UNAVAILABLE'
  return 'E_CLOUDFLARE'
}

class CloudflareApi {
  /**
   * @param {{store: import('./vault').VaultStore, cache?: Map<string, {at: number, value: unknown}>, fetchImpl?: typeof fetch, now?: () => number}} options
   */
  constructor ({ store, cache = new Map(), fetchImpl = fetch, now = Date.now, accessToken = '' }) {
    this.store = store
    this.cache = cache
    this.fetchImpl = fetchImpl
    this.now = now
    this._queue = Promise.resolve()
    this._stamps = []
    /** @param {{force?: boolean}} [options] @returns {Promise<{accessToken: string, identity: object|null}>} */
    this.credential = typeof accessToken === 'string' && accessToken !== ''
      // A one-shot API for the authorization callback: the token is not in the
      // vault yet, so there is nothing to refresh and 401 has no repair path.
      ? async () => ({ accessToken, identity: null })
      : (options = {}) => resolveCredential({ store, force: options.force === true, fetchImpl, now: now() })
    this.lastRateLimit = null
  }

  /**
   * Serialise calls and keep the sustained rate under MAX_PER_SECOND.
   */
  async _throttle () {
    const run = async () => {
      for (;;) {
        const now = this.now()
        this._stamps = this._stamps.filter((at) => now - at < 1000)
        if (this._stamps.length < MAX_PER_SECOND) {
          this._stamps.push(now)
          return
        }
        const waitMs = Math.max(20, 1000 - (now - this._stamps[0]))
        await new Promise((resolve) => setTimeout(resolve, waitMs))
      }
    }
    const next = this._queue.then(run, run)
    this._queue = next.then(() => undefined, () => undefined)
    return next
  }

  /** @param {string} path @param {Record<string, unknown>} [query] */
  _url (path, query) {
    const url = new URL(path.startsWith('http') ? path : `${API_BASE}${path.startsWith('/') ? path : `/${path}`}`)
    if (query !== undefined && query !== null) {
      for (const [key, value] of Object.entries(query)) {
        if (value === undefined || value === null || value === '') continue
        if (Array.isArray(value)) {
          for (const item of value) url.searchParams.append(key, String(item))
          continue
        }
        url.searchParams.set(key, String(value))
      }
    }
    return url
  }

  /**
   * @param {string} method
   * @param {string} path
   * @param {{query?: Record<string, unknown>, body?: unknown, timeoutMs?: number, useCache?: boolean, raw?: boolean}} [options]
   * @returns {Promise<{result: unknown, resultInfo: object, status: number, headers: Headers}>}
   */
  async request (method, path, options = {}) {
    const upper = method.toUpperCase()
    const url = this._url(path, options.query)
    const cacheKey = `${upper} ${url.toString()}`
    const useCache = options.useCache !== false && upper === 'GET'
    if (useCache) {
      const hit = this.cache.get(cacheKey)
      if (hit !== undefined && this.now() - hit.at < GET_CACHE_TTL_MS) {
        return { ...hit.value, cached: true }
      }
    }

    let attempt = 0
    let forceRefresh = false
    for (;;) {
      attempt += 1
      let credential
      try {
        credential = await this.credential({ force: forceRefresh })
      } catch (error) {
        if (error instanceof AuthError) throw error
        throw new AuthError(error && error.message ? error.message : String(error), { code: 'E_INVALID_TOKEN' })
      }

      await this._throttle()
      const headers = {
        accept: 'application/json',
        authorization: `Bearer ${credential.accessToken}`,
        'user-agent': USER_AGENT
      }
      /** @type {RequestInit} */
      const init = { method: upper, headers, signal: AbortSignal.timeout(options.timeoutMs || DEFAULT_TIMEOUT_MS) }
      if (options.body !== undefined) {
        headers['content-type'] = 'application/json'
        init.body = JSON.stringify(options.body)
      }

      let response
      try {
        response = await this.fetchImpl(url.toString(), init)
      } catch (error) {
        throw new CloudflareApiError(`无法连接 api.cloudflare.com：${error.message}`, { code: 'E_NETWORK' })
      }

      const rateLimit = {
        remaining: numberOrNull(response.headers.get('ratelimit-remaining') || parsePolicyRemaining(response.headers.get('ratelimit'))),
        policy: response.headers.get('ratelimit-policy') || response.headers.get('ratelimit') || '',
        retryAfter: response.headers.get('retry-after') || ''
      }
      this.lastRateLimit = rateLimit

      const text = await response.text()
      /** @type {any} */
      let payload = null
      if (text !== '') {
        try {
          payload = JSON.parse(text)
        } catch {
          if (response.ok) {
            return { result: text, resultInfo: {}, status: response.status, headers: response.headers }
          }
          throw new CloudflareApiError(`Cloudflare 返回了非 JSON（HTTP ${response.status}）`, { code: 'E_HTTP', status: response.status })
        }
      }

      const errors = Array.isArray(payload && payload.errors)
        ? payload.errors
          .filter((item) => item !== null && typeof item === 'object')
          .map((item) => ({ code: Number.isFinite(item.code) ? item.code : 0, message: typeof item.message === 'string' ? item.message : '' }))
        : []
      const success = payload !== null && typeof payload === 'object' && payload.success === true

      if (response.ok && (success || payload === null)) {
        const value = {
          result: payload === null ? null : payload.result,
          resultInfo: payload !== null && payload.result_info !== null && typeof payload.result_info === 'object' ? payload.result_info : {},
          status: response.status,
          headers: response.headers
        }
        if (useCache) this.cache.set(cacheKey, { at: this.now(), value })
        else if (upper !== 'GET') this.cache.clear()
        return value
      }

      const status = response.status
      // 401: refresh once, then give up with a code the UI turns into "re-authorize".
      if (status === 401 && attempt === 1 && credential.identity && credential.identity.refreshToken !== '') {
        forceRefresh = true
        continue
      }
      if (status === 429 && attempt <= 2) {
        const waitMs = Math.min(MAX_RETRY_AFTER_MS, (Number(rateLimit.retryAfter) || 1) * 1000)
        await new Promise((resolve) => setTimeout(resolve, waitMs))
        continue
      }

      const code = codeForErrors(errors, status)
      const detail = errors.length > 0
        ? errors.map((item) => `${item.code}: ${item.message}`).join('; ')
        : `HTTP ${status}`
      throw new CloudflareApiError(`Cloudflare 拒绝了请求（${detail}）`, { code, status, errors })
    }
  }

  /** @param {string} path @param {Record<string, unknown>} [options] */
  get (path, options = {}) {
    return this.request('GET', path, options)
  }

  /**
   * Collect every page of a list endpoint, bounded.
   * @param {string} path
   * @param {{query?: Record<string, unknown>, maxPages?: number, perPage?: number}} [options]
   * @returns {Promise<{items: unknown[], pages: number, total: number, truncated: boolean}>}
   */
  async paginate (path, { query = {}, maxPages = 5, perPage = 50 } = {}) {
    const items = []
    let page = 1
    let total = 0
    let truncated = false
    for (; page <= maxPages; page += 1) {
      const response = await this.get(path, { query: { ...query, page, per_page: perPage } })
      const list = Array.isArray(response.result) ? response.result : []
      items.push(...list)
      total = Number.isFinite(response.resultInfo.total_count) ? response.resultInfo.total_count : items.length
      const totalPages = Number.isFinite(response.resultInfo.total_pages) ? response.resultInfo.total_pages : page
      if (list.length === 0 || page >= totalPages) break
    }
    if (page > maxPages) truncated = items.length < total
    return { items, pages: Math.min(page, maxPages), total, truncated }
  }
}

/** @param {string|null} value @returns {number|null} */
function numberOrNull (value) {
  if (typeof value !== 'string' || value === '') return null
  const parsed = Number(value)
  return Number.isFinite(parsed) ? parsed : null
}

/**
 * `Ratelimit: "default";r=50;t=30` → 50
 * @param {string|null} header
 * @returns {string|null}
 */
function parsePolicyRemaining (header) {
  if (typeof header !== 'string') return null
  const match = /;\s*r=(\d+)/.exec(header)
  return match === null ? null : match[1]
}

module.exports = { CloudflareApi, CloudflareApiError, codeForErrors, GET_CACHE_TTL_MS }
