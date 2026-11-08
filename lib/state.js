'use strict'

/**
 * One-time OAuth `state` values, each carrying its PKCE `code_verifier`.
 *
 * The value is a 256-bit random token, single use and short lived. It lives in
 * memory only: a pending authorization cannot survive a restart, which is
 * exactly what a CSRF nonce should do.
 */

const { randomToken } = require('./crypto')

const DEFAULT_TTL_MS = 10 * 60 * 1000
const DEFAULT_MAX_PENDING = 16

class PendingStates {
  /**
   * @param {{ttlMs?: number, max?: number, now?: () => number}} [options]
   */
  constructor ({ ttlMs = DEFAULT_TTL_MS, max = DEFAULT_MAX_PENDING, now = Date.now } = {}) {
    this.ttlMs = ttlMs
    this.max = max
    this.now = now
    /** @type {Map<string, {verifier: string, redirectUri: string, scope: string, browserBound: boolean, createdAt: number, expiresAt: number}>} */
    this.pending = new Map()
  }

  sweep () {
    const now = this.now()
    for (const [state, entry] of this.pending) {
      if (entry.expiresAt <= now) this.pending.delete(state)
    }
  }

  /**
   * @param {{verifier: string, redirectUri: string, scope: string, browserBound?: boolean}} input
   * @returns {{state: string, expiresAt: number}}
   */
  create ({ verifier, redirectUri, scope, browserBound = true }) {
    this.sweep()
    // Drop tool-created states first: a browser-bound state is pinned to a live
    // cookie, so evicting it would strand the user mid-authorization.
    while (this.pending.size >= this.max) {
      let victim = ''
      for (const [state, entry] of this.pending) {
        if (entry.browserBound !== true) { victim = state; break }
        if (victim === '') victim = state
      }
      if (victim === '') break
      this.pending.delete(victim)
    }
    const state = randomToken(32)
    const createdAt = this.now()
    const expiresAt = createdAt + this.ttlMs
    this.pending.set(state, { verifier, redirectUri, scope, browserBound: browserBound === true, createdAt, expiresAt })
    return { state, expiresAt }
  }

  /**
   * Inspect without consuming; unknown or expired values return null.
   * @param {string} state
   */
  peek (state) {
    this.sweep()
    if (typeof state !== 'string' || state === '') return null
    const entry = this.pending.get(state)
    if (!entry) return null
    return { ...entry }
  }

  /**
   * Consume: a state is valid at most once, no matter how the exchange ends.
   * @param {string} state
   */
  take (state) {
    const entry = this.peek(state)
    if (entry !== null) this.pending.delete(state)
    return entry
  }

  get size () {
    this.sweep()
    return this.pending.size
  }
}

module.exports = { PendingStates, DEFAULT_TTL_MS, DEFAULT_MAX_PENDING }
