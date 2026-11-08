'use strict'

/**
 * Cloudflare has no shared OAuth application: every client belongs to one account, and while
 * it stays `private` only members of that account can authorize it. So there is no such thing
 * as a universal built-in client — this is the one the plugin was developed against, and it
 * works only for accounts inside it.
 *
 * It is still the right default: a user who belongs to that account gets a working connection
 * without copying ids around, and everybody else overrides it from the settings page. The
 * value is seeded into the vault on first load, so at rest it lives in the same
 * AES-256-GCM envelope as tokens rather than in a plain config file.
 */
const DEFAULT_CLIENT_ID = '214b93d7d78e9695962dd6c405c0cb06'

/** Scopes the built-in client is registered for; also the smallest useful set. */
const DEFAULT_SCOPE = 'zone.read dns.read'

module.exports = { DEFAULT_CLIENT_ID, DEFAULT_SCOPE }
