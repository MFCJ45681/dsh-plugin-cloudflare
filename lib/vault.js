'use strict'

/**
 * Encrypted credential vault for the Cloudflare plugin.
 *
 * One AES-256-GCM envelope holds everything sensitive: the OAuth client id /
 * secret, and per-identity access + refresh tokens. The master key is either
 * CLOUDFLARE_PLUGIN_MASTER_KEY or a separate 0600 file, so a copy of vault.json
 * alone is useless.
 *
 * A wrong key or a corrupted file must never take the plugin down: callers get
 * a VaultError and the HTTP routes stay up so /status can explain the problem.
 */

const crypto = require('node:crypto')
const fs = require('node:fs')
const os = require('node:os')
const path = require('node:path')

const { deriveKey, encryptJson, decryptJson, randomKey } = require('./crypto')

const VAULT_FILE = 'vault.json'
const KEY_FILE = 'master.key'
const KEY_SALT = 'dsh-cloudflare-vault-v1'
const ENV_MASTER_KEY = 'CLOUDFLARE_PLUGIN_MASTER_KEY'
const ENV_DATA_DIR = 'CLOUDFLARE_PLUGIN_DATA_DIR'
const ALGORITHM = 'aes-256-gcm'

class VaultError extends Error {
  /**
   * @param {string} message
   * @param {string} [code]
   */
  constructor (message, code = 'E_VAULT') {
    super(message)
    this.name = 'VaultError'
    this.code = code
  }
}

/** @returns {string} */
function resolveDataDir () {
  const fromEnv = process.env[ENV_DATA_DIR]
  if (typeof fromEnv === 'string' && fromEnv.trim() !== '') return path.resolve(fromEnv.trim())
  return path.join(os.homedir(), '.dsh', 'cloudflare')
}

/** @param {unknown} value @returns {Record<string, unknown>} */
function asObject (value) {
  return value !== null && typeof value === 'object' && !Array.isArray(value) ? value : {}
}

/** @param {unknown} value @returns {string} */
function asString (value) {
  return typeof value === 'string' ? value : ''
}

/** @param {unknown} value @returns {string[]} */
function asStringArray (value) {
  if (!Array.isArray(value)) return []
  return value.filter((item) => typeof item === 'string' && item !== '')
}

/**
 * Show enough of a client id to recognise it and not enough to reuse it.
 * @param {unknown} clientId
 * @returns {string}
 */
function maskClientId (clientId) {
  const value = asString(clientId)
  if (value === '') return ''
  if (value.length <= 8) return `${value.slice(0, 2)}…`
  return `${value.slice(0, 4)}…${value.slice(-4)}`
}

/** @returns {object} */
function emptyDocument () {
  return {
    version: 1,
    client: { clientId: '', clientSecret: '', redirectUri: '', scope: '', method: 'pkce', source: 'none', configuredAt: 0 },
    identities: {},
    activeUser: '',
    preferences: { defaultAccountId: '', zoneAllowlist: [], readonly: false }
  }
}

/**
 * Normalise whatever is on disk into the current shape, ignoring unknown keys.
 * @param {unknown} raw
 */
function normalizeDocument (raw) {
  const doc = emptyDocument()
  const source = asObject(raw)
  const client = asObject(source.client)
  doc.client = {
    clientId: asString(client.clientId),
    clientSecret: asString(client.clientSecret),
    redirectUri: asString(client.redirectUri),
    scope: asString(client.scope),
    method: client.method === 'secret' ? 'secret' : 'pkce',
    // Documents written before the built-in client existed carry no `source`; anything with an
    // id at that point had been typed in by hand, so it is treated as the user's own.
    source: client.source === 'default'
      ? 'default'
      : (client.source === 'user' ? 'user' : (asString(client.clientId) === '' ? 'none' : 'user')),
    configuredAt: Number.isFinite(client.configuredAt) ? client.configuredAt : 0
  }
  const identities = asObject(source.identities)
  for (const [key, value] of Object.entries(identities)) {
    const entry = asObject(value)
    if (asString(entry.accessToken) === '') continue
    doc.identities[key] = {
      userKey: asString(entry.userKey) || key,
      userId: asString(entry.userId),
      email: asString(entry.email),
      name: asString(entry.name),
      accessToken: asString(entry.accessToken),
      refreshToken: asString(entry.refreshToken),
      expiresAt: Number.isFinite(entry.expiresAt) ? entry.expiresAt : 0,
      grantedScopes: asStringArray(entry.grantedScopes),
      accounts: Array.isArray(entry.accounts)
        ? entry.accounts
          .map((item) => asObject(item))
          .filter((item) => asString(item.id) !== '')
          .map((item) => ({ id: asString(item.id), name: asString(item.name) }))
        : [],
      createdAt: Number.isFinite(entry.createdAt) ? entry.createdAt : 0,
      lastVerifiedAt: Number.isFinite(entry.lastVerifiedAt) ? entry.lastVerifiedAt : 0
    }
  }
  doc.activeUser = doc.identities[asString(source.activeUser)] ? asString(source.activeUser) : Object.keys(doc.identities)[0] || ''
  const prefs = asObject(source.preferences)
  doc.preferences = {
    defaultAccountId: asString(prefs.defaultAccountId),
    zoneAllowlist: asStringArray(prefs.zoneAllowlist),
    readonly: prefs.readonly === true
  }
  return doc
}

class VaultStore {
  /**
   * @param {{dataDir?: string}} [options]
   */
  constructor (options = {}) {
    this.dataDir = typeof options.dataDir === 'string' && options.dataDir !== '' ? path.resolve(options.dataDir) : resolveDataDir()
    this.vaultPath = path.join(this.dataDir, VAULT_FILE)
    this.keyPath = path.join(this.dataDir, KEY_FILE)
    /** @type {{mtimeMs: number, size: number, doc: object}|null} */
    this._cache = null
    this._keySource = ''
  }

  /** Create the data directory and a key file when missing. @returns {this} */
  ensure () {
    fs.mkdirSync(this.dataDir, { recursive: true, mode: 0o700 })
    if (this._keySource === 'env') return this
    if (!fs.existsSync(this.keyPath)) {
      try {
        fs.writeFileSync(this.keyPath, randomKey().toString('base64'), { mode: 0o600, flag: 'wx' })
      } catch (error) {
        if (!error || error.code !== 'EEXIST') throw new VaultError(`cannot create master key: ${error.message}`, 'E_VAULT_KEY')
      }
      try { fs.chmodSync(this.keyPath, 0o600) } catch {}
    }
    return this
  }

  /** @returns {string} 'env' | 'file' */
  keySource () {
    const fromEnv = process.env[ENV_MASTER_KEY]
    return typeof fromEnv === 'string' && fromEnv.trim() !== '' ? 'env' : 'file'
  }

  /** @returns {Buffer} */
  key () {
    const fromEnv = process.env[ENV_MASTER_KEY]
    if (typeof fromEnv === 'string' && fromEnv.trim() !== '') {
      this._keySource = 'env'
      return deriveKey(fromEnv, KEY_SALT)
    }
    this._keySource = 'file'
    let raw
    try {
      raw = fs.readFileSync(this.keyPath, 'utf8')
    } catch (error) {
      throw new VaultError(`cannot read master key at ${this.keyPath}: ${error.message}`, 'E_VAULT_KEY')
    }
    const material = raw.trim()
    if (material === '') throw new VaultError(`master key at ${this.keyPath} is empty`, 'E_VAULT_KEY')
    // A 0600 key file holds 32 random bytes (base64); anything else is treated
    // as a passphrase so `echo -n secret > master.key` also works.
    if (/^[A-Za-z0-9+/=]{43,44}$/.test(material)) {
      const key = Buffer.from(material, 'base64')
      if (key.length === 32) return key
    }
    return deriveKey(material, KEY_SALT)
  }

  /** @returns {object} */
  read () {
    let stat
    try {
      stat = fs.statSync(this.vaultPath)
    } catch (error) {
      if (error && error.code === 'ENOENT') {
        this._cache = null
        return emptyDocument()
      }
      throw new VaultError(`cannot stat vault: ${error.message}`)
    }
    if (this._cache !== null && this._cache.mtimeMs === stat.mtimeMs && this._cache.size === stat.size) {
      return this._cache.doc
    }
    const payload = fs.readFileSync(this.vaultPath, 'utf8')
    let parsed
    try {
      parsed = decryptJson(this.key(), payload.trim())
    } catch (error) {
      throw new VaultError(`${error.message} — set ${ENV_MASTER_KEY} or restore ${this.keyPath}`, 'E_VAULT_DECRYPT')
    }
    const doc = normalizeDocument(parsed)
    this._cache = { mtimeMs: stat.mtimeMs, size: stat.size, doc }
    return doc
  }

  /** @param {object} doc */
  write (doc) {
    this.ensure()
    const payload = encryptJson(this.key(), doc)
    const tmp = `${this.vaultPath}.${crypto.randomBytes(6).toString('hex')}.tmp`
    try {
      fs.writeFileSync(tmp, payload, { mode: 0o600 })
      fs.renameSync(tmp, this.vaultPath)
    } catch (error) {
      try { fs.unlinkSync(tmp) } catch {}
      throw new VaultError(`cannot write vault: ${error.message}`)
    } finally {
      try { fs.chmodSync(this.vaultPath, 0o600) } catch {}
    }
    this._cache = null
    return doc
  }

  /**
   * Read-modify-write in one step.
   * @param {(doc: object) => void|object} mutator
   * @returns {object} the persisted document
   */
  update (mutator) {
    const doc = this.read()
    const returned = mutator(doc)
    return this.write(returned === undefined ? doc : normalizeDocument(returned))
  }

  /** @returns {{configured: boolean, clientId: string, clientSecret: string, redirectUri: string, scope: string, method: string, configuredAt: number}} */
  client () {
    const doc = this.read()
    return { configured: doc.client.clientId !== '', ...doc.client }
  }

  /**
   * @param {{clientId: string, clientSecret?: string, redirectUri: string, scope: string, method?: string, source?: 'default'|'user'}} input
   */
  configureClient ({ clientId, clientSecret, redirectUri, scope, method, source }) {
    if (typeof clientId !== 'string' || clientId.trim() === '') throw new VaultError('client id is required', 'E_NOT_CONFIGURED')
    if (typeof redirectUri !== 'string' || redirectUri.trim() === '') throw new VaultError('redirect URI is required', 'E_REDIRECT_URI')
    this.update((doc) => {
      // Re-saving the form without touching the id must not turn the built-in client into a
      // "custom" one — that would relabel a value the user never chose.
      const sameId = clientId.trim() === doc.client.clientId
      const resolvedSource = source === 'default' || source === 'user'
        ? source
        : (sameId && doc.client.source === 'default' ? 'default' : 'user')
      doc.client = {
        clientId: clientId.trim(),
        clientSecret: typeof clientSecret === 'string' ? clientSecret.trim() : doc.client.clientSecret,
        redirectUri: redirectUri.trim(),
        scope: typeof scope === 'string' ? scope.trim() : doc.client.scope,
        method: method === 'secret' ? 'secret' : (doc.client.clientSecret !== '' && method === undefined ? 'secret' : 'pkce'),
        source: resolvedSource,
        configuredAt: Date.now()
      }
    })
    return this.client()
  }

  /**
   * Fill in the shipped defaults so a fresh install can authorize without typing an id.
   * Only empty fields are touched, and nothing is written when there is nothing to fill —
   * a vault that is already configured must not be rewritten on every start.
   * @param {{clientId?: string, scope?: string}} [input]
   */
  seedDefaults ({ clientId, scope } = {}) {
    const doc = this.read()
    let changed = false
    if (doc.client.clientId === '' && typeof clientId === 'string' && clientId.trim() !== '') {
      doc.client.clientId = clientId.trim()
      doc.client.source = 'default'
      changed = true
    }
    if (doc.client.scope === '' && typeof scope === 'string' && scope.trim() !== '') {
      doc.client.scope = scope.trim()
      changed = true
    }
    if (!changed) return this.client()
    if (!Number.isFinite(doc.client.configuredAt) || doc.client.configuredAt === 0) {
      doc.client.configuredAt = Date.now()
    }
    this.write(normalizeDocument(doc))
    return this.client()
  }

  /**
   * @param {string} userKey
   * @param {{accessToken: string, refreshToken?: string, expiresAt?: number, grantedScopes?: string[], user?: {id: string, email: string, name: string}, accounts?: Array<{id: string, name: string}>}} token
   */
  setIdentity (userKey, token) {
    if (typeof userKey !== 'string' || userKey === '') throw new VaultError('user key is required', 'E_IDENTITY')
    if (!token || typeof token.accessToken !== 'string' || token.accessToken === '') {
      throw new VaultError('access token is required', 'E_TOKEN_RESPONSE')
    }
    this.update((doc) => {
      const previous = asObject(doc.identities[userKey])
      const user = asObject(token.user)
      doc.identities[userKey] = {
        userKey,
        userId: asString(user.id) || asString(previous.userId),
        email: asString(user.email) || asString(previous.email),
        name: asString(user.name) || asString(previous.name),
        accessToken: token.accessToken,
        refreshToken: asString(token.refreshToken) || asString(previous.refreshToken),
        expiresAt: Number.isFinite(token.expiresAt) ? token.expiresAt : 0,
        grantedScopes: Array.isArray(token.grantedScopes) ? token.grantedScopes : asStringArray(previous.grantedScopes),
        accounts: Array.isArray(token.accounts) ? token.accounts : (Array.isArray(previous.accounts) ? previous.accounts : []),
        createdAt: Number.isFinite(previous.createdAt) && previous.createdAt > 0 ? previous.createdAt : Date.now(),
        lastVerifiedAt: Date.now()
      }
      doc.activeUser = userKey
    })
    return this.identity(userKey)
  }

  /** @param {string} userKey */
  identity (userKey) {
    const doc = this.read()
    const entry = doc.identities[userKey]
    return entry ? { ...entry } : null
  }

  /** @returns {object|null} */
  activeIdentity () {
    const doc = this.read()
    if (doc.activeUser === '') return null
    const entry = doc.identities[doc.activeUser]
    return entry ? { ...entry } : null
  }

  /** @returns {string} */
  activeUser () {
    return this.read().activeUser
  }

  /** @param {string} userKey */
  activateUser (userKey) {
    if (this.identity(userKey) === null) throw new VaultError(`unknown identity ${userKey}`, 'E_IDENTITY')
    this.update((doc) => { doc.activeUser = userKey })
    return this.identity(userKey)
  }

  /** @returns {Array<{userKey: string, email: string, name: string, active: boolean, expiresAt: number, accounts: Array<{id: string, name: string}>}>} */
  identities () {
    const doc = this.read()
    return Object.values(doc.identities).map((entry) => ({
      userKey: entry.userKey,
      email: entry.email,
      name: entry.name,
      active: doc.activeUser === entry.userKey,
      expiresAt: entry.expiresAt,
      accounts: entry.accounts
    }))
  }

  /** @param {string} userKey */
  clearIdentity (userKey) {
    this.update((doc) => {
      delete doc.identities[userKey]
      if (doc.activeUser === userKey) doc.activeUser = Object.keys(doc.identities)[0] || ''
    })
  }

  clearAll () {
    this.update((doc) => {
      doc.identities = {}
      doc.activeUser = ''
    })
  }

  /** @returns {{defaultAccountId: string, zoneAllowlist: string[], readonly: boolean}} */
  preferences () {
    return this.read().preferences
  }

  /** @param {{defaultAccountId?: string, zoneAllowlist?: string[], readonly?: boolean}} patch */
  setPreferences (patch = {}) {
    this.update((doc) => {
      if (typeof patch.defaultAccountId === 'string') doc.preferences.defaultAccountId = patch.defaultAccountId
      if (Array.isArray(patch.zoneAllowlist)) doc.preferences.zoneAllowlist = asStringArray(patch.zoneAllowlist)
      if (typeof patch.readonly === 'boolean') doc.preferences.readonly = patch.readonly
    })
    return this.preferences()
  }

  /**
   * Secret-free view used by /status, the panel and cloudflare_auth_status.
   */
  status () {
    let doc
    try {
      doc = this.read()
    } catch (error) {
      // A wrong master key, a corrupted envelope or an unreadable file must not
      // take the plugin down: report it in the status so /status and the panel
      // can explain the problem, and let every tool fail with E_VAULT instead.
      return this.degradedStatus(error)
    }
    const active = doc.activeUser !== '' ? doc.identities[doc.activeUser] || null : null
    const connected = active !== null
    const expired = connected && active.expiresAt > 0 && active.expiresAt <= Date.now()
    /**
     * `pending` = client configured but nobody authorized yet; `invalid` is
     * reserved for an identity that exists but can no longer be used.
     * @type {'unconfigured'|'pending'|'connected'|'expired'}
     */
    const state = doc.client.clientId === ''
      ? 'unconfigured'
      : (connected ? (expired ? 'expired' : 'connected') : 'pending')
    return {
      state,
      configured: doc.client.clientId !== '',
      connected,
      clientIdMasked: maskClientId(doc.client.clientId),
      clientIdSource: doc.client.source,
      clientMethod: doc.client.method,
      redirectUri: doc.client.redirectUri,
      scope: doc.client.scope,
      activeUser: doc.activeUser,
      email: active === null ? '' : active.email,
      name: active === null ? '' : active.name,
      expiresAt: active === null ? 0 : active.expiresAt,
      canRefresh: active !== null && active.refreshToken !== '',
      grantedScopes: active === null ? [] : active.grantedScopes,
      accounts: active === null ? [] : active.accounts,
      identities: this.identities(),
      preferences: doc.preferences,
      vault: { path: this.vaultPath, algorithm: ALGORITHM, keySource: this.keySource() }
    }
  }

  /**
   * Status for a vault that cannot be decrypted. Same shape as the healthy one
   * so callers never need a special case.
   * @param {unknown} error
   */
  degradedStatus (error) {
    const message = error && error.message ? error.message : String(error)
    const code = error && typeof error.code === 'string' ? error.code : 'E_VAULT'
    return {
      state: 'error',
      configured: false,
      connected: false,
      clientIdMasked: '',
      clientIdSource: 'none',
      clientMethod: 'pkce',
      redirectUri: '',
      scope: '',
      activeUser: '',
      email: '',
      name: '',
      expiresAt: 0,
      canRefresh: false,
      grantedScopes: [],
      accounts: [],
      identities: [],
      preferences: { defaultAccountId: '', zoneAllowlist: [], readonly: false },
      vault: { path: this.vaultPath, algorithm: ALGORITHM, keySource: this.keySource(), error: message, code }
    }
  }
}

module.exports = {
  VaultStore,
  VaultError,
  resolveDataDir,
  maskClientId,
  normalizeDocument,
  VAULT_FILE,
  KEY_FILE,
  ENV_MASTER_KEY,
  ENV_DATA_DIR
}
