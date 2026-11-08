'use strict'

/**
 * AES-256-GCM envelope for the Cloudflare credential vault.
 *
 * The whole vault is one AEAD message, so the OAuth client secret, the access
 * token and the refresh token share a single ciphertext: no field is readable
 * without the master key, and any modification of the file makes decryption
 * fail loudly instead of yielding partial data.
 *
 * Payload format: ``cfo1.<iv>.<tag>.<ciphertext>`` (every binary part base64).
 * The format prefix travels as AAD, so a payload from another vault or another
 * format version cannot be substituted.
 */

const crypto = require('node:crypto')

const ALGORITHM = 'aes-256-gcm'
const KEY_BYTES = 32
const IV_BYTES = 12
const TAG_BYTES = 16
const FORMAT = 'cfo1'

/** @param {unknown} key */
function assertKey (key) {
  if (!Buffer.isBuffer(key) || key.length !== KEY_BYTES) {
    throw new TypeError(`master key must be a ${KEY_BYTES}-byte Buffer`)
  }
}

/**
 * Derive a stable AES key from a passphrase-shaped environment value.
 * @param {string} material
 * @param {string} salt
 * @returns {Buffer}
 */
function deriveKey (material, salt) {
  if (typeof material !== 'string' || material.trim() === '') {
    throw new TypeError('master key material must be a non-empty string')
  }
  return crypto.scryptSync(material.trim(), Buffer.from(salt, 'utf8'), KEY_BYTES)
}

/** @returns {Buffer} */
function randomKey () {
  return crypto.randomBytes(KEY_BYTES)
}

/**
 * @param {number} [bytes]
 * @returns {string} URL-safe random token
 */
function randomToken (bytes = 32) {
  const size = Number.isInteger(bytes) && bytes > 0 ? bytes : 32
  return crypto.randomBytes(size).toString('base64url')
}

/**
 * @param {Buffer} key
 * @param {unknown} value
 * @param {string} [aad]
 * @returns {string}
 */
function encryptJson (key, value, aad = '') {
  assertKey(key)
  const iv = crypto.randomBytes(IV_BYTES)
  const cipher = crypto.createCipheriv(ALGORITHM, key, iv, { authTagLength: TAG_BYTES })
  if (aad !== '') cipher.setAAD(Buffer.from(aad, 'utf8'))
  const plaintext = Buffer.from(JSON.stringify(value), 'utf8')
  const ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final()])
  return [FORMAT, iv.toString('base64'), cipher.getAuthTag().toString('base64'), ciphertext.toString('base64')].join('.')
}

/**
 * @param {Buffer} key
 * @param {string} payload
 * @param {string} [aad]
 * @returns {unknown}
 */
function decryptJson (key, payload, aad = '') {
  assertKey(key)
  if (typeof payload !== 'string' || payload === '') throw new Error('vault payload is empty')
  const parts = payload.split('.')
  if (parts.length !== 4 || parts[0] !== FORMAT) throw new Error(`vault payload is not a ${FORMAT} envelope`)
  const iv = Buffer.from(parts[1], 'base64')
  const tag = Buffer.from(parts[2], 'base64')
  const ciphertext = Buffer.from(parts[3], 'base64')
  if (iv.length !== IV_BYTES || tag.length !== TAG_BYTES) {
    throw new Error('vault payload has malformed IV or authentication tag')
  }
  try {
    const decipher = crypto.createDecipheriv(ALGORITHM, key, iv, { authTagLength: TAG_BYTES })
    if (aad !== '') decipher.setAAD(Buffer.from(aad, 'utf8'))
    decipher.setAuthTag(tag)
    const plaintext = Buffer.concat([decipher.update(ciphertext), decipher.final()])
    return JSON.parse(plaintext.toString('utf8'))
  } catch (error) {
    throw new Error(`vault decryption failed: ${error.message}`)
  }
}

module.exports = { deriveKey, encryptJson, decryptJson, randomKey, randomToken, KEY_BYTES, FORMAT }
