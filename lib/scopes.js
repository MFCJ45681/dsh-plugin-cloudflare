'use strict'

/**
 * Capability derivation from granted OAuth scopes.
 *
 * Cloudflare scope names are the API-token permission names and are not
 * stably documented per product, so this module never hard-codes an exact
 * string. It classifies a scope by its resource word and its action word, and
 * anything it cannot classify lands in the `unknown` bucket where the panel
 * shows it verbatim.
 *
 * Classification is only a hint for the UI and for tool pre-checks: the API's
 * own 403 is the authority, and `cf-api.js` reports it as E_PERMISSION.
 */

const CAPABILITIES = [
  { id: 'zoneRead', label: '读取 zone', resource: /zone|domain/i, action: /read|view|list/i },
  { id: 'zoneWrite', label: '修改 zone 设置', resource: /zone/i, action: /write|edit|update|admin/i },
  { id: 'dnsRead', label: '读取 DNS 记录', resource: /dns/i, action: /read|view|list/i },
  { id: 'dnsWrite', label: '增删改 DNS 记录', resource: /dns/i, action: /write|edit|update|admin/i },
  { id: 'cachePurge', label: '清理缓存', resource: /cache/i, action: /purge|write|edit|admin/i },
  { id: 'workersRead', label: '读取 Workers', resource: /worker|script/i, action: /read|view|list/i },
  { id: 'workersWrite', label: '部署 Workers', resource: /worker|script/i, action: /write|edit|deploy|admin/i },
  { id: 'accountRead', label: '读取账号信息', resource: /account/i, action: /read|view|list/i },
  { id: 'analyticsRead', label: '读取分析数据', resource: /analytics|graphql|log/i, action: /read|view|list/i }
]

/**
 * @param {string} scope
 * @returns {string[]} capability ids matched by this scope
 */
function classify (scope) {
  const value = String(scope)
  const matched = []
  for (const capability of CAPABILITIES) {
    if (capability.resource.test(value) && capability.action.test(value)) matched.push(capability.id)
  }
  return matched
}

/**
 * Turn the granted scope list into a capability map plus an unknown bucket.
 * @param {unknown} grantedScopes
 * @returns {{granted: string[], capabilities: Record<string, boolean>, labels: Record<string, string>, unknown: string[]}}
 */
function summarize (grantedScopes) {
  const granted = Array.isArray(grantedScopes) ? grantedScopes.filter((item) => typeof item === 'string' && item !== '') : []
  /** @type {Record<string, boolean>} */
  const capabilities = {}
  for (const capability of CAPABILITIES) capabilities[capability.id] = false
  const unknown = []
  for (const scope of granted) {
    const matched = classify(scope)
    if (matched.length === 0) unknown.push(scope)
    for (const id of matched) capabilities[id] = true
  }
  /** @type {Record<string, string>} */
  const labels = {}
  for (const capability of CAPABILITIES) labels[capability.id] = capability.label
  return { granted, capabilities, labels, unknown }
}

/**
 * Human-readable "can / cannot" lines for the panel and the status tool.
 * @param {unknown} grantedScopes
 * @returns {string[]}
 */
function describe (grantedScopes) {
  const { capabilities, labels, unknown } = summarize(grantedScopes)
  const lines = []
  for (const [id, allowed] of Object.entries(capabilities)) {
    if (allowed) lines.push(`✓ ${labels[id]}`)
  }
  for (const [id, allowed] of Object.entries(capabilities)) {
    if (!allowed) lines.push(`✗ ${labels[id]}`)
  }
  if (unknown.length > 0) lines.push(`? 未识别的权限串：${unknown.join(', ')}`)
  return lines
}

/** Capability ids that a read-only session needs to be useful at all. */
const READONLY_REQUIRED = ['zoneRead', 'dnsRead']

module.exports = { CAPABILITIES, READONLY_REQUIRED, classify, summarize, describe }
