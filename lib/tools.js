'use strict'

/**
 * Native DSH tools for Cloudflare (read-only phase).
 *
 * Every tool returns the same envelope so the model can read one shape:
 *   { ok, code, text, data, status, rateLimit }
 * `text` is the human/model-facing summary, `data` the structured payload.
 * Failures are returned (ok:false) rather than thrown, so one rejected call does
 * not abort a multi-turn task.
 *
 * No tool ever accepts an access token, and no tool returns one: the token lives
 * in the encrypted vault and is attached by cf-api.js only.
 */

const { CloudflareApi, CloudflareApiError } = require('./cf-api')
const { AuthError } = require('./auth')
const { VaultError } = require('./vault')
const { buildAuthorizeUrl, createPkce, discover, parseScopes } = require('./oauth')
const { summarize, describe } = require('./scopes')
const { CALLBACK_PATH } = require('./routes')
const { DEFAULT_CLIENT_ID } = require('./defaults')

const DEFAULT_TEXT_CHARS = 20000

const OUTPUT_SCHEMA = {
  type: 'object',
  additionalProperties: false,
  properties: {
    ok: { type: 'boolean', required: true },
    code: { type: 'string', required: true },
    text: { type: 'string', required: true },
    data: { type: 'json' },
    status: { type: 'integer' },
    rateLimit: { type: 'json' }
  }
}

/** @param {unknown} value @param {number} max @returns {string} */
function stringifyBounded (value, max = DEFAULT_TEXT_CHARS) {
  let text
  try {
    text = JSON.stringify(value, null, 2)
  } catch {
    text = String(value)
  }
  if (text === undefined) return ''
  return text.length > max ? `${text.slice(0, max)}\n… (truncated, ${text.length} chars total)` : text
}

/** @param {unknown} error @returns {string} */
function errorCode (error) {
  if (error instanceof AuthError) return error.code
  if (error instanceof CloudflareApiError) return error.code
  if (error instanceof VaultError) return error.code
  if (error && typeof error.code === 'string' && error.code !== '') return error.code
  return 'E_INTERNAL'
}

/**
 * @param {unknown} error
 * @param {object} [data]
 */
function failure (error, data) {
  const code = errorCode(error)
  const message = error && error.message ? error.message : String(error)
  const status = error && Number.isInteger(error.status) ? error.status : 0
  return {
    ok: false,
    code,
    text: `${message}${hintFor(code)}`,
    data: data === undefined ? null : data,
    status,
    rateLimit: null
  }
}

/** @param {string} code @returns {string} */
function hintFor (code) {
  switch (code) {
    case 'E_NOT_CONFIGURED':
      return ' → 先调用 cloudflare_auth_setup 保存 OAuth client_id，或在设置页填写。'
    case 'E_NOT_CONNECTED':
      return ' → 先调用 cloudflare_auth_start 拿授权链接，在浏览器里完成授权。'
    case 'E_INVALID_TOKEN':
      return ' → 授权已失效/被撤销：重新调用 cloudflare_auth_start。'
    case 'E_PERMISSION':
      return ' → 该 token 的权限不足：在 Cloudflare 授权时补上对应 scope，或检查账号是否被限制。'
    case 'E_NOT_FOUND':
      return ' → 资源不存在，或 token 所属账号看不到它。'
    case 'E_RATE_LIMITED':
      return ' → 触发 Cloudflare 限流，稍等一会儿再试。'
    case 'E_STATE':
      return ' → 授权链接过期了，重新调用 cloudflare_auth_start。'
    default:
      return ''
  }
}

/**
 * @param {{ok: true, code?: string, text: string, data?: unknown, status?: number, rateLimit?: unknown}} input
 */
function envelope ({ ok = true, code = 'OK', text, data, status = 0, rateLimit = null }) {
  return { ok, code, text, data: data === undefined ? null : data, status, rateLimit }
}

/**
 * @param {{defineTool: Function, store: import('./vault').VaultStore, states: import('./state').PendingStates, cache: Map<string, unknown>, port: () => number, fetchImpl?: typeof fetch}} deps
 */
function buildTools ({ defineTool, store, states, cache, port, fetchImpl }) {
  const api = new CloudflareApi({ store, cache, fetchImpl })
  const tools = []

  /** @param {string} code @param {unknown} data */
  function precheck (code, data) {
    const status = store.status()
    const capabilities = summarize(status.grantedScopes)
    if (!status.connected) return failure(new AuthError('还没有连接 Cloudflare', { code: 'E_NOT_CONNECTED' }))
    if (capabilities.granted.length > 0 && code !== '' && capabilities.capabilities[code] === false) {
      // Blocked before the call: the granted-scope string set is authoritative for
      // *this* token, and Cloudflare answers 403 (not an empty page) for account
      // scoped reads the token cannot see, so claiming 'still trying' would be a lie.
      return {
        ok: false,
        code: 'E_PERMISSION_HINT',
        text: `已跳过：当前授权范围（${capabilities.granted.join(' ')}）没有「${capabilities.labels[code]}」。` +
          '到 Cloudflare 的 OAuth client 里补上对应 scope，再在设置页重新授权即可。',
        data
      }
    }
    return null
  }

  tools.push(defineTool({
    name: 'cloudflare_auth_status',
    description:
      'Show the Cloudflare connection status: whether an OAuth client id is configured, whether an ' +
      'account is authorized, the account email, the granted scopes with a capability breakdown, ' +
      'token expiry and where the encrypted vault lives. Never returns tokens or the client secret.',
    parameters: {},
    output: { schema: OUTPUT_SCHEMA, render: (args, value) => [{ type: 'text', text: value.text }] },
    async execute () {
      try {
        const status = store.status()
        const capabilities = summarize(status.grantedScopes)
        const lines = [
          `状态：${status.state}`,
          status.configured
            ? `OAuth client：${status.clientIdMasked}` +
              `（${status.clientIdSource === 'default' ? '内置' : '自定义'}，` +
              `${status.clientMethod === 'pkce' ? 'PKCE，无 secret' : 'client_secret'}）`
            : 'OAuth client：未配置（下一步 cloudflare_auth_setup）',
          status.redirectUri !== '' ? `回调地址：${status.redirectUri}` : '',
          status.connected
            ? `账号：${status.email || status.name || status.activeUser}`
            : '账号：未授权（下一步 cloudflare_auth_start）',
          status.connected && status.expiresAt > 0
            ? `令牌过期：${new Date(status.expiresAt).toISOString()}（可刷新：${status.canRefresh ? '是' : '否'}）` +
              (status.canRefresh
                ? ''
                : '\n提示：这次授权没有 refresh_token，到期后需要重新授权。给 OAuth client 加上 refresh_token 授权类型即可自动续期。')
            : '',
          status.connected ? `可见账号数：${status.accounts.length}` : '',
          status.connected ? `授权范围：${status.grantedScopes.join(' ') || '(未报告)'}` : '',
          status.connected ? `能力：\n  ${describe(status.grantedScopes).join('\n  ')}` : '',
          `加密凭据库：${status.vault.path}（${status.vault.algorithm}，密钥来源 ${status.vault.keySource}）`
        ].filter(Boolean)
        return envelope({ text: lines.join('\n'), data: { status, capabilities } })
      } catch (error) {
        return failure(error)
      }
    }
  }))

  tools.push(defineTool({
    name: 'cloudflare_auth_setup',
    description:
      'Save which Cloudflare OAuth client this plugin uses. Only the public client_id, the redirect ' +
      'URI and the requested scope are passed here — never a token or a client secret. Create the ' +
      'client once in the Cloudflare dashboard (Manage Account → OAuth clients) with response type ' +
      '"code", grant "authorization_code", token authentication "none" (PKCE) and the redirect URI ' +
      'printed by cloudflare_auth_start. A confidential client (client_secret) must be saved from the ' +
      'plugin settings page instead, because tool arguments end up in the conversation.',
    parameters: {
      clientId: { type: 'string', description: `OAuth client id; omit to use the built-in client (${DEFAULT_CLIENT_ID})` },
      redirectUri: { type: 'string', description: 'Redirect URI registered on the client, e.g. http://127.0.0.1:3080/plugins/cloudflare/callback' },
      scope: { type: 'string', description: 'Space-separated scopes to request; omit to keep the stored scopes' }
    },
    output: { schema: OUTPUT_SCHEMA, render: (args, value) => [{ type: 'text', text: value.text }] },
    async execute (args) {
      try {
        // No argument is the common case: the built-in client is already in the vault, so
        // this tool only exists to override it when someone runs their own OAuth app.
        const clientId = typeof args.clientId === 'string' && args.clientId.trim() !== ''
          ? args.clientId.trim()
          : DEFAULT_CLIENT_ID
        const redirectUri = typeof args.redirectUri === 'string' && args.redirectUri.trim() !== ''
          ? args.redirectUri.trim()
          : `http://127.0.0.1:${port() || 3080}${CALLBACK_PATH}`
        const scope = typeof args.scope === 'string' ? args.scope.trim() : ''
        const previous = store.client()
        store.configureClient({
          clientId,
          clientSecret: previous.clientSecret,
          redirectUri,
          scope: scope === '' ? previous.scope : scope,
          method: previous.clientSecret !== '' ? 'secret' : 'pkce',
          source: clientId === DEFAULT_CLIENT_ID ? 'default' : 'user'
        })
        const status = store.status()
        return envelope({
          text: [
            `OAuth client 已保存：${status.clientIdMasked}`,
            `回调地址：${status.redirectUri}`,
            '下一步：调用 cloudflare_auth_start 拿授权链接，在浏览器里完成授权。'
          ].join('\n'),
          data: status
        })
      } catch (error) {
        return failure(error)
      }
    }
  }))

  tools.push(defineTool({
    name: 'cloudflare_auth_start',
    description:
      'Create a one-time OAuth state plus a PKCE verifier and return the Cloudflare authorization ' +
      'URL. Open the URL in a browser; Cloudflare redirects back to the plugin callback, which stores ' +
      'the token in the encrypted vault. The state is single use and expires in 10 minutes.',
    parameters: {},
    output: { schema: OUTPUT_SCHEMA, render: (args, value) => [{ type: 'text', text: value.text }] },
    async execute () {
      try {
        const config = store.client()
        if (!config.configured) {
          return failure(new AuthError('还没有配置 OAuth client_id', { code: 'E_NOT_CONFIGURED' }))
        }
        const endpoints = await discover({ fetchImpl })
        const pkce = createPkce()
        const pending = states.create({
          verifier: pkce.verifier,
          redirectUri: config.redirectUri,
          scope: config.scope,
          browserBound: false
        })
        const url = buildAuthorizeUrl({
          clientId: config.clientId,
          redirectUri: config.redirectUri,
          state: pending.state,
          scope: config.scope,
          codeChallenge: config.method === 'secret' ? '' : pkce.challenge,
          endpoint: endpoints.authorize
        })
        return envelope({
          text: [
            '打开下面的地址完成 Cloudflare 授权（10 分钟内有效，只能使用一次）：',
            '',
            url,
            '',
            `回调地址必须是：${config.redirectUri}`,
            '授权完成后回到这里调用 cloudflare_auth_status 确认状态。'
          ].join('\n'),
          data: { url, redirectUri: config.redirectUri, expiresAt: pending.expiresAt, endpointSource: endpoints.source }
        })
      } catch (error) {
        return failure(error)
      }
    }
  }))

  tools.push(defineTool({
    name: 'cloudflare_auth_logout',
    description:
      'Revoke the stored Cloudflare token at Cloudflare and delete it from the encrypted vault. ' +
      'Pass all=true to forget every authorized identity. The OAuth client configuration stays.',
    parameters: {
      all: { type: 'boolean', description: 'Also remove every other stored identity' },
      userKey: { type: 'string', description: 'Specific identity to remove; defaults to the active one' }
    },
    output: { schema: OUTPUT_SCHEMA, render: (args, value) => [{ type: 'text', text: value.text }] },
    async execute (args) {
      try {
        const all = args.all === true
        const wanted = typeof args.userKey === 'string' ? args.userKey : ''
        const targets = all ? store.identities().map((item) => item.userKey) : [wanted !== '' ? wanted : store.activeUser()].filter(Boolean)
        if (targets.length === 0) return envelope({ text: '当前没有已授权账号，无需登出。', data: { removed: [] } })
        const config = store.client()
        const endpoints = await discover({ fetchImpl }).catch(() => null)
        const { revoke } = require('./oauth')
        const removed = []
        for (const key of targets) {
          const identity = store.identity(key)
          if (identity === null) continue
          for (const token of [identity.accessToken, identity.refreshToken]) {
            if (typeof token !== 'string' || token === '') continue
            try {
              await revoke({ token, clientId: config.clientId, clientSecret: config.clientSecret, endpoint: endpoints ? endpoints.revoke : undefined, fetchImpl })
            } catch {
              // Local deletion still proceeds: a dead token must not stay usable.
            }
          }
          store.clearIdentity(key)
          removed.push(key)
        }
        cache.clear()
        return envelope({
          text: `已登出并删除 ${removed.length} 个身份：${removed.join(', ')}。Cloudflare 侧的授权也已尽力撤销。`,
          data: { removed, status: store.status() }
        })
      } catch (error) {
        return failure(error)
      }
    }
  }))

  tools.push(defineTool({
    name: 'cloudflare_accounts',
    description:
      'List the Cloudflare accounts the authorized token can see, with the id needed by every ' +
      'account-scoped call. Read-only.',
    parameters: {},
    output: { schema: OUTPUT_SCHEMA, render: (args, value) => [{ type: 'text', text: value.text }] },
    async execute () {
      try {
        const gate = precheck('accountRead')
        if (gate !== null && gate.ok === false) return gate
        const page = await api.paginate('/accounts', { perPage: 50, maxPages: 2 })
        const accounts = page.items
          .filter((item) => item !== null && typeof item === 'object')
          .map((item) => ({
            id: typeof item.id === 'string' ? item.id : '',
            name: typeof item.name === 'string' ? item.name : '',
            type: typeof item.type === 'string' ? item.type : ''
          }))
          .filter((item) => item.id !== '')
        const lines = accounts.length === 0
          ? '这个 token 看不到任何账号。'
          : accounts.map((item) => `${item.name || '(未命名)'}  ${item.id}${item.type ? `  [${item.type}]` : ''}`).join('\n')
        return envelope({
          text: `账号（${accounts.length}）：\n${lines}${page.truncated ? '\n…(还有更多，已截断)' : ''}`,
          data: { accounts, truncated: page.truncated },
          rateLimit: api.lastRateLimit
        })
      } catch (error) {
        return failure(error)
      }
    }
  }))

  tools.push(defineTool({
    name: 'cloudflare_zones',
    description:
      'List Cloudflare zones (domains) visible to the authorized token, optionally filtered by exact ' +
      'zone name. Returns id, name, status, account and nameservers. Read-only.',
    parameters: {
      name: { type: 'string', description: 'Exact zone name, e.g. example.com' },
      perPage: { type: 'integer', description: 'Page size, default 50, max 100' }
    },
    output: { schema: OUTPUT_SCHEMA, render: (args, value) => [{ type: 'text', text: value.text }] },
    async execute (args) {
      try {
        const gate = precheck('zoneRead')
        if (gate !== null && gate.ok === false) return gate
        const name = typeof args.name === 'string' ? args.name.trim() : ''
        const perPage = Number.isInteger(args.perPage) ? Math.min(100, Math.max(1, args.perPage)) : 50
        const page = await api.paginate('/zones', {
          perPage,
          maxPages: 3,
          query: name !== '' ? { name } : {}
        })
        const zones = page.items
          .filter((item) => item !== null && typeof item === 'object')
          .map((item) => ({
            id: typeof item.id === 'string' ? item.id : '',
            name: typeof item.name === 'string' ? item.name : '',
            status: typeof item.status === 'string' ? item.status : '',
            paused: item.paused === true,
            type: typeof item.type === 'string' ? item.type : '',
            accountId: item.account !== null && typeof item.account === 'object' && typeof item.account.id === 'string' ? item.account.id : '',
            accountName: item.account !== null && typeof item.account === 'object' && typeof item.account.name === 'string' ? item.account.name : '',
            nameservers: Array.isArray(item.name_servers) ? item.name_servers.filter((entry) => typeof entry === 'string') : []
          }))
          .filter((item) => item.id !== '')
        const lines = zones.length === 0
          ? (name === '' ? '没有可见的 zone。' : `没有名为 ${name} 的 zone。`)
          : zones.map((item) => `${item.name}  ${item.status}${item.paused ? ' (paused)' : ''}  ${item.id}`).join('\n')
        return envelope({
          text: `zone（${zones.length}${page.total > zones.length ? ` / 共 ${page.total}` : ''}）：\n${lines}${page.truncated ? '\n…(已截断)' : ''}`,
          data: { zones, total: page.total, truncated: page.truncated },
          rateLimit: api.lastRateLimit
        })
      } catch (error) {
        return failure(error)
      }
    }
  }))

  tools.push(defineTool({
    name: 'cloudflare_zone',
    description: 'Show one zone by id or exact name: status, plan, nameservers, settings-relevant flags. Read-only.',
    parameters: {
      zoneId: { type: 'string', description: 'Zone id (preferred)' },
      name: { type: 'string', description: 'Exact zone name, used when zoneId is absent' }
    },
    output: { schema: OUTPUT_SCHEMA, render: (args, value) => [{ type: 'text', text: value.text }] },
    async execute (args) {
      try {
        const gate = precheck('zoneRead')
        if (gate !== null && gate.ok === false) return gate
        const zoneId = typeof args.zoneId === 'string' ? args.zoneId.trim() : ''
        const name = typeof args.name === 'string' ? args.name.trim() : ''
        let zone = null
        if (zoneId !== '') {
          const response = await api.get(`/zones/${encodeURIComponent(zoneId)}`)
          zone = response.result
        } else if (name !== '') {
          const found = await api.get('/zones', { query: { name } })
          const list = Array.isArray(found.result) ? found.result : []
          zone = list.find((item) => item && item.name === name) || list[0] || null
        } else {
          return failure(new Error('需要 zoneId 或 name'), null)
        }
        if (zone === null || typeof zone !== 'object') return failure(new Error('zone 不存在或看不到'), null)
        const summary = {
          id: zone.id,
          name: zone.name,
          status: zone.status,
          paused: zone.paused === true,
          type: zone.type,
          plan: zone.plan && typeof zone.plan === 'object' ? zone.plan.name : '',
          accountId: zone.account && zone.account.id ? zone.account.id : '',
          accountName: zone.account && zone.account.name ? zone.account.name : '',
          nameservers: Array.isArray(zone.name_servers) ? zone.name_servers : [],
          createdAt: zone.created_on,
          modifiedAt: zone.modified_on
        }
        return envelope({
          text: stringifyBounded(summary),
          data: summary,
          rateLimit: api.lastRateLimit
        })
      } catch (error) {
        return failure(error)
      }
    }
  }))

  tools.push(defineTool({
    name: 'cloudflare_dns_records',
    description:
      'List DNS records of one zone (id or exact name), optionally filtered by type and name. ' +
      'Paginated, read-only. Returns id, type, name, content, ttl, proxied, priority.',
    parameters: {
      zoneId: { type: 'string', description: 'Zone id' },
      zoneName: { type: 'string', description: 'Exact zone name, used when zoneId is absent' },
      type: { type: 'string', description: 'Record type filter, e.g. A, AAAA, CNAME, TXT, MX' },
      name: { type: 'string', description: 'Record name filter (exact match)' },
      perPage: { type: 'integer', description: 'Page size, default 100, max 100' },
      maxPages: { type: 'integer', description: 'How many pages to fetch, default 2, max 5' }
    },
    output: { schema: OUTPUT_SCHEMA, render: (args, value) => [{ type: 'text', text: value.text }] },
    async execute (args) {
      try {
        const gate = precheck('dnsRead')
        if (gate !== null && gate.ok === false) return gate
        const zoneId = typeof args.zoneId === 'string' ? args.zoneId.trim() : ''
        const zoneName = typeof args.zoneName === 'string' ? args.zoneName.trim() : ''
        let id = zoneId
        if (id === '' && zoneName !== '') {
          const found = await api.get('/zones', { query: { name: zoneName } })
          const list = Array.isArray(found.result) ? found.result : []
          const match = list.find((item) => item && item.name === zoneName) || list[0]
          if (!match || typeof match.id !== 'string') return failure(new Error(`找不到 zone ${zoneName}`), null)
          id = match.id
        }
        if (id === '') return failure(new Error('需要 zoneId 或 zoneName'), null)
        /** @type {Record<string, unknown>} */
        const query = {}
        if (typeof args.type === 'string' && args.type.trim() !== '') query.type = args.type.trim().toUpperCase()
        if (typeof args.name === 'string' && args.name.trim() !== '') query.name = args.name.trim()
        const perPage = Number.isInteger(args.perPage) ? Math.min(100, Math.max(1, args.perPage)) : 100
        const maxPages = Number.isInteger(args.maxPages) ? Math.min(5, Math.max(1, args.maxPages)) : 2
        const page = await api.paginate(`/zones/${encodeURIComponent(id)}/dns_records`, { query, perPage, maxPages })
        const records = page.items
          .filter((item) => item !== null && typeof item === 'object')
          .map((item) => ({
            id: item.id,
            type: item.type,
            name: item.name,
            content: item.content,
            ttl: item.ttl,
            proxied: item.proxied === true,
            priority: item.priority,
            comment: typeof item.comment === 'string' ? item.comment : ''
          }))
        const lines = records.length === 0
          ? '没有匹配的 DNS 记录。'
          : records.map((item) => `${item.type.padEnd(6)} ${item.name}  →  ${item.content}  ttl=${item.ttl}${item.proxied ? ' proxied' : ''}`).join('\n')
        return envelope({
          text: `DNS 记录（${records.length}${page.total > records.length ? ` / 共 ${page.total}` : ''}）：\n${lines}${page.truncated ? '\n…(已截断，调大 maxPages 或缩小过滤范围)' : ''}`,
          data: { zoneId: id, records, total: page.total, truncated: page.truncated },
          rateLimit: api.lastRateLimit
        })
      } catch (error) {
        return failure(error)
      }
    }
  }))

  tools.push(defineTool({
    name: 'cloudflare_capabilities',
    description:
      'Explain what the current authorization can and cannot do, derived from the granted scopes, ' +
      'plus any scope strings the plugin does not recognise. Read-only; no API call.',
    parameters: {},
    output: { schema: OUTPUT_SCHEMA, render: (args, value) => [{ type: 'text', text: value.text }] },
    async execute () {
      try {
        const status = store.status()
        const capabilities = summarize(status.grantedScopes)
        const lines = [
          `授权范围：${capabilities.granted.join(' ') || '(未报告)'}`,
          ...describe(status.grantedScopes)
        ]
        return envelope({ text: lines.join('\n'), data: { capabilities, granted: parseScopes(status.grantedScopes.join(' ')) } })
      } catch (error) {
        return failure(error)
      }
    }
  }))

  return tools
}

module.exports = { buildTools, OUTPUT_SCHEMA }
