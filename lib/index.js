'use strict'

/**
 * Host entry for dsh-plugin-cloudflare.
 *
 * Responsibilities, in order of what the user can observe:
 *   1. HTTP routes under /plugins/cloudflare/* on the existing DSH web server
 *      (status, start, callback, done, logout, accounts, zones, scopes,
 *      preferences, config);
 *   2. native tools cloudflare_* for the agent;
 *   3. the browser bundle in ./client.js, discovered through package.json's
 *      `dsh.client` declaration and served by dsh-client-modules.
 *
 * OAuth secrets (access/refresh token) and the optional client secret live in
 * one AES-256-GCM envelope (lib/vault.js); the master key is either
 * CLOUDFLARE_PLUGIN_MASTER_KEY or a separate 0600 file. A wrong key must never
 * take the plugin down: the routes stay up so /status can explain the problem.
 */

const path = require('node:path')
const { pathToFileURL } = require('node:url')

const { VaultStore, maskClientId } = require('./vault')
const { PendingStates } = require('./state')
const { createRoutes } = require('./routes')
const { buildTools } = require('./tools')
const { DEFAULT_CLIENT_ID, DEFAULT_SCOPE } = require('./defaults')

/** Stable cordis plugin name — must equal the package name. */
exports.name = 'dsh-plugin-cloudflare'

/** The plugin needs the tool registry and the HTTP server. */
exports.inject = ['tools', 'webServer']

const TOOLS_MODULE = '@deepseek-ai/dsh-tools'

/** @param {string} message */
function report (message) {
  try {
    process.stderr.write(`${exports.name}: ${message}\n`)
  } catch {
    // No console available (loaded as a library): registration is still observable.
  }
}

/** Candidate bases for resolving dsh-tools: the plugin tree has no access to it. */
function resolveBases () {
  const bases = new Set([__dirname, process.cwd()])
  if (require.main && require.main.filename) bases.add(path.dirname(require.main.filename))
  if (process.execPath) bases.add(path.dirname(process.execPath))
  if (process.env.DSH_RUNTIME_DIR) bases.add(process.env.DSH_RUNTIME_DIR)
  return [...bases].filter((base) => typeof base === 'string' && base !== '')
}

/**
 * Locate `defineTool` — the plugin and dsh-tools live in two separate trees, so
 * a bare require from here would fail even though the API exists.
 * @returns {{defineTool: Function|null, resolvedPaths: string[], note: string}}
 */
function acquireDefineTool () {
  const resolvedPaths = []
  const notes = []
  for (const base of resolveBases()) {
    let resolved
    try {
      resolved = require.resolve(TOOLS_MODULE, { paths: [base] })
    } catch {
      continue
    }
    resolvedPaths.push(resolved)
    try {
      const loaded = require(resolved)
      if (typeof loaded.defineTool === 'function') return { defineTool: loaded.defineTool, resolvedPaths, note: '' }
      notes.push(`${resolved}: defineTool is not a function`)
    } catch (error) {
      notes.push(`${resolved}: ${(error && error.code) || (error && error.message) || 'require failed'}`)
    }
  }
  return { defineTool: null, resolvedPaths, note: notes.join('; ') }
}

/**
 * ESM-only fallback: dsh-tools is `type: module`, so require(esm) may be
 * unavailable on older runtimes even though a plain `import` works.
 * @param {string[]} resolvedPaths
 */
async function importDefineTool (resolvedPaths) {
  for (const resolved of [...new Set(resolvedPaths)]) {
    try {
      const loaded = await import(pathToFileURL(resolved).href)
      if (typeof loaded.defineTool === 'function') return loaded.defineTool
    } catch {}
  }
  try {
    const loaded = await import(TOOLS_MODULE)
    if (typeof loaded.defineTool === 'function') return loaded.defineTool
  } catch {}
  return null
}

/**
 * Register every tool. Construction happens before registration so a bad
 * definition registers nothing; a registration-time failure names the tools
 * that did land, because the registry has no batch rollback.
 * @param {Function} defineTool
 * @param {import('@deepseek-ai/cordis').Context} ctx
 * @param {object} deps
 */
function registerTools (defineTool, ctx, deps) {
  const tools = buildTools({ defineTool, ...deps })
  const registered = []
  for (const tool of tools) {
    try {
      ctx.effect(() => ctx.tools.register(tool), `cloudflare: tool ${tool.name}`)
    } catch (error) {
      report(
        `PARTIAL_REGISTRATION: registered=[${registered.join(', ')}] failed=${tool.name} ` +
        `(${(error && error.message) || error}) — already-registered tools remain usable`
      )
      return registered
    }
    registered.push(tool.name)
  }
  return registered
}

/**
 * @param {import('@deepseek-ai/cordis').Context} ctx
 * @param {{dataDir?: string, publicUrl?: string, callbackPath?: string, allowedHosts?: string[]}} [config]
 */
exports.apply = function apply (ctx, config = {}) {
  const store = new VaultStore({ dataDir: config.dataDir })

  let state
  try {
    store.ensure()
    // Seeded once, into the encrypted vault: a fresh install can authorize without the user
    // copying a client id, and the value at rest sits in the same envelope as the tokens.
    const seeded = store.seedDefaults({ clientId: DEFAULT_CLIENT_ID, scope: DEFAULT_SCOPE })
    if (seeded.source === 'default') {
      report(`using the built-in OAuth client ${maskClientId(seeded.clientId)} (encrypted in ${store.vaultPath})`)
    }
    state = store.status()
  } catch (error) {
    report(`vault unavailable: ${(error && error.message) || error}`)
    state = null
  }
  if (state !== null && state.configured === false) {
    report(`no OAuth client yet; configure one with cloudflare_auth_setup (vault: ${state.vault.path})`)
  }
  if (state !== null && state.connected === false) {
    report('no Cloudflare account authorized yet; open the panel or call cloudflare_auth_start')
  }

  const states = new PendingStates()
  // Shared by the HTTP routes and the tools: one short-lived GET cache, cleared
  // on every mutation, keeps repeated panel/tool reads from re-hitting Cloudflare.
  const cache = new Map()
  const port = () => (ctx.webServer && typeof ctx.webServer.port === 'number' ? ctx.webServer.port : 0)

  const { routes } = createRoutes({
    store,
    states,
    cache,
    port,
    publicUrl: typeof config.publicUrl === 'string' ? config.publicUrl : '',
    // Reverse proxies and custom domains must be named here (or in
    // CLOUDFLARE_PLUGIN_ALLOWED_HOSTS); unknown domain names are treated as DNS rebinding.
    allowedHosts: Array.isArray(config.allowedHosts) ? config.allowedHosts : []
  })
  for (const route of routes) {
    ctx.effect(() => ctx.webServer.register(route), `cloudflare: route ${route.path}`)
  }

  const deps = { store, states, cache, port }

  if (!ctx.tools || typeof ctx.tools.register !== 'function') {
    report('host did not provide the tools service; Cloudflare tools are not registered')
    return
  }

  const acquired = acquireDefineTool()
  if (acquired.defineTool !== null) {
    const registered = registerTools(acquired.defineTool, ctx, deps)
    report(`registered ${registered.length} tool(s): ${registered.join(', ')}`)
    return
  }
  return importDefineTool(acquired.resolvedPaths).then((defineTool) => {
    if (defineTool === null) {
      report(`cannot load ${TOOLS_MODULE} (${acquired.note || 'not resolvable'}); Cloudflare tools are not registered`)
      return
    }
    const registered = registerTools(defineTool, ctx, deps)
    report(`registered ${registered.length} tool(s): ${registered.join(', ')}`)
  })
}

/**
 * Diagnostics shared with `node scripts/doctor.js` and the panel.
 * @param {{dataDir?: string}} [config]
 */
exports.probe = function probe (config = {}) {
  const store = new VaultStore({ dataDir: config.dataDir })
  const acquired = acquireDefineTool()
  let status = null
  let error = null
  try {
    status = store.status()
  } catch (thrown) {
    error = thrown && thrown.message ? thrown.message : String(thrown)
  }
  return {
    name: exports.name,
    defineTool: acquired.defineTool !== null,
    toolsModuleNote: acquired.note,
    vault: status === null ? { error } : status.vault,
    configured: status === null ? null : status.configured,
    connected: status === null ? null : status.connected,
    state: status === null ? null : status.state
  }
}
