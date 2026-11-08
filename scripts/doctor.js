#!/usr/bin/env node
'use strict'

/**
 * Local diagnostics for dsh-plugin-cloudflare.
 *
 *   node scripts/doctor.js            # human-readable report
 *   node scripts/doctor.js --json     # machine-readable
 *
 * It never calls Cloudflare and never prints a token: it only inspects the local
 * vault, the resolved defineTool, and whether a usable credential envelope is
 * present. Exit code 0 = healthy enough to load, 1 = needs attention.
 */

const path = require('node:path')

const entry = require(path.join(__dirname, '..', 'lib', 'index.js'))

/** @param {string[]} argv */
function parseArgs (argv) {
  const out = { json: false, dataDir: undefined }
  for (let index = 0; index < argv.length; index += 1) {
    const arg = argv[index]
    if (arg === '--json') out.json = true
    else if (arg === '--data-dir') {
      out.dataDir = argv[index + 1]
      index += 1
    }
  }
  return out
}

function main () {
  const args = parseArgs(process.argv.slice(2))
  let probe
  try {
    probe = entry.probe({ dataDir: args.dataDir })
  } catch (error) {
    const payload = { ok: false, error: error && error.message ? error.message : String(error) }
    if (args.json) process.stdout.write(`${JSON.stringify(payload, null, 2)}\n`)
    else process.stdout.write(`cloudflare doctor: FAILED to probe — ${payload.error}\n`)
    return 1
  }

  const lines = [
    `plugin      ${probe.name}`,
    `defineTool  ${probe.defineTool ? 'resolved' : 'NOT resolvable'}${probe.toolsModuleNote ? ` (${probe.toolsModuleNote})` : ''}`,
    `vault       ${probe.vault && probe.vault.path ? probe.vault.path : '(unavailable)'}`,
    `key source  ${probe.vault && probe.vault.keySource ? probe.vault.keySource : '?'}`,
    `state       ${probe.state || '?'}`,
    `configured  ${probe.configured}`,
    `connected   ${probe.connected}`
  ]

  if (args.json) {
    process.stdout.write(`${JSON.stringify({ ok: true, probe }, null, 2)}\n`)
  } else {
    process.stdout.write(`${lines.join('\n')}\n`)
    if (!probe.configured) {
      process.stdout.write('\nnext: 在设置页填写 OAuth client_id / redirect_uri，或调用 cloudflare_auth_setup\n')
    } else if (!probe.connected) {
      process.stdout.write('\nnext: 调用 cloudflare_auth_start（或面板上的「连接 Cloudflare」）完成授权\n')
    }
    if (!probe.defineTool) {
      process.stdout.write('\nnote: defineTool 未解析 —— 只影响工具注册；在 DSH 宿主内加载时通常可解析。\n')
    }
  }
  return probe.vault && probe.vault.error ? 1 : 0
}

process.exitCode = main()
