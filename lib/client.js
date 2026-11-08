window.__ModuleLoader__.load({
  id: 'dsh-plugin-cloudflare',
  factory: function (require) {
    'use strict'

    var React = require('react')
    var h = React.createElement

    var BASE = '/plugins/cloudflare'
    var HOME_URL = 'https://github.com/MFCJ45681/dsh-plugin-cloudflare'
    var STYLE_ID = 'dsh-cloudflare-style'
    // One bootstrap request paints the whole section; reopening the settings page within the
    // TTL reuses the last payload instead of waiting on the network again.
    var BOOTSTRAP_TTL_MS = 15000
    var bootstrapCache = null

    var CSS = [
      /* ---- shell -------------------------------------------------------- */
      '.cf-settings{display:flex;flex-direction:column;gap:12px;padding:2px 0 18px;font-size:13px;line-height:1.5;color:var(--dsw-alias-label-primary,#1f2328);max-width:660px}',
      '.cf-card{position:relative;display:flex;flex-direction:column;gap:12px;padding:14px;border-radius:12px;background:var(--dsw-alias-settings-card-fill,var(--dsw-alias-bg-layer-1,rgba(127,127,127,.035)));border:1px solid var(--dsw-alias-settings-card-stroke,var(--dsw-alias-border-l1,rgba(31,35,40,.12)));box-shadow:0 1px 2px rgba(16,24,40,.04);animation:cf-in .34s cubic-bezier(.22,.61,.36,1) backwards}',

      /* ---- status hero -------------------------------------------------- */
      '.cf-hero{overflow:hidden}',
      '.cf-hero::before{content:"";position:absolute;top:0;left:0;right:0;height:2px;background:linear-gradient(90deg,rgba(45,164,78,0),rgba(45,164,78,.85) 22%,rgba(96,205,120,.9) 50%,rgba(45,164,78,0));opacity:0;transition:opacity .3s ease}',
      '.cf-hero.ok::before{opacity:1}',
      '.cf-hero.warn::before{background:linear-gradient(90deg,rgba(191,135,0,0),rgba(191,135,0,.8) 30%,rgba(191,135,0,0));opacity:1}',
      '.cf-hero.bad::before{background:linear-gradient(90deg,rgba(207,34,46,0),rgba(207,34,46,.8) 30%,rgba(207,34,46,0));opacity:1}',
      '.cf-spread{display:flex;gap:10px;align-items:center;justify-content:space-between;flex-wrap:wrap}',
      '.cf-row{display:flex;gap:8px;align-items:center;flex-wrap:wrap}',
      '.cf-state{display:inline-flex;align-items:center;gap:8px;font-size:13.5px;font-weight:600;letter-spacing:.005em}',
      '.cf-dot{position:relative;flex:none;width:7px;height:7px;border-radius:50%;background:var(--dsw-alias-label-tertiary,#9aa0a6)}',
      '.cf-dot.on{background:var(--dsw-alias-state-success-primary,#2da44e);box-shadow:0 0 0 3px rgba(45,164,78,.13)}',
      '.cf-dot.warn{background:var(--dsw-alias-state-warn-primary,#bf8700);box-shadow:0 0 0 3px rgba(191,135,0,.13)}',
      '.cf-dot.off{background:var(--dsw-alias-state-error-primary,#cf222e);box-shadow:0 0 0 3px rgba(207,34,46,.13)}',
      '.cf-dot.on::after{content:"";position:absolute;inset:-4px;border-radius:50%;border:1px solid rgba(45,164,78,.55);animation:cf-ping 2.6s cubic-bezier(.22,.61,.36,1) infinite}',
      '.cf-badge{display:inline-flex;align-items:center;gap:4px;padding:1px 7px;border-radius:999px;font-size:10.5px;font-weight:600;letter-spacing:.02em;color:var(--dsw-alias-state-success-primary,#2da44e);background:rgba(45,164,78,.11)}',
      '.cf-badge.warn{color:var(--dsw-alias-state-warn-primary,#bf8700);background:rgba(191,135,0,.13)}',
      '.cf-meta{display:flex;flex-wrap:wrap;gap:6px 14px;font-size:11.5px;color:var(--dsw-alias-label-tertiary,#6e7781)}',
      '.cf-meta-item{display:inline-flex;align-items:center;gap:5px;min-width:0}',
      '.cf-meta-item span{overflow:hidden;text-overflow:ellipsis;white-space:nowrap;max-width:min(340px,100%)}',

      /* ---- buttons ------------------------------------------------------ */
      '.cf-btn{appearance:none;display:inline-flex;align-items:center;justify-content:center;gap:6px;border:1px solid var(--dsw-alias-border-l2,rgba(31,35,40,.16));background:var(--dsw-alias-bg-layer-2,transparent);color:inherit;border-radius:8px;padding:6px 11px;font:inherit;font-size:12.5px;font-weight:500;cursor:pointer;white-space:nowrap;text-decoration:none;box-sizing:border-box;transition:background .16s ease,border-color .16s ease,transform .12s ease,box-shadow .16s ease,filter .16s ease}',
      '.cf-btn:hover:not([disabled]){background:var(--dsw-alias-interactive-bg-hover-solid,rgba(31,35,40,.06));border-color:var(--dsw-alias-border-l3,rgba(31,35,40,.26))}',
      '.cf-btn:active:not([disabled]){transform:scale(.97)}',
      '.cf-btn:focus-visible{outline:none;box-shadow:0 0 0 3px rgba(31,136,61,.22)}',
      '.cf-btn[disabled]{opacity:.45;cursor:not-allowed}',
      '.cf-btn.primary{background:var(--dsw-alias-button-primary-fill,#1f883d);border-color:transparent;color:#fff;box-shadow:inset 0 1px 0 rgba(255,255,255,.14),0 1px 2px rgba(16,24,40,.14)}',
      '.cf-btn.primary:hover:not([disabled]){background:var(--dsw-alias-button-primary-fill,#1f883d);filter:brightness(1.07)}',
      '.cf-btn.ghost{border-color:transparent;background:transparent;color:var(--dsw-alias-label-secondary,#57606a)}',
      '.cf-btn.ghost:hover:not([disabled]){color:var(--dsw-alias-label-primary,#1f2328);background:var(--dsw-alias-interactive-bg-hover,rgba(31,35,40,.05))}',
      '.cf-btn.mini{padding:5px 9px;font-size:11.5px;border-radius:7px;gap:4px}',
      '.cf-btn svg{flex:none}',

      /* ---- section headings --------------------------------------------- */
      '.cf-sec{display:flex;align-items:center;gap:8px}',
      '.cf-sec-title{display:inline-flex;align-items:center;gap:6px;font-size:11.5px;font-weight:700;letter-spacing:.04em;color:var(--dsw-alias-label-tertiary,#6e7781)}',
      '.cf-sec-line{flex:1;height:1px;background:var(--dsw-alias-border-l1,rgba(31,35,40,.1))}',

      /* ---- fields ------------------------------------------------------- */
      '.cf-fields{display:flex;flex-direction:column;gap:11px}',
      '.cf-field{display:flex;flex-direction:column;gap:5px}',
      '.cf-label{display:inline-flex;align-items:center;gap:5px;font-size:11.5px;font-weight:600;color:var(--dsw-alias-label-secondary,#57606a)}',
      '.cf-input{width:100%;box-sizing:border-box;border:1px solid var(--dsw-alias-border-l2,rgba(31,35,40,.16));background:var(--dsw-alias-bg-layer-2,transparent);color:inherit;border-radius:8px;padding:8px 10px;font:inherit;font-size:12.5px;transition:border-color .16s ease,box-shadow .16s ease,background .16s ease}',
      '.cf-input::placeholder{color:var(--dsw-alias-label-tertiary,#8c959f)}',
      '.cf-input:hover{border-color:var(--dsw-alias-border-l3,rgba(31,35,40,.26))}',
      '.cf-input:focus{outline:none;border-color:var(--dsw-alias-button-primary-fill,#1f883d);box-shadow:0 0 0 3px rgba(31,136,61,.16)}',
      '.cf-hint{font-size:11.5px;color:var(--dsw-alias-label-tertiary,#6e7781);line-height:1.6}',
      '.cf-actions{margin-top:2px}',

      /* ---- scope chips --------------------------------------------------- */
      '.cf-chips{display:flex;flex-wrap:wrap;gap:5px;margin-top:1px}',
      '.cf-chip{display:inline-flex;align-items:center;gap:4px;padding:1.5px 8px;border-radius:999px;font-size:10.5px;font-family:ui-monospace,SFMono-Regular,Menlo,monospace;color:var(--dsw-alias-label-secondary,#57606a);background:var(--dsw-alias-bg-layer-3,rgba(127,127,127,.1));border:1px solid transparent;transition:background .16s ease,color .16s ease}',
      '.cf-chip.auto{color:var(--dsw-alias-state-success-primary,#2da44e);background:rgba(45,164,78,.1);border-color:rgba(45,164,78,.18)}',

      /* ---- read-only value row ------------------------------------------ */
      '.cf-value{display:flex;align-items:center;gap:8px;min-width:0}',
      '.cf-mono{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:12.5px;color:var(--dsw-alias-label-primary,#1f2328);overflow:hidden;text-overflow:ellipsis;white-space:nowrap}',
      '.cf-tag{padding:1px 7px;border-radius:999px;font-size:10.5px;line-height:1.6;font-weight:500;flex:0 0 auto;color:var(--dsw-alias-label-secondary,#57606a);background:var(--dsw-alias-bg-layer-3,rgba(127,127,127,.1));border:1px solid transparent}',
      '.cf-tag.auto{color:var(--dsw-alias-state-success-primary,#2da44e);background:rgba(45,164,78,.1);border-color:rgba(45,164,78,.18)}',

      /* ---- advanced list ------------------------------------------------ */
      '.cf-sub{display:flex;flex-direction:column;gap:2px}',
      '.cf-subitem{display:flex;align-items:center;justify-content:space-between;gap:10px 14px;flex-wrap:wrap;padding:9px 10px;border-radius:9px;border-left:2px solid transparent;animation:cf-rise .3s cubic-bezier(.22,.61,.36,1) backwards;transition:background .18s ease,border-left-color .18s ease,transform .18s ease}',
      '.cf-subitem:hover{background:var(--dsw-alias-interactive-bg-hover,rgba(31,35,40,.05));border-left-color:var(--dsw-alias-button-primary-fill,#1f883d);transform:translateX(2px)}',
      '.cf-subitem:active{transform:translateX(2px) scale(.995)}',
      '.cf-subitem>div{min-width:0;flex:1 1 180px}',
      '.cf-subitem>.cf-input,.cf-subitem>.cf-code,.cf-subitem>.cf-inline{flex:0 1 auto;min-width:0}',
      '.cf-inline{display:flex;align-items:center;gap:6px;flex-wrap:wrap;justify-content:flex-end}',
      '.cf-sub-label{font-size:12.5px;font-weight:500;color:var(--dsw-alias-label-primary,#1f2328)}',
      '.cf-sub-hint{font-size:11.5px;color:var(--dsw-alias-label-tertiary,#6e7781);line-height:1.55;margin-top:1px}',

      /* ---- switch ------------------------------------------------------- */
      '.cf-switch{appearance:none;border:0;padding:0;margin:0;width:36px;height:20px;border-radius:999px;background:var(--dsw-alias-border-l3,rgba(31,35,40,.22));position:relative;flex:none;cursor:pointer;transition:background .2s ease,box-shadow .2s ease}',
      '.cf-switch::after{content:"";position:absolute;top:2px;left:2px;width:16px;height:16px;border-radius:50%;background:#fff;box-shadow:0 1px 3px rgba(16,24,40,.3);transition:transform .2s cubic-bezier(.22,.61,.36,1)}',
      '.cf-switch:hover{box-shadow:0 0 0 3px rgba(127,127,127,.12)}',
      '.cf-switch.on{background:var(--dsw-alias-button-primary-fill,#1f883d)}',
      '.cf-switch.on:hover{box-shadow:0 0 0 3px rgba(31,136,61,.16)}',
      '.cf-switch.on::after{transform:translateX(16px)}',
      '.cf-switch:focus-visible{outline:none;box-shadow:0 0 0 3px rgba(31,136,61,.24)}',

      /* ---- select / code / messages ------------------------------------- */
      'select.cf-input{appearance:none;-webkit-appearance:none;padding-right:26px;background-repeat:no-repeat;background-position:right 8px center;background-image:url("data:image/svg+xml,%3Csvg xmlns=\'http://www.w3.org/2000/svg\' width=\'12\' height=\'12\' viewBox=\'0 0 24 24\' fill=\'none\' stroke=\'%238c959f\' stroke-width=\'2.5\' stroke-linecap=\'round\' stroke-linejoin=\'round\'%3E%3Cpath d=\'M6 9l6 6 6-6\'/%3E%3C/svg%3E")}',
      '.cf-code{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:11px;line-height:1.5;color:var(--dsw-alias-label-tertiary,#6e7781);word-break:break-all;text-align:right;max-width:min(320px,100%)}',
      '.cf-error{display:flex;gap:8px;align-items:flex-start;border:1px solid rgba(207,34,46,.32);background:rgba(207,34,46,.07);color:var(--dsw-alias-state-error-primary,#cf222e);border-radius:9px;padding:9px 11px;font-size:12px;line-height:1.55;white-space:pre-wrap;animation:cf-in .26s ease backwards}',
      '.cf-error svg{margin-top:1.5px;flex:none}',
      '.cf-ok{display:inline-flex;align-items:center;gap:4px;font-size:12px;color:var(--dsw-alias-state-success-primary,#2da44e);animation:cf-in .24s ease backwards}',

      /* ---- loading skeleton --------------------------------------------- */
      '.cf-skel{height:13px;border-radius:6px;background:linear-gradient(90deg,rgba(127,127,127,.07),rgba(127,127,127,.17),rgba(127,127,127,.07));background-size:220% 100%;animation:cf-shimmer 1.25s linear infinite}',
      '.cf-skel.w60{width:60%}',
      '.cf-skel.w40{width:40%}',

      /* ---- keyframes ---------------------------------------------------- */
      '@keyframes cf-in{from{opacity:0;transform:translateY(4px)}to{opacity:1;transform:translateY(0)}}',
      '@keyframes cf-rise{from{opacity:0;transform:translateY(6px)}to{opacity:1;transform:translateY(0)}}',
      '@keyframes cf-ping{0%{transform:scale(.72);opacity:.75}70%,100%{transform:scale(1.7);opacity:0}}',
      '@keyframes cf-shimmer{from{background-position:220% 0}to{background-position:-220% 0}}',
      '@media (max-width:520px){.cf-subitem{align-items:flex-start}.cf-subitem>.cf-input,.cf-subitem>.cf-code{width:100%!important;max-width:none;text-align:left}.cf-spread{align-items:flex-start}}',
      '.cf-foot{display:flex;align-items:center;justify-content:center;flex-wrap:wrap;gap:5px;padding:2px 2px 10px;font-size:11px;line-height:1.6;color:var(--dsw-alias-label-tertiary,#8b949e)}',
      '.cf-foot>svg{flex:none;opacity:.75}',
      '.cf-foot a{color:inherit;text-decoration:none;border-bottom:1px dotted currentColor;transition:color .18s ease,border-bottom-color .18s ease}',
      '.cf-foot a:hover{color:var(--dsw-alias-label-secondary,#c9d1d9);border-bottom-color:transparent}',
      '.cf-foot .cf-sep{opacity:.45}',
      '@media (prefers-reduced-motion:reduce){.cf-card,.cf-subitem,.cf-error,.cf-ok,.cf-skel{animation:none;transition:none}.cf-dot::after{animation:none;opacity:0}}'
    ].join('\n')

    function ensureStyle () {
      if (typeof document === 'undefined') return
      if (document.getElementById(STYLE_ID) !== null) return
      var node = document.createElement('style')
      node.id = STYLE_ID
      node.textContent = CSS
      document.head.appendChild(node)
    }

    var ICONS = {
      link: ['M10 13a5 5 0 007.5.5l3-3a5 5 0 00-7-7l-1.8 1.8', 'M14 11a5 5 0 00-7.5-.5l-3 3a5 5 0 007 7l1.8-1.8'],
      out: ['M18 13v6a2 2 0 01-2 2H5a2 2 0 01-2-2V8a2 2 0 012-2h6', 'M15 3h6v6', 'M10 14L21 3'],
      check: ['M20 6L9 17l-5-5'],
      logout: ['M9 21H5a2 2 0 01-2-2V5a2 2 0 012-2h4', 'M16 17l5-5-5-5', 'M21 12H9'],
      user: ['M20 21v-2a4 4 0 00-4-4H8a4 4 0 00-4 4v2', 'M12 3a4 4 0 100 8 4 4 0 000-8z'],
      clock: ['M12 3a9 9 0 100 18 9 9 0 000-18z', 'M12 7v5l3 2'],
      key: ['M21 2l-2 2', 'M15.5 7.5l3 3L22 7l-3-3', 'M11.4 11.6a5 5 0 10-7.1 7.1 5 5 0 007.1-7.1zm0 0L15.5 7.5'],
      sliders: ['M4 21v-7', 'M4 10V3', 'M12 21v-9', 'M12 8V3', 'M20 21v-5', 'M20 12V3', 'M1 14h6', 'M9 8h6', 'M17 16h6'],
      alert: ['M12 9v4', 'M12 17h.01', 'M10.3 3.9L1.8 18a2 2 0 001.7 3h17a2 2 0 001.7-3L13.7 3.9a2 2 0 00-3.4 0z'],
      shield: ['M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z']
    }

    /** Tiny inline icon set: no dependency, inherits font color via currentColor. */
    function Icon (props) {
      var paths = ICONS[props.name] || []
      return h('svg', {
        width: props.size || 14,
        height: props.size || 14,
        viewBox: '0 0 24 24',
        fill: 'none',
        stroke: 'currentColor',
        strokeWidth: props.weight || 2,
        strokeLinecap: 'round',
        strokeLinejoin: 'round',
        'aria-hidden': 'true',
        focusable: 'false'
      }, paths.map(function (d) { return h('path', { key: d, d: d }) }))
    }

    function fetchJson (path, options) {
      var opts = options || {}
      return fetch(BASE + path, {
        method: opts.method || 'GET',
        headers: opts.body === undefined ? {} : { 'content-type': 'application/json' },
        body: opts.body === undefined ? undefined : JSON.stringify(opts.body),
        credentials: 'same-origin'
      }).then(function (response) {
        return response.json().catch(function () { return {} }).then(function (payload) {
          if (!response.ok || payload.ok === false) {
            var error = new Error(payload.error || payload.message || ('HTTP ' + response.status))
            error.code = payload.code || 'E_HTTP'
            throw error
          }
          return payload
        })
      })
    }

    function loadBootstrap (force) {
      if (!force && bootstrapCache !== null && Date.now() - bootstrapCache.at < BOOTSTRAP_TTL_MS) {
        return Promise.resolve(bootstrapCache.payload)
      }
      return fetchJson('/bootstrap').then(function (payload) {
        bootstrapCache = { at: Date.now(), payload: payload }
        return payload
      })
    }

    /** Colour class for the status dot, the hero stripe and the hero modifier class. */
    function stateTone (status) {
      if (status.connected) return 'on'
      if (status.state === 'expired' || status.state === 'error') return 'off'
      if (status.state === 'pending') return 'warn'
      return ''
    }

    function heroTone (tone) {
      if (tone === 'on') return ' ok'
      if (tone === 'warn') return ' warn'
      if (tone === 'off') return ' bad'
      return ''
    }

    function stateLabel (status) {
      if (status.state === 'error') return '凭据库异常'
      if (status.connected) return '已连接 Cloudflare'
      if (status.state === 'expired') return '令牌已过期'
      if (status.state === 'pending') return '等待授权'
      return '未连接'
    }

    function formatWhen (ms) {
      if (!ms || ms <= 0) return ''
      try { return new Date(ms).toLocaleString() } catch (error) { return '' }
    }

    /** Split a space separated scope string the same way the host side does. */
    function scopeList (raw) {
      return String(raw || '').split(/\s+/).filter(function (part) { return part !== '' })
    }

    /**
     * Plain anchor, not a fetch + window.open: it is a real user-gesture navigation, so
     * pop-up blockers cannot swallow it and the browser stores the state cookie itself.
     */
    function ConnectButton (props) {
      return h('a', {
        className: 'cf-btn' + (props.primary === true ? ' primary' : ''),
        href: BASE + '/start',
        target: '_blank',
        rel: 'noopener noreferrer',
        title: '在新标签页打开 Cloudflare 授权页'
      },
      h(Icon, { name: 'link', size: 13 }),
      h('span', null, props.label || '授权登录'),
      h(Icon, { name: 'out', size: 11, weight: 2.4 }))
    }

    /**
     * One second-level row. The index only staggers the entrance animation so the list
     * rises in sequence instead of appearing all at once.
     */
    function SubItem (props) {
      return h('div', {
        className: 'cf-subitem',
        style: { animationDelay: (props.index * 45) + 'ms' }
      },
      h('div', null,
        h('div', { className: 'cf-sub-label' }, props.title),
        h('div', { className: 'cf-sub-hint' }, props.hint)),
      props.control)
    }

    function MetaItem (props) {
      return h('span', { className: 'cf-meta-item', title: props.title },
        h(Icon, { name: props.icon, size: 12 }),
        h('span', null, props.text))
    }

    function SettingsSection () {
      var payloadState = React.useState(null)
      var payload = payloadState[0]
      var setPayload = payloadState[1]
      var draft = React.useState({ clientId: '', redirectUri: '', scope: '' })
      var form = draft[0]
      var setForm = draft[1]
      var notice = React.useState('')
      var setNotice = notice[1]
      var errors = React.useState('')
      var setError = errors[1]
      var busy = React.useState(false)
      var setBusy = busy[1]

      function load (force) {
        return loadBootstrap(force === true).then(function (next) {
          setPayload(next)
          var status = next.status || {}
          setForm({
            clientId: '',
            redirectUri: status.redirectUri || next.callbackUrl || '',
            scope: status.scope || ''
          })
        }).catch(function (error) {
          setError(error.message || String(error))
        })
      }

      React.useEffect(function () { load(false) }, [])

      // Coming back from the consent tab should re-read state without a manual refresh.
      React.useEffect(function () {
        function onFocus () { load(true) }
        window.addEventListener('focus', onFocus)
        return function () { window.removeEventListener('focus', onFocus) }
      }, [])

      // Success messages are confirmations, not state: fade them out on their own.
      React.useEffect(function () {
        if (notice[0] === '') return undefined
        var timer = setTimeout(function () { setNotice('') }, 2800)
        return function () { clearTimeout(timer) }
      }, [notice[0]])

      function logout () {
        setBusy(true)
        setError('')
        setNotice('')
        fetchJson('/logout', { method: 'POST', body: {} })
          .then(function () {
            bootstrapCache = null
            setBusy(false)
            setNotice('已登出，本机凭据已删除。')
            return load(true)
          })
          .catch(function (error) {
            setBusy(false)
            setError(error.message || String(error))
          })
      }

      function save (overrides) {
        setBusy(true)
        setError('')
        setNotice('')
        // A blank client_id means "keep the stored one": the field only ever shows a mask,
        // and saving that mask back would break the client registration.
        var body = { redirectUri: form.redirectUri, scope: form.scope }
        if (form.clientId.trim() !== '') body.clientId = form.clientId.trim()
        // Explicit flag only — this function is also used directly as a click handler, and
        // spreading an event object into the body would post nonsense.
        if (overrides && overrides.useDefaultClient === true) body.useDefaultClient = true
        fetchJson('/config', { method: 'POST', body: body })
          .then(function () {
            setBusy(false)
            bootstrapCache = null
            setNotice('已保存。')
            return load(true)
          })
          .catch(function (error) {
            setBusy(false)
            setError(error.message || String(error))
          })
      }

      function savePreferences (patch) {
        setError('')
        fetchJson('/preferences', { method: 'POST', body: patch })
          .then(function (result) {
            setNotice('已保存。')
            setPayload(function (previous) {
              if (previous === null) return previous
              var status = Object.assign({}, previous.status, { preferences: result.preferences })
              return Object.assign({}, previous, { status: status })
            })
          })
          .catch(function (error) { setError(error.message || String(error)) })
      }

      if (payload === null) {
        return h('div', { className: 'cf-settings' },
          h('div', { className: 'cf-card' },
            h('div', { className: 'cf-skel w40' }),
            h('div', { className: 'cf-skel w60' }),
            h('div', { className: 'cf-skel w60' })))
      }

      var status = payload.status || {}
      var preferences = status.preferences || {}
      var accounts = status.accounts || []
      var connected = status.connected === true
      var configured = status.configured === true
      var tone = stateTone(status)
      var expiryText = formatWhen(status.expiresAt)
      var identity = status.email || status.name || status.activeUser || ''
      var chips = scopeList(form.scope)
      var builtIn = status.clientIdSource !== 'user'

      return h('div', { className: 'cf-settings' },

        /* ---- status ---------------------------------------------------- */
        h('div', { className: 'cf-card cf-hero' + heroTone(tone), style: { animationDelay: '0ms' } },
          h('div', { className: 'cf-spread' },
            h('div', { className: 'cf-row', style: { gap: 10 } },
              h('div', { className: 'cf-state' },
                h('span', { className: 'cf-dot ' + tone }),
                h('span', null, stateLabel(status))),
              connected
                ? h('span', { className: 'cf-badge' + (status.canRefresh ? '' : ' warn') },
                  h(Icon, { name: status.canRefresh ? 'check' : 'alert', size: 10, weight: 3 }),
                  status.canRefresh ? '自动续期' : '需重新授权')
                : null),
            h('div', { className: 'cf-row' },
              configured
                ? h(ConnectButton, { label: connected ? '重新授权' : '授权登录', primary: connected !== true })
                : h('button', { className: 'cf-btn primary', disabled: true },
                  h(Icon, { name: 'link', size: 13 }), h('span', null, '授权登录')),
              connected
                ? h('button', { className: 'cf-btn ghost', disabled: busy[0], onClick: logout },
                  h(Icon, { name: 'logout', size: 13 }), h('span', null, '登出'))
                : null)),

          connected
            ? h('div', { className: 'cf-meta' },
              identity !== '' ? h(MetaItem, { icon: 'user', text: identity, title: identity }) : null,
              expiryText !== '' ? h(MetaItem, { icon: 'clock', text: '令牌至 ' + expiryText }) : null,
              h(MetaItem, { icon: 'shield', text: '凭据本机加密保存' }))
            : h('div', { className: 'cf-hint' },
              configured
                ? 'client 信息已就绪，点「授权登录」在 Cloudflare 页面同意一次即可。'
                : '还没有可用的 OAuth 应用：到高级里填写 client_id 与回调地址并保存。')),

        errors[0] !== '' ? h('div', { className: 'cf-error' }, h(Icon, { name: 'alert', size: 13 }), h('span', null, errors[0])) : null,

        /* ---- connection parameters ------------------------------------- */
        h('div', { className: 'cf-card', style: { animationDelay: '70ms' } },
          h('div', { className: 'cf-sec' },
            h('span', { className: 'cf-sec-title' }, h(Icon, { name: 'key', size: 12 }), '连接参数'),
            h('span', { className: 'cf-sec-line' })),
          h('div', { className: 'cf-fields' },
            h('div', { className: 'cf-field' },
              h('div', { className: 'cf-label' }, '授权应用'),
              h('div', { className: 'cf-value' },
                h('span', { className: 'cf-mono' }, status.clientIdMasked || '未设置'),
                h('span', { className: 'cf-tag' + (builtIn ? ' auto' : '') }, builtIn ? '内置' : '自定义')),
              h('div', { className: 'cf-hint' }, builtIn
                ? '内置应用，已加密写入本机凭据库；要换用自己的 client 到高级里填写。'
                : '使用你填写的 client_id；要换回内置应用到高级里点「用回内置」。')),
            h('div', { className: 'cf-field' },
              h('div', { className: 'cf-label' }, '回调地址'),
              h('input', {
                className: 'cf-input',
                spellCheck: false,
                autoComplete: 'off',
                value: form.redirectUri,
                onChange: function (event) { setForm(Object.assign({}, form, { redirectUri: event.target.value })) }
              }),
              h('div', { className: 'cf-hint' }, '必须与 client 上登记的 redirect URI 完全一致，端口变了要同步改。')),
            h('div', { className: 'cf-field' },
              h('div', { className: 'cf-label' }, '权限范围'),
              h('input', {
                className: 'cf-input',
                spellCheck: false,
                autoComplete: 'off',
                placeholder: 'zone.read dns.read',
                value: form.scope,
                onChange: function (event) { setForm(Object.assign({}, form, { scope: event.target.value })) }
              }),
              chips.length > 0
                ? h('div', { className: 'cf-chips' }, chips.map(function (name) {
                  return h('span', {
                    key: name,
                    className: 'cf-chip' + (name === 'offline_access' ? ' auto' : '')
                  }, name)
                }))
                : h('div', { className: 'cf-hint' }, '空格分隔，必须是 client 上已登记的权限名。'))),
          h('div', { className: 'cf-row cf-actions' },
            h('button', { className: 'cf-btn primary', disabled: busy[0], onClick: save },
              h(Icon, { name: 'check', size: 13 }), h('span', null, busy[0] ? '保存中…' : '保存')),
            notice[0] !== '' ? h('span', { className: 'cf-ok' }, h(Icon, { name: 'check', size: 12 }), notice[0]) : null)),

        /* ---- advanced --------------------------------------------------- */
        h('div', { className: 'cf-card', style: { animationDelay: '140ms' } },
          h('div', { className: 'cf-sec' },
            h('span', { className: 'cf-sec-title' }, h(Icon, { name: 'sliders', size: 12 }), '高级'),
            h('span', { className: 'cf-sec-line' })),
          h('div', { className: 'cf-sub' },
            h(SubItem, {
              index: 0,
              title: '只读模式',
              hint: '拒绝一切写操作，包括 DNS 与缓存清理。',
              control: h('button', {
                className: 'cf-switch' + (preferences.readonly ? ' on' : ''),
                onClick: function () { savePreferences({ readonly: !preferences.readonly }) },
                title: preferences.readonly ? '已开启' : '已关闭',
                'aria-label': '只读模式'
              })
            }),
            h(SubItem, {
              index: 1,
              title: '默认账号',
              hint: '多账号时工具默认使用这个。',
              control: h('select', {
                className: 'cf-input',
                style: { width: 200 },
                value: preferences.defaultAccountId || '',
                onChange: function (event) { savePreferences({ defaultAccountId: event.target.value }) }
              },
              h('option', { value: '' }, '自动'),
              accounts.map(function (account) {
                return h('option', { key: account.id, value: account.id }, account.name || account.id)
              }))
            }),
            h(SubItem, {
              index: 2,
              title: '写入白名单',
              hint: '只允许修改这些 zone；留空不限制。',
              control: h('input', {
                className: 'cf-input',
                style: { width: 200 },
                spellCheck: false,
                placeholder: 'example.com',
                value: (preferences.zoneAllowlist || []).join(', '),
                onChange: function (event) {
                  var list = event.target.value.split(',').map(function (item) { return item.trim() })
                    .filter(function (item) { return item !== '' })
                  savePreferences({ zoneAllowlist: list })
                }
              })
            }),
            h(SubItem, {
              index: 3,
              title: '授权应用',
              hint: builtIn ? '留空继续使用内置应用。' : '当前使用自定义 client_id。',
              control: h('div', { className: 'cf-inline' },
                h('input', {
                  className: 'cf-input',
                  style: { width: 176 },
                  spellCheck: false,
                  autoComplete: 'off',
                  placeholder: builtIn ? '内置 ' + (status.clientIdMasked || '') : '粘贴你的 client_id',
                  value: form.clientId,
                  onChange: function (event) { setForm(Object.assign({}, form, { clientId: event.target.value })) },
                  onKeyDown: function (event) { if (event.key === 'Enter') save() }
                }),
                h('button', { className: 'cf-btn ghost mini', disabled: busy[0], onClick: function () { save() } }, '保存'),
                builtIn
                  ? null
                  : h('button', {
                    className: 'cf-btn ghost mini',
                    disabled: busy[0],
                    onClick: function () { save({ useDefaultClient: true }) }
                  }, '用回内置'))
            }),
            h(SubItem, {
              index: 4,
              title: '凭据库',
              hint: 'AES-256-GCM 加密的本机文件。',
              control: h('span', { className: 'cf-code' }, (status.vault && status.vault.path) || '?')
            }))),

        /* ---- footer ------------------------------------------------------ */
        h('div', { className: 'cf-foot' },
          h(Icon, { name: 'shield', size: 11 }),
          h('span', null, '基于 MIT 协议开源'),
          h('span', { className: 'cf-sep' }, '·'),
          h('a', {
            href: HOME_URL,
            target: '_blank',
            rel: 'noopener noreferrer',
            title: '在 GitHub 上查看源码与许可证'
          }, 'MFCJ45681/dsh-plugin-cloudflare')))
    }

    function apply (ctx) {
      ensureStyle()
      ctx.effect(function () {
        return ctx.slots.inject('settings.section', function () {
          return ctx.slots.register({
            name: 'settings.section',
            id: 'cloudflare',
            order: 60,
            label: function () { return 'Cloudflare' }
          }, SettingsSection)
        })
      }, 'cloudflare: settings section')
    }

    var module = { exports: {} }
    module.exports.apply = apply
    module.exports.inject = ['slots']
    return module.exports
  }
})
