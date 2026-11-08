# Cloudflare 连接插件 —— 原理与框架（设计稿 v1：P1 已落地）

> 目标：在 DSH 里做一个「连接 Cloudflare」的插件，形态对齐已有的 `@local/github-oauth`
> （宿主 cordis 插件 + 原生工具 + 同源 HTTP 路由 + 浏览器 UI + 加密凭据库）。
> 本文讲原理、边界、模块划分和分期；实现现状见 §12，代码在 `lib/`。

---

## 0. 一句话概括

插件跑在 DSH 宿主进程里，把 Cloudflare v4 API 包装成三样东西：

1. agent 可调用的 `cloudflare_*` 原生工具（读为主、写有闸门）；
2. 一个右侧栏面板 + 设置页（连接状态、zone 列表、最近操作、配额）；
3. 一组同源 HTTP 路由 `/plugins/cloudflare/*`（面板和工具共用同一份状态）。

凭据只存在本机 AES-256-GCM 凭据库里，宿主侧解密后直连 `api.cloudflare.com`；
**浏览器永远拿不到 token，token 也不进对话上下文、不进会话日志。**

---

## 1. 先确认产品定位（三选一或组合）

「连接 Cloudflare」在 DSH 里至少有三种完全不同的含义，它们的 API、风险和交付物都不一样：

| | A. 平台管理型 | B. 通道型 | C. 模型型 |
|---|---|---|---|
| 做什么 | 看/改 DNS、缓存、Workers、KV、R2、D1、Tunnel | 用 Cloudflare Tunnel 把本机 DSH 暴露到公网，或反代到自建域名 | 把 Workers AI / AI Gateway 接成 DSH 的 LLM provider |
| 主 API | REST v4 + GraphQL Analytics | `cloudflared` 进程 + Tunnel API | OpenAI 兼容端点 / AI Gateway |
| 产出 | 20+ 工具 + 管理面板 | 一条公网 URL + 访问策略 | 一个可选的模型列表 |
| 风险 | 写操作能改生产 DNS/配置 | 把本地 GUI 暴露到公网 | 计费 + 数据出境 |
| 复杂度 | 中（域多、写操作多） | 中（进程生命周期、证书） | 低 |

**本设计以 A 为主线**，B 和 C 作为后续可插拔模块（它们复用同一套 vault/HTTP/UI 骨架）。
如果真实需求其实是 B 或 C，第 4 节之后的工具面要整体换掉，但第 2、3 节的骨架不变。

---

## 2. 原理

### 2.1 认证：三种凭据，一条统一出口

| 方式 | 怎么来 | 优点 | 缺点 | 建议 |
|---|---|---|---|---|
| **API Token**（推荐） | Dashboard → My Profile → API Tokens，勾选最小权限 + 资源范围 | 最小权限、可单独吊销、可设 zone/account 范围、无回调地址要求 | 需要用户手动粘贴 | **默认路径** |
| Global API Key（遗留） | My Profile → API Tokens → Global API Key | 一次拿到全部权限 | 全权限、无法限域、泄露即全失守 | 允许但默认只读，UI 强警告 |
| **OAuth 应用** | Dashboard → Manage Account → OAuth clients（需 Super Administrator / Administrator / OAuth Client Write） | 点一次授权，无粘贴；scope 与 token 权限同名；私有 client 默认只有本账号成员能授权 | 需要先注册 client id/secret + 回调地址；只有授权码流程 | 二期做成「可选登录方式」 |

**v1 已定：API Token 走主路径（「API 形式」）**，OAuth 降为 P4 的可选补充（设计保留在 §11，
将来想加时只需多一个 credential kind，骨架不变）。API Token 的具体流程见 §2.2。

统一抽象：vault 里只存 **Credential**，不是「token 字符串」。

```
Credential = {
  id, kind: "api_token" | "global_key" | "oauth",
  label,                       // 用户可见名字，如 "prod-dns"
  token?, refreshToken?,       // 密文
  email?, key?,                // global_key 专用
  scopesHint: string[],        // 申请/探测到的权限
  accountId?, zoneIds?[],      // 可选资源范围
  expiresAt?, createdAt, lastVerifiedAt
}
```

校验与能力探测（这是设计里必须区分清楚的一件事）：

- **活性**：`GET /client/v4/user/tokens/verify` → `result.status === "active"`。
  它只证明 token 没过期/没吊销，**不返回权限清单**。
- **权限**：靠试探调用归因 —— 先 `GET /zones`、`GET /accounts` 拿到可见资源，
  再对具体资源调用；403 + `errors[].code` 才是「这个 scope 不行」的证据。
  探测结果缓存进 vault（`scopesHint`），并在设置页显式展示「能做什么/不能做什么」。
- **余额/配额**：`GET /user/tokens` 可拿 token 元数据（需相应权限），失败就降级不显示。

API Token 路径要点（v1 主路径，OAuth 细节见 §11）：

- **怎么建**：Dashboard → My Profile → API Tokens → **Create Token → Custom token**。
  P1 只需要三个权限组：`Zone → Zone → Read`、`Zone → DNS → Read`、`Account → Account Settings → Read`
  （P2 再加 `Zone → Cache Purge`、`Zone → DNS → Edit`）。**资源范围**选「Specific zone / account」而不是全账号，
  这样 token 泄露也只失守那几个 zone。
- **录入只能走 Web 表单，绝不能走工具参数** —— 工具参数会进对话记录和模型上下文，等于把 token 写进聊天截图。
  工具侧只负责回一个「去设置页粘贴」的指引（含 `writeGuard` 提示），vault 写入由同源路由 `POST /plugins/cloudflare/token` 完成。
  无 UI 环境用 `scripts/configure.js token set --stdin`。
- **录入即校验**（三步，任一步失败都要说清原因，不能只说「失败」）：
  1. `GET /user/tokens/verify` → `active` + `expires_on`（有 TTL 就存下来，到期前提醒）；
  2. `GET /zones` / `GET /accounts` → 可见资源清单（同时作为 `zoneIds`/`accountId` 候选）；
  3. 试探性调用按 403 归因，把缺失的权限组翻译成人话（「缺 Zone:DNS:Read」），写进 `scopesHint`。
- **token 值只显示一次**：UI 要求粘贴后立刻加密落盘，不落日志、不回显完整值（只回尾 4 位）。
- **多凭据**：同 kind 可存多条 + 一个默认指针，供 §10 第 3 条的多账号切换使用。

### 2.2 请求层：一个 Cloudflare 客户端

- Base：`https://api.cloudflare.com/client/v4/`，头 `Authorization: Bearer <token>`
  （Global Key 用 `X-Auth-Email` + `X-Auth-Key`）。
- 信封统一：`{ success, errors[{code,message}], messages[], result, result_info }`。
  **永远先看 `success`，再看 HTTP 状态码** —— 400/403/404 也可能带 `success:false` 的结构化原因。
- 分页：`result_info` 里 `page / per_page / count / total_count / total_pages`，
  查询参数 `page`、`per_page`（最大 100 左右，过大易超时）、`order`、`direction`。
- 分析数据走 **GraphQL**：`POST /client/v4/graphql`，按数据集（httpRequests1dGroups 等）取，
  成本按查询复杂度计费，限制远比 REST 紧。
- 速率限制（官方）：**1200 请求 / 5 分钟 / 用户或 token**，**200 请求 / 秒 / IP**，
  GraphQL **320 / 5 分钟**；超限返回 429，5 分钟内全封。
  响应头 `Ratelimit: "default";r=50;t=30`、`Ratelimit-Policy`、以及仅在 429 时的 `retry-after`。
- 因此客户端内建：**串行队列 + 令牌桶**（默认 4 req/s、突发 10）、**指数退避**（429 读 `retry-after`，
  5xx 退避 3 次）、**GET 短 TTL 缓存**（15s，写操作后按资源前缀失效）。
- 写操作没有幂等键，所以采用 **写后读回校验**：create 后 GET 一次确认存在，
  delete 后 GET 期望 404，失败就回 `E_UNVERIFIED` 而不是假装成功。

### 2.3 凭据落盘：加密 vault

```
master key: 环境变量 CLOUDFLARE_PLUGIN_MASTER_KEY，否则 ~/.dsh/.../cloudflare/master.key（0600）
vault.json: { version, kdf, salt, iv, tag, ciphertext }   // AES-256-GCM，密文内含全部 credential + preferences
```

- 理由：API token 等价于账号权限，明文落盘等于把钥匙放在桌面；DSH 目录常被备份/同步。
- 主密钥与密文分离存放，换机器可只搬 vault 不搬 key（或反之）。
- 解密失败必须**降级不崩溃**：插件继续加载，`/status` 说明「vault 不可解密」，
  工具返回 `E_VAULT_DECRYPT`，而不是让整个 DSH 起不来。
- vault 内容永不回传浏览器：路由只返回脱敏信息（`tokenId`、尾 4 位、`label`、`scopesHint`）。

### 2.4 信任边界（谁看得见 token）

```
浏览器 client.js  ──同源 /plugins/cloudflare/*──▶  宿主插件进程  ──Bearer──▶  api.cloudflare.com
   ▲ 只看脱敏状态                                       ▲ 唯一持有明文 token
   │                                                    │
   └──────────── DSH 会话/工具结果（无 token） ───────────┘
```

三条硬规则：

1. token 不进入工具返回值、不进入日志、不进入 UI DOM；
2. 浏览器 → 宿主的请求全部走同源路由，**不做**「前端直连 Cloudflare」（那必然要把 token 给浏览器）；
3. 写操作在宿主侧再判一次权限（不能只靠 UI 灰化按钮）。

### 2.5 工具面：给 agent 的契约

每个工具返回同一信封（对齐 `github_*` 的形状，模型只需学一次）：

```
{ ok, code, text, data, status?, rateLimitRemaining?, rateLimitReset?, nextPage?, cloudflare?: { rayId, errors } }
```

- `text` 是人/模型可读摘要；`data` 是结构化结果（截断到预算，默认 20k 字符，上限 200k）。
- 失败**返回** `ok:false` 而不是抛异常，避免一个工具挂了毁掉整轮对话。
- 错误码固定表（见 §6），`text` 里附带一句「下一步怎么办」的提示。
- 写操作分级：
  - **safe**（可逆/低影响）：创建 DNS 记录除外的多数读、缓存 purge 单 URL；
  - **guarded**（必须先 dry-run 再确认）：DNS 记录增删改、缓存全清、Workers 部署；
  - **dangerous**（删除类 + D1 任意 SQL）：必须传 `confirm: "<资源名或 ID>"` 精确匹配，否则 `E_CONFIRM_REQUIRED`。
- `dry_run: true` 对写工具返回「将要发送的 method/path/body 摘要」，不真正调用 ——
  这是让 agent 自查意图的最低成本手段。

---

## 3. DSH 插件框架（宿主侧 + 浏览器侧）

### 3.1 运行模型

```
dsh web 启动
  └─ cordis loader 读 profile 的 dsh.profile.bundles
       └─ 加载 dsh-plugin-cloudflare（package.json main → lib/index.js）
            ├─ exports.name      = "dsh-plugin-cloudflare"（必须等于包名）
            ├─ exports.inject    = ["tools", "webServer"]
            ├─ exports.apply(ctx, config)
            │    ├─ new VaultStore()            凭据
            │    ├─ ctx.effect(() => ctx.webServer.register(route))   路由（随插件卸载自动摘除）
            │    └─ ctx.effect(() => ctx.tools.register(tool))        工具
            └─ package.json 的 dsh.client 声明
                 └─ dsh-client-modules 把 ./client.js 挂到 /plugins/dsh-plugin-cloudflare/client.js
                      └─ 浏览器侧 exports.inject = ["slots"]
                           └─ ctx.slots.inject('settings.section', ...)   设置页（唯一 UI 入口）
```

要点（都是从现有 `@local/github-oauth` 验证过的写法）：

- 工具注册依赖 `@deepseek-ai/dsh-tools` 的 `defineTool`，但插件树和 runtime 树是两套，
  **不能裸 require**，要按候选 base 逐个 `require.resolve`，失败再 `import()` 回退；
  注册失败要报 `PARTIAL_REGISTRATION`（注册表没有批量回滚）。
- 所有注册都包在 `ctx.effect(...)` 里，插件停用/重载时自动清理。
- Web 侧改动需要 `dsh plugin` 安装 + 重启（或跑 `pnpm run dev:web` 才有 HMR）。

### 3.2 包结构

```
cloudflare-plugin/
├── package.json            # name/main/exports + dsh.bundle.patch + dsh.client
├── cordis.patch.yml        # insert: id + name = dsh-plugin-cloudflare
├── lib/
│   ├── index.js            # 宿主入口：vault → routes → tools
│   ├── crypto.js           # AES-256-GCM 原语、master key 读写
│   ├── vault.js            # Credential/Preferences/Audit 的加密存储与脱敏视图
│   ├── cf-api.js           # 唯一出口：URL 组装、信封解析、分页、限流、重试、写后校验
│   ├── auth.js             # verify、scope 探测、OAuth 换 token/刷新、requireToken
│   ├── oauth.js            # authorize URL、PKCE、state
│   ├── state.js            # 一次性 state / 待确认操作（TTL Map）
│   ├── routes.js           # /plugins/cloudflare/*（status/connect/oauth/logout/*）
│   ├── tools-auth.js       # cloudflare_auth_* + 账户/zone 发现
│   ├── tools-dns.js        # DNS 记录 CRUD
│   ├── tools-cache.js      # 缓存查询与 purge
│   ├── tools-workers.js    # scripts / KV / R2 / D1（按域再拆）
│   ├── audit.js            # 本地操作审计（jsonl，脱敏）
│   ├── client.js           # 浏览器 bundle：面板 / 设置页 / 输入框按钮
│   └── ui/                 # 面板用的小组件（可选，先内联在 client.js）
├── scripts/configure.js    # 无 UI 时的 CLI：set / use-default / doctor
├── test/                   # node:test：crypto、vault、api 信封、路由、tools、限流
├── CHANGELOG.md
├── install.sh / uninstall.sh
└── DESIGN.md
```

### 3.3 与 GitHub 插件的复用关系

可直接照搬的结构：crypto/vault 的密文格式、`require.resolve` 找 `defineTool` 的兼容逻辑、
`ctx.effect` 注册模式、路由的 sendJson/CSRF/大小上限、工具信封与错误码风格、测试基线。
**不能照搬的**：GitHub OAuth 的 scope 语义、单资源域（repo）假设、以及「只读为主」的风险模型 ——
Cloudflare 的写操作能改生产流量，闸门必须更硬。

---

## 4. 模块职责与数据流

### 4.1 一次工具调用的完整链路

```
tool call(cloudflare_dns_records_create)
  → 参数校验（zone 标识解析：name | id；类型白名单）
  → requireToken()（无凭据 → E_NOT_CONNECTED）
  → 危险级判定（guarded → 需要 dry_run/confirm）
  → cf-api.request()：队列等待 → 组 URL → fetch → 信封解析
       ├─ success:true  → 写后读回校验 → 失效缓存 → audit 记录 → 返回
       └─ success:false → 错误归一化（403/429/404/5xx）→ 返回 ok:false
```

### 4.2 状态机（连接状态）

| 状态 | 含义 | 面板表现 | 可用工具 |
|---|---|---|---|
| `unconfigured` | 没有任何凭据 | 「连接 Cloudflare」按钮 | 仅 `cloudflare_auth_*` |
| `invalid` | token 被吊销/过期 | 红色 + 重新连接 | 仅 `cloudflare_auth_*` |
| `readonly` | 有凭据但只探测到读权限，或用户开了只读开关 | 黄色 | 读工具；写工具返回 `E_READONLY` |
| `connected` | 正常 | 绿色 + zone 数 | 全部（受危险级闸门） |
| `degraded` | vault 不可解密 / 网络不可达 | 灰色 + 原因 | 仅 `cloudflare_auth_status` |

### 4.3 关键数据

```
Preferences = { defaultZoneId?, pinnedZones[], readonlyMode, writeAllowlist: { zoneIds[], accountIds[] }, pageSize }
AuditEntry  = { ts, tool, method, path, target, dryRun, ok, code, requestId?, rayId? }   // 不含 body 全量
```

`writeAllowlist` 是「防手滑」的核心：即便 agent 被提示注入，也只能在用户勾选的 zone 里写。

---

## 5. 工具清单（分期）

| 工具 | 作用 | 需要的 token 权限 | 风险 | 期 |
|---|---|---|---|---|
| `cloudflare_auth_status` | 连接状态、脱敏凭据、scope 探测结果 | — | safe | P1 |
| `cloudflare_auth_setup` | 保存 API Token / Global Key（含只读模式） | — | safe | P1 |
| `cloudflare_auth_start` | 生成 OAuth 授权 URL（PKCE） | — | safe | P4 |
| `cloudflare_auth_logout` | 删除凭据 + 清缓存 | — | safe | P1 |
| `cloudflare_accounts` | 列出可见 account | Account Settings:Read | safe | P1 |
| `cloudflare_zones` | 列出 zone（按 name 过滤、分页） | Zone:Read | safe | P1 |
| `cloudflare_zone` | 单 zone 详情（plan/status/name_servers/paused） | Zone:Read | safe | P1 |
| `cloudflare_dns_records` | 列出/搜索记录（type/name/content） | DNS:Read | safe | P1 |
| `cloudflare_dns_create` | 新增记录（A/AAAA/CNAME/TXT/MX/SRV/CAA） | DNS:Edit | guarded | P2 |
| `cloudflare_dns_update` | 改记录（PATCH） | DNS:Edit | guarded | P2 |
| `cloudflare_dns_delete` | 删记录 | DNS:Edit | **dangerous** | P2 |
| `cloudflare_cache_purge` | purge 单 URL / 前缀 / 全部（全部=guarded） | Cache Purge | guarded | P2 |
| `cloudflare_zone_settings` | 读/改 SSL、Always Use HTTPS、开发模式等 | Zone Settings:Read/Edit | guarded | P3 |
| `cloudflare_workers_list` | 列 scripts + 路由 | Workers Scripts:Read | safe | P3 |
| `cloudflare_workers_deploy` | 上传/更新 script（multipart） | Workers Scripts:Edit | guarded | P3 |
| `cloudflare_kv` | namespace 列表 / key 读 / key 写删 | Workers KV Storage | guarded | P3 |
| `cloudflare_r2` | bucket 列表/建/删（对象读写走 S3 API） | Workers R2 Storage | guarded | P4 |
| `cloudflare_d1_query` | 执行 SQL（读/写） | D1:Edit | **dangerous** | P4 |
| `cloudflare_tunnel` | Tunnel 列表/创建/删除、路由 | Cloudflare Tunnel:Read/Edit | guarded | P4 |
| `cloudflare_graphql` | 只读分析查询（流量/缓存命中/错误率） | Analytics:Read | safe | P3 |
| `cloudflare_api` | 兜底：任意 v4 路径（默认只读 method 白名单） | 取决于调用 | guarded | P2 |

实现期必须提前知道的两个坑：

1. **Workers 部署不是纯 JSON**：`PUT /accounts/{id}/workers/scripts/{name}` 要 `multipart/form-data`
   （`metadata` part + 一个或多个模块文件），Node 侧要么手写 multipart 组装，要么直接调 `wrangler`。
   这决定了 `cf-api.js` 的 body 抽象不能只支持 JSON。
2. **R2 对象不是 v4 REST**：桶管理走 `/accounts/{id}/r2/buckets`，但对象上传/下载要走 S3 兼容接口，
   需要 R2 的 Access Key / Secret，**和 API Token 是两套凭据**。所以 R2 要么只做桶管理，要么在 vault 里加第二类凭据。

---

## 6. 统一错误码

| code | 触发 | 提示方向 |
|---|---|---|
| `E_NOT_CONNECTED` | 无凭据 | 先 `cloudflare_auth_status` / `cloudflare_auth_setup` |
| `E_INVALID_TOKEN` | verify 失败 / 401 | 重新生成 token |
| `E_INSUFFICIENT_SCOPE` | 403 + 权限类 error code | 指出缺哪个权限 + 控制台路径 |
| `E_READONLY` | 只读模式 / 无写权限 | 在设置里开启写权限或换 token |
| `E_CONFIRM_REQUIRED` | 危险操作缺 confirm | 先 dry_run 再带 confirm 调用 |
| `E_RATE_LIMIT` | 429 且退避耗尽 | 给出 `rateLimitReset` |
| `E_NOT_FOUND` | 404 / success:false | 检查 zone/record/script 标识 |
| `E_INPUT` | 本地校验失败 | 具体哪个字段 |
| `E_UPSTREAM` | 5xx | 原样报 Cloudflare 状态码 + rayId |
| `E_NETWORK` | DNS/连接失败 | 代理设置提示 |
| `E_VAULT` | 解密/密钥错误 | 修 master key 或重建 vault |
| `E_UNVERIFIED` | 写后读回不一致 | 明确说「可能已生效，请人工确认」 |
| `E_TRUNCATED` | 超输出预算 | 缩小 pageSize / 加过滤条件 |

---

## 7. HTTP 路由与 UI

### 7.1 路由（全部同源，挂 `ctx.webServer`）

```
GET  /plugins/cloudflare/status        连接状态 + 脱敏凭据 + 配额（不含 token）
POST /plugins/cloudflare/connect       保存 token / global key（可带 readonly 标记）
POST /plugins/cloudflare/disconnect    删凭据
GET  /plugins/cloudflare/oauth/start   302 到 dash.cloudflare.com/oauth2/auth
GET  /plugins/cloudflare/oauth/callback 换 token（校验 state + HttpOnly cookie）
GET  /plugins/cloudflare/zones         面板用 zone 速览（短 TTL 缓存）
GET  /plugins/cloudflare/audit         最近 N 条操作
GET  /plugins/cloudflare/preferences   默认 zone / allowlist / 只读开关
POST /plugins/cloudflare/preferences   同上（原子替换）
```

约束：body ≤ 64KB、`content-type` 校验、`cache-control: no-store`、POST 一律校验 `Origin`/`Sec-Fetch-Site`；
OAuth 用一次性 `state` + HttpOnly `SameSite=Lax` cookie 双校验（挡 login CSRF），state 10 分钟过期。

### 7.2 UI 三块

| 位置 | 内容 | 不显示什么 |
|---|---|---|
| 设置 → Cloudflare | 连接方式（Token/OAuth）、权限探测结果、只读开关、写白名单、默认 zone、凭据删除 | token 明文（最多尾 4 位） |
| 设置页 Cloudflare 分节 | 状态卡（状态点 + 续期徽标 + 账号/到期/加密三项元信息）、连接参数卡（client_id / 回调地址 / 权限范围 + scope 胶囊）、高级二级列表（只读 / 默认账号 / 写白名单 / 凭据库路径，常驻展开 + 逐条入场动画）。视觉全走 `--dsw-alias-*` 主题 token（含 `settings-card-fill/-stroke`），浅色与深色自动适配，图标为内联 SVG，不引第三方依赖 | 任何 body 里的敏感内容 |
| 输入框左侧按钮 | 当前连接账户（多凭据时点开切换） | — |

---

## 8. 安全模型（威胁 → 对策）

| 威胁 | 后果 | 对策 |
|---|---|---|
| vault.json 泄露 | 全账号权限 | AES-256-GCM + 主密钥分离（env/0600 文件）+ 支持轮换 |
| 浏览器 XSS | 拿不到 token（本就不下发） | 路由只回脱敏数据；CSP；无 `innerHTML` 拼接 |
| 恶意网页 CSRF 调本地路由 | 替用户连上攻击者的账号 / 触发 purge | state + cookie、Origin 校验、危险路由要求带一次性 confirm token |
| 提示注入让 agent 删生产 DNS | 站点挂掉 | 写白名单（zone 级）+ 危险级 confirm 精确匹配 + dry_run + 审计 |
| 日志/会话泄漏 token | 同上 | 单点脱敏函数（所有日志/错误路径共用）+ 测试断言 token 不出现在任何序列化结果 |
| `cloudflare_api` 兜底被滥用 | 绕过域级闸门 | 默认 method 白名单只读；写需显式开启 + 仍在白名单 zone 内 |
| 上游 429 拖垮整轮对话 | 体验差 | 队列 + 退避 + `E_RATE_LIMIT` 明确回归时间 |
| Workers 部署/ SQL 破坏性 | 生产事故 | Phase 3/4 才开；部署前强制 dry_run 显示 diff 摘要；D1 只允许显式 `confirm` |

---

## 9. 分期与验收

| 期 | 内容 | 验收（可测） |
|---|---|---|
| **P0 骨架** | 包结构、cordis.patch、vault、`/status`、`cloudflare_auth_status` | 插件装进 profile 后重启可见；无凭据时状态 `unconfigured`；master key 错误时插件仍加载并报 `E_VAULT` |
| **P1 只读** | token 录入、auth_status、accounts/zones/dns 列表、audit、设置页 | 粘一个真实 token 后状态 `connected` 并列出 zone；token 从不出现在 DOM/工具返回/会话日志；GET 缓存 15s 生效 |
| **P2 写（DNS/缓存）** | create/update/delete、purge、写白名单、confirm | 未带 confirm 的 delete 返回 `E_CONFIRM_REQUIRED`；dry_run 不发请求；写后读回校验；429 时退避后返回 `E_RATE_LIMIT` |
| **P3 Workers/KV/GraphQL** | scripts 列表与部署、KV、分析查询 | 部署走 multipart；GraphQL 只读；错误码覆盖 403/5xx |
| **P4 OAuth + 面板完善** | OAuth client、R2/Tunnel/D1 | 私有 client 授权后状态 `connected`；refresh/过期行为有测试；面板显示配额 |

---

## 10. 待确认（影响实现顺序，不影响骨架）

1. 定位是 **A（平台管理）/ B（Tunnel 通道）/ C（Workers AI 模型）** 还是 A+ ？
2. ~~凭据优先 API Token 还是 OAuth~~ → **已定：API Token**（OAuth 留作 P4 可选）
3. 需要 **多凭据/多账号** 切换吗（像 GitHub 插件那样）？
4. 写操作是「每次确认」还是允许「信任模式」（白名单内免确认）？
5. Workers 部署要不要兼容 wrangler 的配置（wrangler.toml / 路由 / bindings），还是只做单文件 script 上传？

---

## 11. OAuth 方案详解（备选通道，P4 再做）

### 11.1 一个无法回避的约束：没有「内置 OAuth 应用」

GitHub 插件能随包内置一个 OAuth App（secret 相当于公开信息，真正的权限来自用户点的那次同意）。
Cloudflare 不行：OAuth client **归属某个 Cloudflare 账号**，私有 client（默认）只有该账号成员能授权，
要变成 public 还必须做域名归属验证且**不可逆**。

结论：**每个用户必须自己注册一次 client（约 5 分钟），之后每次连接都是一键**。
这不是设计缺陷，而是 Cloudflare 的信任模型决定的；插件要做的是把这一次注册流程做到「照着点就行」——
设置页给出参数清单、可一键复制的回调地址、以及「这些 scope 分别对应什么能力」的对照表。

### 11.2 Client 注册参数（用户做一次）

| 字段 | 值 | 说明 |
|---|---|---|
| 入口 | Dashboard → Manage Account → **OAuth clients** → Create client | 需要 Super Administrator / Administrator / **OAuth Client Write** |
| response type | `code` | 只支持授权码流程，无 device code / client credentials |
| grant type | `authorization_code` | 同上 |
| token 认证 | `none`（PKCE S256）优先；`client_secret_basic`/`post` 备选 | PKCE 客户端不留 secret，本地安装更安全 |
| redirect URI | `http://127.0.0.1:3080/plugins/cloudflare/oauth/callback` | 必须逐字符匹配；端口随 DSH 而变，主流程固定一个 |
| scopes | P1：Zone Read、DNS Read；P2 再加 DNS Edit、Cache Purge | 建议把**写权限标为 optional**，用户可在同意页一键关掉 → 天然只读授权 |
| visibility | private（默认） | 私有就够了；public 要求域名验证且不可回退 |

拿到 `client_id`（机密客户端还有 `client_secret`）后填进插件设置页，存在 vault 里。

### 11.3 授权时序

```
面板「连接 Cloudflare」
  → GET /plugins/cloudflare/oauth/start
       生成 state(32B) + code_verifier(43~128B)，存 pending（TTL 10min，可并存多个）
       Set-Cookie: cfo_state=<state>; HttpOnly; SameSite=Lax; Path=/plugins/cloudflare
       302 → https://dash.cloudflare.com/oauth2/auth
              ?client_id&redirect_uri&response_type=code&scope&state
              &code_challenge=S256(verifier)&code_challenge_method=S256
  → 用户在 Cloudflare 选账号、勾权限、点 Authorize
  → GET /plugins/cloudflare/oauth/callback?code&state
       校验 state 同时匹配 pending store 与 cookie（挡 login CSRF）→ 取出 verifier
       POST https://dash.cloudflare.com/oauth2/token  (authorization_code + verifier / 或 client_secret)
       拿到 access_token / expires_in / scope / refresh_token?
  → GET https://dash.cloudflare.com/oauth2/userinfo             身份（email/id）
  → GET https://api.cloudflare.com/client/v4/accounts、/zones   可见资源
  → 写 vault（密文）+ 清 GET 缓存 + audit
  → 302 回 /plugins/cloudflare/done（纯前端页面，不带任何 token）
```

端点不硬编码：优先读 `https://dash.cloudflare.com/.well-known/openid-configuration`，
失败再回退到常量（auth/token/revoke/userinfo 都在 `https://dash.cloudflare.com/oauth2/*`）。

### 11.4 token 生命周期

| 场景 | 行为 |
|---|---|
| 正常 | 请求前检查 `expiresAt - 60s`，过期内联 refresh |
| 401 / 403 权限类 | 有 `refresh_token` 就先换一次再**重试一次**原请求；再失败 → `invalid` |
| refresh 失败 / 无 refresh_token | 状态 `invalid`，工具返回 `E_INVALID_TOKEN`，面板显示「重新授权」 |
| 用户 logout | `POST /oauth2/revoke`（token + refresh_token）→ 删 vault 条目 → 清缓存 |
| 用户在 dashboard 撤销 | 我们只能观察 401 → 走 `invalid`，这是正常路径，不要当异常上报 |
| 授权响应带可选 scope 被拒 | 不是错误：降级为 `readonly`，面板黄色提示 |

### 11.5 权限推导：不猜 scope 名

官方 scope 名等同 API token 权限名（文档示例 `workers-platform.read` / `.write`），
但具体字符串会随产品变化，**硬编码是坑**。设计：

1. 授权响应里的 `scope` 是**权威**，存 vault 为 `grantedScopes`；
2. 每个工具声明 `requiredScopes`（内部别名 → 官方串的映射表，集中在一个常量文件）；
3. 工具可用性 = 别名映射命中且被授予；映射不到的串放 `unknown` 桶，设置页原样展示；
4. 上游实际返回 403 时，把该能力永久标记为 `missing`（直到重新授权），
   因为 scope 字符串对不上时，真实权限只能靠上游说话。

### 11.6 失败矩阵

| 现象 | 原因 | 处理 |
|---|---|---|
| `invalid_request: redirect_uri` | 回调地址不匹配（换端口/profile 后最常见） | 面板直接显示「去把回调地址改成 X」 |
| state 缺失/不匹配/过期 | 过期、重启、被别的标签页用掉 | 拒绝并提示重新点连接（这是 CSRF 防线在工作） |
| `access_denied` | 用户点了拒绝 | 状态不变，提示可重试 |
| `invalid_grant` (PKCE) | pending 丢失（DSH 中途重启） | 提示重走授权，不要重试换 token |
| 同意页看不到目标账号 | 管理员在 Members → Settings 关了 OAuth 访问 | 提示改用 API Token 通道 |
| 令牌端点 5xx / 网络断 | 上游抖动 | 可重试；state 在成功换到 token 后才删除 |
| `http:` 回调被拒 | 注册页要求 https | 先按 wrangler 的做法验证（它用 `http://localhost:8976/oauth/callback` 完成登录，说明 localhost + http 可行） |

### 11.7 对 §3 框架的影响

- `lib/oauth.js`：authorize URL、PKCE、state、token 交换、refresh、revoke、OIDC 发现；
  与之配套的 `lib/auth.js` 只保留「取当前 credential → 必要时 refresh → 组装请求头」。
- 路由新增（原 §7.1 已列）：`oauth/start`、`oauth/callback`、`oauth/config`（client id/secret）、
  `oauth/revoke`、`done`（结果页）。
- vault 增加两类记录：`oauthClient`（clientId、clientSecret?、redirectUri、scopes 模板）与 `oauthToken`
  （access、refresh、expiresAt、grantedScopes、userinfo、accountIds）。
- `cloudflare_auth_status` 的返回要带 `grantedScopes` + 推导出的能力矩阵 + 授权时间 + 是否只读。
- `scripts/configure.js` 增加 `oauth-client set --client-id ... [--client-secret-stdin]`，
  方便无 UI 环境先把 client 配好。
- 仍保留 API Token 通道（同一套 `requireToken` 出口，只是 credential kind 不同），
  这样 §2.1 的三种凭据抽象不用推翻。

### 11.8 动手前先验证的三件事（10 分钟，做完再写 P1）

1. Dashboard 建 client 时，`token_endpoint_auth_method = none`（纯 PKCE）的**私有** client 是否被接受；
2. `http://127.0.0.1:3080/plugins/cloudflare/oauth/callback` 这种明文本地回调是否被接受；
3. 授权响应里到底有没有 `refresh_token`、`expires_in` 多长 —— 这决定 §11.4 要不要加「定时静默重授权」。

这三点都只影响实现细节，不影响 §3 的骨架；任意一点不通，就退回 API Token 通道，工具面完全不变。


---

## 12. 实现现状（P1 + OAuth，已可用）

### 12.1 文件与职责

| 文件 | 行数 | 职责 |
| --- | --- | --- |
| `lib/index.js` | 210 | 宿主入口：`exports.name = 'dsh-plugin-cloudflare'`、`inject = ['tools','webServer']`，注册 12 条路由 + 9 个工具，`probe()` 给 doctor 用 |
| `lib/oauth.js` | 289 | OIDC 发现（1h 缓存，失败回退常量）、PKCE S256、authorize URL、code 交换、refresh、revoke、userinfo |
| `lib/auth.js` | 102 | `resolveCredential()`：取 credential → 60s 内过期就 refresh → 组装 Bearer；`explainOAuthFailure()` 把 OAuth 错误码翻成人话 |
| `lib/cf-api.js` | 269 | 唯一出口：4 req/s 串行限速、GET 15s 缓存、401 刷新重试一次、429 读 retry-after（上限 10s）、错误码映射、`lastRateLimit` |
| `lib/vault.js` | 424 | AES-256-GCM 信封（`cfo1`）、原子写 0600、主密钥来自 env 或 `master.key`、`status()` 脱敏视图 |
| `lib/scopes.js` | 84 | 能力分类器：把任意 scope 字符串按「资源词 + 动作词」映射到九项能力，映射不到进 unknown 桶 |
| `lib/state.js` | 87 | 一次性 state + PKCE verifier 的 pending 存储（TTL 10 分钟，最多 16 条并发） |
| `lib/routes.js` | 471 | 12 条同源路由 + state cookie 双校验 + 自带样式的回调结果页 |
| `lib/tools.js` | 519 | 9 个 `cloudflare_*` 工具，统一 `{ok, code, text, data, status, rateLimit}` 信封与中文下一步提示 |
| `lib/client.js` | 337 | 浏览器 bundle：只注册设置页分节，`window.__ModuleLoader__` 装载 |

### 12.2 实际路由

```
GET  /plugins/cloudflare/status        GET  /plugins/cloudflare/bootstrap
POST /plugins/cloudflare/config        GET|POST /plugins/cloudflare/start
GET  /plugins/cloudflare/callback      GET  /plugins/cloudflare/done
POST /plugins/cloudflare/logout        GET  /plugins/cloudflare/accounts
GET  /plugins/cloudflare/zones         GET  /plugins/cloudflare/scopes
GET|POST /plugins/cloudflare/preferences
```

### 12.3 与 §4.2 状态机的差异

实现里把「已配置 client 但还没授权」单独命名为 `pending`，`invalid` 只留给「有身份但用不了」，
避免面板把「还没连接」显示成「授权失效」：

```
unconfigured ──配置 client──▶ pending ──授权成功──▶ connected
                                 ▲                    │
                                 └──── 令牌过期/撤销 ──┘（expired / 重新授权）
```

### 12.4 本地已验证

- 全部模块 `node --check` 通过；
- 用临时 `http.Server` 挂 12 条路由跑通：`/status`、`/preferences`、`/config`（写入后 `configured=true`、
  状态转 `pending`）、`/bootstrap`、`/start`（返回带 `code_challenge_method=S256` 的授权 URL）、
  `/callback`（坏 state 返回 400 结果页）；
- `buildTools({defineTool: identity})` 造出 9 个工具，`cloudflare_auth_status.execute({})` 返回可读中文状态；
- vault 在空目录下自建 `vault.json` + `master.key`（0600），`probe()` 报告 `state=unconfigured`；
- `npm test`（`node --test test/*.test.js`）6 项通过：密文里不含明文令牌/邮箱、主密钥 0600、
  主密钥错时 `status()` 降级为 `state=error` 而不是抛异常、state 一次性且容量封顶、
  PKCE 形状与 authorize URL 的参数（无 scope 时不带 scope 参数）、scope 词根分类与 unknown 桶；
- 浏览器 bundle 在 stub 宿主里 `factory()` + `apply(ctx)` 跑通，注册了 tab + 两个 slot。

### 12.5 尚未做（按优先级）

1. **装进 profile 并重启 Web 验证真实装载**（`dsh plugin --profile web add link:...`，需要重启 `dsh web`）；
2. P2 写操作：DNS 增删改、cache purge、`dry_run` 与 `confirm` 语义、zone 白名单强制执行；
3. API Token 降级通道（`lib/token.js` + `/plugins/cloudflare/token`），OAuth 不通时的备胎；
4. Workers/KV/R2/D1 与 `cloudflare_graphql`；
5. `scripts/configure.js`（无 UI 环境的一次性配置）。

### 12.6 已知取舍

- **不硬编码 scope 字符串**：Cloudflare 的 scope 名没有稳定公开清单，`scopes.js` 用词根分类，
  真正的权威仍是上游 403；`/scopes` 路由可随时拉官方目录做对照。
- **工具不接收 token / client_id**：这两个值只能走设置页表单，因为它们出现在工具参数里就会进
  对话记录与模型上下文。
- **界面只做 PKCE，不提供 client_secret 输入框**（v1.1）：机密客户端仍由 `/config` 接口支持，
  但常规路径是 public client + PKCE，少一个能填错的字段就少一类故障。
- **界面只在设置页出现**（v1.1）：右侧栏 tab 与能力矩阵已移除，避免同一份状态有两处入口；
  状态、授权、登出、配置全部收在 `设置 → Cloudflare` 一处。
- **限速宁可保守**：4 req/s 远低于 Cloudflare 的 1200/5min，代价是批量读慢一些，换取不触发 5 分钟封禁。
