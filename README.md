# dsh-plugin-cloudflare

[![npm version](https://img.shields.io/npm/v/dsh-plugin-cloudflare.svg)](https://www.npmjs.com/package/dsh-plugin-cloudflare)
[![license](https://img.shields.io/npm/l/dsh-plugin-cloudflare.svg)](./LICENSE)
[![node](https://img.shields.io/node/v/dsh-plugin-cloudflare.svg)](package.json)
[![test](https://img.shields.io/badge/tests-12%20passing-brightgreen)](./test)

让 DSH 连上 Cloudflare：设置页里一个配置分节 + `cloudflare_*` 工具，走 **OAuth 授权码 + PKCE**，令牌用 AES-256-GCM 加密存在本机。不写代码也能看懂的部分见 [DESIGN.md](./DESIGN.md)。

本项目基于 [MIT 协议](./LICENSE)开源。

## 它做什么

| 能力 | 形态 |
| --- | --- |
| 连接/断开 Cloudflare | OAuth 2.0 授权码流程，PKCE S256，state 双校验 |
| 凭据保存 | `~/.dsh/cloudflare/vault.json`（AES-256-GCM），主密钥来自 `CLOUDFLARE_PLUGIN_MASTER_KEY` 或同目录 `master.key` |
| 给模型用的工具 | 9 个只读工具：状态、配置、授权、登出、账号、zone、zone 详情、DNS 记录、能力清单 |
| UI | 只占一处：设置页 → `Cloudflare` 分节（状态卡 + 连接参数 + 高级二级列表；跟随宿主主题的浅/深色 token）|

## 安装

从 GitHub 装（推荐）：

```bash
dsh plugin --profile web add github:MFCJ45681/dsh-plugin-cloudflare
```

从本地目录装（改代码时用软链更方便）：

```bash
dsh plugin --profile web add link:/path/to/dsh-plugin-cloudflare
```

或者手工两步：把包放进 `<profile>/node_modules/`，再把包名加进 `<profile>/package.json` 的
`dsh.profile.bundles`——`bundles` 是唯一开关，`dependencies` 里没有也能加载。

装完需要重启 DSH Web（`dsh web`）才会加载新 bundle。之后：

- 设置页出现 `Cloudflare` 分节（连接状态、client_id、回调地址、权限范围）；
- 模型侧多出 9 个 `cloudflare_*` 工具。

## 第一次连接

**默认不需要填任何东西**：插件自带一个内置 `client_id`，首次加载时用 AES-256-GCM 加密写进
凭据库（`vault.json` 里看不到明文），设置页里只显示 `214b…cb06` 这样的打码值加一个「内置」标签。
装完直接点 **授权登录** 就能走完同意页。

内置 client 是 **private** 的，只有它所属 Cloudflare 账号的成员能授权。用别人的账号时，
自己注册一个再覆盖（约 5 分钟，只需一次）：

1. Cloudflare Dashboard → **Manage Account** → **OAuth clients** → 新建；
2. Response type = `code`，grant = `authorization_code`（想自动续期再加 `refresh_token`），
   token 认证 = **none**（PKCE）；
3. 回调地址逐字填设置页里显示的那个 URL，默认是
   `http://127.0.0.1:3080/plugins/cloudflare/callback`
   （端口变了就要改，Cloudflare 逐字符比对）；
4. 设置 → Cloudflare → 高级 → **授权应用**，填自己的 `client_id`，保存（留空 = 继续用内置）；
5. 点 **授权登录**，选账号、勾权限，完成。

**不需要再手动复制授权链接**：按钮本身就是一个 `href="/plugins/cloudflare/start"` 的普通链接，
点击即跳转（真实用户手势，不会被弹窗拦截）；从同意页切回来时设置页会自动刷新状态。

授权成功后状态变「已连接」，工具立刻可用，且**令牌是持久的**：access token、refresh token、
授权范围、账号列表都用 AES-256-GCM 加密写在 `~/.dsh/cloudflare/vault.json`（主密钥单独在
`master.key`），DSH 重启后仍然有效；token 到期前会自动用 refresh token 续期。只有这三种情况会失效：
你在设置页点「登出」、你在 Cloudflare 后台撤销了授权、或 refresh token 被 Cloudflare 拒绝。

## 常用命令

```bash
# 本地体检：不联网、不打印令牌
node scripts/doctor.js
node scripts/doctor.js --json

# 换凭据库目录（默认 ~/.dsh/cloudflare）
export CLOUDFLARE_PLUGIN_DATA_DIR=/some/dir
```

## 工具

| 工具 | 作用 |
| --- | --- |
| `cloudflare_auth_status` | 连接状态、账号、授权范围、能力清单、凭据库位置 |
| `cloudflare_auth_setup` | 保存公开的 `client_id` / 回调地址 / scope（**不收** token 与 secret） |
| `cloudflare_auth_start` | 生成一次性 state + PKCE，返回授权链接 |
| `cloudflare_auth_logout` | 尽量撤销并删除本地令牌（`all: true` 清全部身份） |
| `cloudflare_accounts` | 可见账号与 id |
| `cloudflare_zones` | zone 列表，可按名字过滤 |
| `cloudflare_zone` | 单个 zone 详情（id 或名字） |
| `cloudflare_dns_records` | 某 zone 的 DNS 记录，可按 type/name 过滤 |
| `cloudflare_capabilities` | 把授权范围翻译成「能做什么」 |

所有工具返回同一个信封：`{ ok, code, text, data, status, rateLimit }`。失败不抛异常，`code` 用来区分 `E_NOT_CONFIGURED` / `E_NOT_CONNECTED` / `E_INVALID_TOKEN` / `E_PERMISSION` / `E_RATE_LIMITED` 等。

## 安全边界

- 令牌只在宿主进程里存在，浏览器拿不到，工具返回里也没有；
- 界面只走 PKCE，不存 `client_secret`；`client_id` 也只能从设置页表单录入，因为工具参数会进对话记录和模型上下文；
- 界面只显示 `client_id` 打码值（`abcd…wxyz`）与账号名；
- 主密钥与密文分开存放；密钥错了插件照常加载，`/status` 会说明原因而不是崩溃。
- 每个接口都有方法白名单：状态变更只接受 `POST`，用 `<img src>` 或链接触发的一律 405；
- 带请求体的接口强制 `content-type: application/json`，浏览器「简单请求」形态的跨站提交被 415 挡掉；
- 非 GET 请求校验 `Origin` 与 `Sec-Fetch-Site`，跨站写一律 403；
- `Host` 头必须是字面量 IP、`localhost` 或显式白名单，域名形式的 rebinding 攻击返回 421；
  用反向代理/自定义域名访问时，把域名加进插件配置的 `allowedHosts` 或环境变量
  `CLOUDFLARE_PLUGIN_ALLOWED_HOSTS`（逗号分隔）。

## HTTP 接口（设置页与工具共用）

```
GET  /plugins/cloudflare/status       连接状态（无敏感字段）
GET  /plugins/cloudflare/bootstrap    状态 + 能力 + 回调地址（一次拉全）
POST /plugins/cloudflare/config       保存 client_id / secret / 回调 / scope
GET  /plugins/cloudflare/start        302 跳到 Cloudflare 授权页
POST /plugins/cloudflare/start        返回授权 URL（GET 则直接 302 跳转）
GET  /plugins/cloudflare/callback     换码、落盘、渲染结果页
POST /plugins/cloudflare/logout       撤销并删除令牌
GET  /plugins/cloudflare/accounts     账号
GET  /plugins/cloudflare/zones        zone
GET  /plugins/cloudflare/scopes       Cloudflare 公开的 scope 目录
GET  /plugins/cloudflare/preferences  默认账号 / 写入白名单 / 只读
POST /plugins/cloudflare/preferences  改上面的偏好
```

`/callback` 要求 `state` 同时匹配内存里的 pending 记录与 `/start` 种下的 HttpOnly cookie，挡住「别人把浏览器接到他的 Cloudflare 账号」这类 login CSRF。

## 排错

| 现象 | 原因 / 处理 |
| --- | --- |
| 同意页报 `invalid_request` + redirect_uri | 回调地址与 client 注册值不一致；换端口后要同步改两边 |
| 回调页提示 state 无效/已用 | 授权链接超过 10 分钟或点过两次；重新点「连接 Cloudflare」 |
| 同意页看不到账号 | 管理员在 Manage Account → Members → Settings 关了 OAuth 授权 |
| `E_PERMISSION` | 授权时少勾了对应权限；重新授权并补上 |
| 换机器后状态变「令牌不可用」 | 主密钥丢了，重新授权即可 |

## 状态

已实现：OAuth 授权 + 凭据库 + 9 个只读工具 + 设置页。
未实现（见 DESIGN.md 分期）：DNS 写、缓存清理、Workers/KV/R2/D1、API Token 降级通道。

## 许可证

本项目基于 **MIT 协议**开源，全文见 [LICENSE](./LICENSE)。

简单说：你可以自由使用、修改、分发、商用这份代码，包括闭源集成；唯一要求是保留版权声明与许可证原文。软件按「现状」提供，不附带任何担保。

```
MIT License · Copyright (c) 2026 MFCJ45681
```
