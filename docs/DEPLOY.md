# 部署指南

## 1. 源码托管到 GitHub

本仓库无第三方运行时依赖，直接推送即可。

```bash
cd uptime-pulse
git init
git add .
git commit -m "UptimePulse: code-driven config + status page"
git remote add origin https://github.com/<你的账号>/uptime-pulse.git
git branch -M main
git push -u origin main
```

## 2. 部署到 Cloudflare Workers

### 2.1 准备 KV 命名空间

```bash
npx wrangler@4 kv namespace create UPTIME_KV
```

将返回的 `id` 填入 `wrangler.toml` 的 `[[kv_namespaces]].id`。KV 仅存历史、事件状态与探针上报，不存监控配置。

### 2.2 配置监控项（改代码）

编辑 `src/config.mjs` 的 `MONITORS` 数组：新增/删除对象、设置 `name`、`url`、`type`、`enabled` 与检测参数。每个目标独立检测与告警。字段说明见 `docs/CONFIG.md`。

部署前请至少确认：

- `id` 唯一（或省略由 url+name 派生）
- `url` 是公网 http(s) 地址，不是内网地址
- 若使用国内探针，`probes` 中的 `external.id` 与探针 `PROBE_ID` 一致

### 2.3 配置告警变量（Dashboard）

进入 Cloudflare Dashboard → Workers & Pages → `uptime-pulse` → Settings → Variables and Secrets。

| 名称 | 类型 | 说明 |
|---|---|---|
| `ALERT_WEBHOOK_ENABLED` | 变量 | `true`/`false`；不填则"有地址就开启" |
| `ALERT_WEBHOOK_URL` | Secret 或变量 | Webhook 地址（兼容旧 `WEBHOOK_URL`） |
| `ALERT_EMAIL_ENABLED` | 变量 | `true`/`false`；不填则"邮件传输就绪即开启" |
| `ALERT_EMAIL_TO` | 变量 | 收件人（兼容旧 `EMAIL_TO`） |
| `RESEND_API_KEY` | Secret | 邮件 API 密钥（需要邮件告警时） |
| `EMAIL_FROM` | 变量 | 已验证的发件地址 |
| `ALERT_SIGNING_SECRET` | Secret | Webhook HMAC 签名密钥 |
| `PROBE_TOKEN` | Secret | 探针回传令牌，与国内探针一致 |
| `PROBE_REGION` | 变量 | 本实例线路标识，如 `cf-sin`、`cf-fra` |

> 只读版已移除 `ADMIN_TOKEN`，无需配置；即便配置也会被忽略。

> **关键**：`wrangler deploy` 默认会清空 Dashboard 上未在配置中声明的变量。本仓库部署命令固定带 `--keep-vars`，请勿移除——否则告警变量会被清空。

### 2.4 部署

手动：

```bash
npx wrangler@4 deploy --keep-vars
```

或通过 GitHub Actions：仓库 Settings → Secrets and variables → Actions 添加 `CLOUDFLARE_API_TOKEN` 与 `CLOUDFLARE_ACCOUNT_ID`，推送到 `main` 自动部署。Cron 每分钟触发一次检测。

### 2.5 修改监控目标与告警

- 改监控项：编辑 `src/config.mjs` → 提交推送 → 自动重新部署。
- 改告警地址/开关：在 Dashboard 改变量即可，无需改代码或重新部署（新隔离实例立即按新变量运行）。

### 2.6 验证部署

```bash
curl https://uptime-pulse.<你的账号>.workers.dev/
curl https://uptime-pulse.<你的账号>.workers.dev/api/status
```

确认：页面为浅色风格、顶部显示"系统一切正常"（或"部分服务异常"）、分组卡片显示 `N/N 在线`、每个监控项有状态条与响应时间曲线；状态接口返回 `MONITORS` 中配置的监控项及 `history`；`POST /api/monitors` 返回 `405`。

## 3. 部署国内探针

Cloudflare Workers 无法从中国大陆出口发起请求，国内线路由此探针实现，运行在中国大陆网络环境中。

```bash
export WORKER_URL=https://uptime-pulse.<你的账号>.workers.dev
export PROBE_TOKEN=<与 Worker 一致的 PROBE_TOKEN>
export PROBE_ID=cn-sh-1
export PROBE_REGION=cn-shanghai
export INTERVAL_SEC=60
node scripts/probe-cn/index.mjs
```

用 `pm2`、`systemd` 或云函数保持常驻。探针 ID 必须与 `src/config.mjs` 中 `external` 探针的 `id` 一致。建议部署 2 个不同地区的探针以获得真正的多线路覆盖。

## 4. 告警接收端验签

若配置了 `ALERT_SIGNING_SECRET`，每个 Webhook 请求携带：

```
X-UptimePulse-Signature: sha256=<hex HMAC-SHA256>
```

签名是对完整请求体字节计算的 HMAC-SHA256。接收方应验签后再处理 JSON，并拒绝时间戳过旧的事件。

## 5. 升级

无需数据库迁移：历史与事件数据按稳定 ID 存入 KV。修改 `src/config.mjs` 后，新增目标自动开始检测；移除的目标不再展示与接收探针数据（旧历史记录保留在 KV 中，不影响运行）。若修改了 `id` 或 `url+name`，会被视为新目标并重新开始累计历史。
