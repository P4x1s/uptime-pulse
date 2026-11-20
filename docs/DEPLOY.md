# 部署指南

## 1. 源码托管到 GitHub

本仓库无第三方运行时依赖，直接推送即可。

```bash
cd uptime-pulse
git init
git add .
git commit -m "UptimePulse read-only"
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

### 2.2 配置后台变量（唯一的配置入口）

进入 Cloudflare Dashboard → Workers & Pages → `uptime-pulse` → Settings → Variables and Secrets。

**必填：`MONITOR_TARGETS`（变量，JSON）** —— 监控目标列表，服务端据此生成监控项：

```json
[
  {"id":"site-a","name":"官网","url":"https://example.com","failureThreshold":3,
   "probes":[{"id":"edge-main","type":"edge","region":"cf-edge"},
             {"id":"cn-sh-1","type":"external","region":"cn-shanghai"}]}
]
```

其余变量：

| 名称 | 类型 | 说明 |
|---|---|---|
| `MONITOR_TARGETS` | 变量 | **必填**，监控目标 JSON 列表 |
| `PROBE_TOKEN` | Secret | 探针回传令牌，与国内探针一致 |
| `ALERT_SIGNING_SECRET` | Secret | Webhook HMAC 签名密钥 |
| `WEBHOOK_URL` | Secret 或变量 | 全局告警 Webhook（可选） |
| `PROBE_REGION` | 变量 | 本实例线路标识，如 `cf-sin`、`cf-fra` |
| `RESEND_API_KEY` | Secret | 邮件 API 密钥（需要邮件告警时） |
| `EMAIL_FROM` | 变量 | 发件地址，需在 Resend 验证域名 |

> 只读版已移除 `ADMIN_TOKEN`，无需配置；即便配置也会被忽略。

> **关键**：`wrangler deploy` 默认会清空 Dashboard 上未在配置中声明的变量。本仓库的部署命令固定带 `--keep-vars`，请勿移除——否则 `MONITOR_TARGETS` 等会被清空。

### 2.3 部署

手动：

```bash
npx wrangler@4 deploy --keep-vars
```

或通过 GitHub Actions：仓库 Settings → Secrets and variables → Actions 添加 `CLOUDFLARE_API_TOKEN` 与 `CLOUDFLARE_ACCOUNT_ID`，推送到 `main` 自动部署。Cron 每分钟触发一次检测。

### 2.4 修改监控目标

只需在 Dashboard 编辑 `MONITOR_TARGETS` 变量，**无需改代码或重新部署**。服务端按变量原始字符串缓存解析结果，变量一变即重新生成监控列表；Workers 滚动更新隔离实例后（通常数十秒内）新配置对检测与展示全面生效。

### 2.5 验证部署

```bash
curl https://uptime-pulse.<你的账号>.workers.dev/
curl https://uptime-pulse.<你的账号>.workers.dev/api/status
```

确认：页面标注"只读"、状态接口返回 `MONITOR_TARGETS` 中配置的监控项；`POST /api/monitors` 返回 `405`。

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

用 `pm2`、`systemd` 或云函数保持常驻。探针 ID 必须与 `MONITOR_TARGETS` 中 `external` 探针的 `id` 一致；配置示例见第 2.2 节。建议部署 2 个不同地区的探针以获得真正的多线路覆盖。

## 4. 告警接收端验签

若配置了 `ALERT_SIGNING_SECRET`，每个 Webhook 请求携带：

```
X-UptimePulse-Signature: sha256=<hex HMAC-SHA256>
```

签名是对完整请求体字节计算的 HMAC-SHA256。接收方应验签后再处理 JSON，并拒绝时间戳过旧的事件。

## 5. 升级

无需数据库迁移：监控配置在后台变量中，历史/事件数据按稳定 ID 存入 KV。修改 `MONITOR_TARGETS` 后，新增目标自动开始检测；移除的目标不再展示与接收探针数据（旧历史记录保留在 KV 中，不影响运行）。
