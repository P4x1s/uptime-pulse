# 部署指南

## 1. 源码托管到 GitHub

本仓库无第三方运行时依赖，直接推送即可。

```bash
cd uptime-pulse
git init
git add .
git commit -m "Initial UptimePulse"
git remote add origin https://github.com/<你的账号>/uptime-pulse.git
git branch -M main
git push -u origin main
```

若沙箱内 `github.com:443` 不可达而 `api.github.com` 可达，可用 REST Git Data API 推送（见项目长期记忆中的 GitHub 上传方案），或先在本地打包为 zip 再通过网页手动上传。

## 2. 部署到 Cloudflare Workers

### 2.1 准备 KV 命名空间

```bash
npx wrangler@4 kv namespace create UPTIME_KV
```

将返回的 `id` 填入 `wrangler.toml` 的 `[[kv_namespaces]].id`。

### 2.2 设置密钥（Dashboard）

进入 Cloudflare Dashboard → Workers & Pages → `uptime-pulse` → Settings → Variables and Secrets，添加：

| 名称 | 类型 | 说明 |
|---|---|---|
| `ADMIN_TOKEN` | Secret | 配置接口 Bearer 令牌，建议 32 字节随机串 |
| `PROBE_TOKEN` | Secret | 探针回传令牌，与 Admin 令牌不同 |
| `ALERT_SIGNING_SECRET` | Secret | Webhook HMAC 签名密钥 |
| `WEBHOOK_URL` | Secret 或变量 | 全局告警 Webhook（可选） |
| `PROBE_REGION` | 变量 | 本实例线路标识，如 `cf-sin`、`cf-fra` |
| `RESEND_API_KEY` | Secret | 邮件 API 密钥（需要邮件告警时） |
| `EMAIL_FROM` | 变量 | 发件地址，需在 Resend 验证域名 |

也可以本地执行 `npx wrangler@4 secret put ADMIN_TOKEN` 等命令写入。

> **关键**：`wrangler deploy` 默认会清空 Dashboard 上未在配置中声明的变量。本仓库的部署命令固定带 `--keep-vars`，请勿移除。

### 2.3 部署

手动：

```bash
npx wrangler@4 deploy --keep-vars
```

或通过 GitHub Actions：在仓库 Settings → Secrets and variables → Actions 添加 `CLOUDFLARE_API_TOKEN` 与 `CLOUDFLARE_ACCOUNT_ID`，之后推送到 `main` 会自动部署（`.github/workflows/deploy.yml`）。Node 版本固定为 22，满足 wrangler v4 要求。

### 2.4 验证部署

部署后必须做端到端确认，不能只看 CI 显示成功：

```bash
curl https://uptime-pulse.<你的账号>.workers.dev/
curl https://uptime-pulse.<你的账号>.workers.dev/api/status
```

若页面能打开且返回 JSON 状态，说明代码与 KV 绑定均正常。若曾经改名或重建 Worker，注意 `workers.dev` 域名会变化。

Cron 触发器已配置为每分钟一次，具体检测间隔由每个监控项的 `intervalSec` 控制。

## 3. 部署国内探针

国内探针需要运行在中国大陆的网络环境中。

```bash
export WORKER_URL=https://uptime-pulse.<你的账号>.workers.dev
export PROBE_TOKEN=<与 Worker 一致的 PROBE_TOKEN>
export PROBE_ID=cn-sh-1
export PROBE_REGION=cn-shanghai
export INTERVAL_SEC=60
node scripts/probe-cn/index.mjs
```

用 `pm2`、`systemd` 或云函数保持常驻。建议同时部署 2 个不同地区的探针，以获得真正的多线路覆盖。

**配置监控项时**，探针 ID 必须与 `PROBE_ID` 一致，且类型选择 `external`。页面"添加监控项"表单中可用逗号分隔填写多个探针 ID。若需更细粒度控制（如 `all` 聚合），直接调用 API：

```bash
curl -X POST https://uptime-pulse.<你的账号>.workers.dev/api/monitors \
  -H "Authorization: Bearer <ADMIN_TOKEN>" \
  -H "Content-Type: application/json" \
  -d '{
    "url":"https://example.com",
    "name":"example",
    "failureThreshold":3,
    "aggregate":"all",
    "probes":[
      {"id":"edge-main","type":"edge","region":"cf-edge"},
      {"id":"cn-sh-1","type":"external","region":"cn-shanghai"}
    ],
    "webhookUrl":"https://your-domain.com/hook",
    "emailTo":"you@example.com"
  }'
```

## 4. 告警接收端验签

若配置了 `ALERT_SIGNING_SECRET`，每个 Webhook 请求会携带：

```
X-UptimePulse-Signature: sha256=<hex HMAC-SHA256>
```

签名内容是对完整请求体字节计算的 HMAC-SHA256。接收方应在校验签名后再处理 JSON，并拒绝时间戳过旧的事件。

## 5. 升级

无需数据库迁移：新增字段通过默认值兼容旧 KV 记录。重新部署后旧监控项仍可用，可在页面中删除后按新格式重建以启用新特性。
