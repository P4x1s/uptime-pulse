# UptimePulse

轻量网站 / 服务可用性监控。整个项目只有一个 Worker 文件 `workers.js`，运行在 Cloudflare Workers；支持多线路、Webhook 与邮件告警、失败阈值、告警去重与恢复通知。

> **只读模式**：监控目标在 `workers.js` 顶部的 `MONITORS` 数组中集中维护；告警地址与开关在 Cloudflare 后台变量中配置。公开页面为纯只读展示，**不提供任何新增/编辑/删除监控项的前端入口或接口**。

## 文件结构

```
workers.js          唯一的 Worker 源码：MONITORS 配置 + 检测/告警/状态页全部逻辑
wrangler.toml       Cloudflare 部署配置（KV 绑定、Cron、变量说明）
package.json        仅含 deploy 脚本，无第三方依赖
.dev.vars.example   本地开发变量示例（复制为 .dev.vars 使用，勿提交）
```

## 如何增删监控地址

全部在 `workers.js` 的 `MONITORS` 数组中维护，改完部署即生效（在 Cloudflare Dashboard 编辑器中直接修改后点 Deploy，或本地 `npx wrangler deploy --keep-vars`）：

- **添加**：复制一个 `{ ... }` 对象，改掉 `id` / `name` / `url`
- **删除**：删掉对应的 `{ ... }` 对象（注意保留对象之间的逗号）
- **临时停用**：把该项的 `enabled` 改为 `false`

常用字段：

```js
{
  id: 'my-website',
  name: 'My Personal Website',
  url: 'https://example.com',
  type: 'website',       // website | api | service（分类展示用）
  group: 'Public',
  enabled: true,
  expectedStatus: 200,   // 期望状态码（登录跳转可设 307，受保护路径可设 401）
  timeoutMs: 5000,
  intervalSec: 60,       // 检测间隔（>=60）
  failureThreshold: 3,   // 连续失败 N 次才告警
  aggregate: 'any',      // any=任一线路成功即正常 | all=全部成功才正常
  probes: [{ id: 'edge-main', type: 'edge', region: 'cf-edge' }],
}
```

进阶字段（可选）：`expectedCodes`（多状态码）、`responseKeyword` / `responseForbiddenKeyword`（响应体关键字正反匹配）、`method` / `headers` / `body`（自定义请求）、`retries`（瞬时故障重试 0-3）、`tooltip`、`statusPageLink`、`hideLatencyChart`。完整字段说明见 `workers.js` 内注释。

## 告警通知

告警地址与开关**不写在代码里**，在 Cloudflare Dashboard → Worker → Variables and Secrets 以普通变量（plain_text）配置（完整说明见 `wrangler.toml` 注释）：

| 变量 | 作用 |
|---|---|
| `ALERT_WEBHOOK_ENABLED` / `ALERT_WEBHOOK_URL` | Webhook 开关与地址（兼容 ntfy / Server酱） |
| `ALERT_FAILURE_THRESHOLD` | 全局失败阈值，设 `1` = 检测到故障立即推送 |
| `ALERT_EMAIL_ENABLED` / `ALERT_EMAIL_TO` | 邮件开关与收件人 |
| `RESEND_API_KEY` / `EMAIL_FROM` | 邮件传输（Resend） |
| `ALERT_SIGNING_SECRET` | Webhook HMAC 验签 |
| `PROBE_TOKEN` / `PROBE_REGION` | 国内自托管探针回传 |

## 特性

- 目标独立检测：每个监控项独立调度、独立历史、独立告警状态机
- 多线路：Cloudflare 边缘（国外）+ 自托管探针（国内），判定规则两端一致
- 检测维度（参考 UptimeFlare）：多状态码、关键字正反匹配、自定义请求、瞬时故障重试、稳定错误分类
- 状态页：统计摘要 + 分组卡片 + 状态条 + 延迟折线图，24h/7d/全部区间切换，浅色/深色主题
- 告警：Webhook（HMAC 签名）+ 邮件（Resend），含恢复通知、失败阈值、冷却去重；仅送达成功才写冷却标记，失败自动重试
- 安全：仅探针回传保留令牌、SSRF 防护（含 IPv6 隧道地址）、严格 CSP、零 `innerHTML` 用户渲染、写接口一律 405

## API 摘要（只读）

| 方法 | 路径 | 鉴权 | 说明 |
|---|---|---|---|
| GET | `/` | 无 | 只读状态页 |
| GET | `/app.css`、`/app.js` | 无 | 页面静态资源 |
| GET | `/api/status` | 无 | 只读：状态、可用率、历史数据点、最近异常 |
| GET | `/api/probes/tasks?probeId=` | Probe | 探针领取任务 |
| POST | `/api/ingest` | Probe | 探针回传结果（不可改配置） |

## 部署

1. Cloudflare Dashboard 创建 Worker，粘贴 `workers.js` 全部内容，绑定 KV（变量名 `KV`）与 Cron `* * * * *`。
2. 在 Variables 中以 plain_text 添加告警变量（见上表）。
3. 点击 Deploy 即可；此后增删监控地址直接在编辑器修改 `MONITORS` 数组再 Deploy。

注意：若使用 `wrangler deploy` 命令行部署，必须带 `--keep-vars`，否则会清空 Dashboard 变量。

## 已知边界

- Cloudflare Workers 无法从中国大陆出口发起请求，国内线路需自托管探针。
- Workers 的 `fetch` 只能做 HTTP(S) 请求，`service` 类型指 HTTP 健康检查端点，非端口探测。
- DNS 校验与实际连接之间存在极短 TOCTOU 时间窗；已通过"不跟随重定向 + 禁止 IP 字面量 + 解析后校验"降低风险。
- 告警送达依赖第三方服务，工具保证按策略触发与发送，不保证最终投递。
