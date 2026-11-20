# UptimePulse 架构设计

## 1. 目标与边界

轻量网站可用性监控，源码可托管 GitHub，运行时部署在 Cloudflare Workers。配置自定义监控项，从国内外多线路定期检测，覆盖 HTTP 状态、响应时间、超时、连续失败；展示实时状态、历史可用率、异常记录；按配置推送邮件 / Webhook 告警，含恢复通知、失败阈值、告警去重。

明确边界：

- Cloudflare Workers 无法指定出站数据中心，也无法从中国大陆出口发起请求。因此"国内线路"必须由部署在中国大陆的自托管探针回传结果，Tools 不宣称纯 CF 方案覆盖国内。
- 告警送达依赖外部服务（邮件 API / 用户 Webhook），工具保证"按策略触发与发送"，不保证第三方最终投递。
- 免费额度下 KV 写入频率受限，默认最小检测间隔 60 秒，避免超出配额。

## 2. 总体架构

```
                    ┌──────────────────────────────┐
   浏览器 ──HTTPS──▶│  Cloudflare Worker (入口)     │
                    │  · 极简 Dashboard (内联 HTML) │
                    │  · 配置 API (Bearer 鉴权)     │
                    │  · Cron 调度器                │
                    └───────┬──────────────┬────────┘
                            │              │
              ┌─────────────▼──┐    ┌──────▼────────────┐
              │ KV 存储         │    │ 检测引擎           │
              │ · monitor:<id>  │    │ · SSRF 校验        │
              │ · history:<id>  │    │ · fetch + 计时     │
              │ · incident:<id> │    │ · 状态/超时判定    │
              └────────────────┘    └──────┬────────────┘
                                           │
                    ┌──────────────────────┼──────────────────┐
                    │                      │                  │
             ┌──────▼──────┐      ┌────────▼────────┐  ┌──────▼──────┐
             │ CF 边缘探针  │      │ 国内自托管探针   │  │ 告警通道     │
             │ (国外线路)   │      │ (Node 无依赖)   │  │ · Webhook   │
             │ 出站走 CF    │      │ HTTP 回传结果   │  │ · Email API │
             └─────────────┘      └─────────────────┘  └─────────────┘
```

## 3. 多线路模型

探针抽象为 `ProbeResult { probeId, region, ok, status, latencyMs, error, checkedAt }`。

- **国外线路**：Cron 在 CF 网络内执行 `fetch`，出站 IP 属 Cloudflare 全球边缘。每次结果记录执行 colo（从 `request.cf.colo` 或环境变量 `PROBE_REGION`）作为线路标识。需要多地独立探测时，部署多个 Worker 实例并设置不同 `PROBE_REGION`。
- **国内线路**：`scripts/probe-cn` 提供无第三方依赖的 Node 探针，部署在大陆 VPS / 云函数。它调用受保护的 `/api/ingest` 上报结果，使用独立 `PROBE_TOKEN`，不暴露配置写权限。
- **聚合规则**：每个监控项可启用多个探针。一次"检查轮次"汇总所有已上报探针结果，按多数 / 任一成功策略（可配 `aggregate`，默认 `any`）判定整体可用性；每个探针的连续失败独立计数，避免单线路故障误判。

## 4. 数据模型（KV）

| Key | 值 | 说明 |
|---|---|---|
| `monitor:<id>` | Monitor 对象 | 监控项配置 |
| `monitor:index` | string[] | 监控项 id 列表 |
| `history:<id>` | CheckRecord[] | 最近 N 条检查记录（默认 500，环形覆盖） |
| `incident:<id>` | IncidentState | 告警状态机（连续失败数、事件 id、最近告警时间） |

Monitor 关键字段：`id, name, url, method, expectedStatus, timeoutMs, intervalSec, failureThreshold, probes[], aggregate, alertChannels[], webhookUrl, emailTo, enabled`。

IncidentState 关键字段：`consecutiveFailures, state(ok/warning/firing), incidentId, lastAlertAt, lastNotifiedStatus, lastErrorSignature`。

## 5. 检测与判定

1. Cron 每分钟触发；遍历 `monitor:index`，按 `intervalSec` 与 `lastRunAt` 判断是否到期。
2. 对到期项执行 SSRF 校验 → `fetch`（`redirect: 'manual'`，记录重定向但不自动跳转）→ 计时 → 记录 status / latency / error。
3. 判定：超时、`status` 不在期望集合、网络错误均为失败；连续失败数达 `failureThreshold` 才进入 firing。
4. 恢复：任一探针成功且此前 firing → 发送恢复通知，重置计数。

## 6. 告警策略

- **失败阈值**：`consecutiveFailures >= failureThreshold` 才触发，避免抖动误报。
- **去重**：同一 incident 内只发一次"故障"通知；错误签名（status + error 类别）变化且超过冷却窗口才补充通知；恢复后 incidentId 更换。
- **冷却**：`alertCooldownSec` 默认 300 秒，同 incident 同签名不重复发送。
- **通道**：
  - Webhook：POST JSON，带 `X-UptimePulse-Signature: sha256=<HMAC>`（密钥 `ALERT_SIGNING_SECRET`），便于接收方验签。
  - 邮件：HTTP 调用 Resend API（`<RESPEND_API_KEY>`），不依赖 SMTP（Workers 无 SMTP）。
- 所有出站告警 URL 必须经过与监控 URL 相同的 SSRF 校验。

## 7. 安全设计

| 威胁 | 措施 |
|---|---|
| 配置接口未授权访问 | Bearer `ADMIN_TOKEN` + 常量时间比较；所有写操作与 ingest 分离鉴权 |
| SSRF（监控 URL / Webhook） | 仅 http(s)；拒绝 IP 字面量、localhost、内网域名后缀、元数据地址；DoH 解析后拒绝私网 IP；禁止跟随重定向 |
| XSS | 前端仅用 `textContent` / DOM API 渲染用户数据，零 `innerHTML` 拼接；CSP 限制脚本来源 |
| 告警签名伪造 | HMAC-SHA256，接收方可验签 |
| 敏感信息泄漏 | 密钥仅存 Worker Secret；前端不返回任何密钥；错误响应不回显请求体 |
| 逻辑漏洞（重复告警） | 状态机 + incidentId + 冷却窗口，单测覆盖 |

## 8. 交付阶段

- **阶段 A（demo）**：单文件 Worker，配置 CRUD + 检测 + Webhook 告警 + 极简页面，本地 dev server 跑通核心链路。
- **阶段 B（功能丰富）**：模块化、邮件通道、国内探针、统计与异常记录、完整鉴权、GitHub Actions、文档。
- **阶段 C（安全测试）**：自动化用例覆盖 SSRF / XSS / 鉴权 / 逻辑漏洞，输出报告并修复。
