# UptimePulse 架构设计

## 1. 目标与边界

轻量网站 / 服务可用性监控，源码可托管 GitHub，运行时部署在 Cloudflare Workers。监控目标在源码 `src/config.mjs` 的 `MONITORS` 数组中集中维护，服务端读取生成监控列表；告警地址与开关由 Cloudflare 后台变量下发。从国内外多线路定期检测，覆盖 HTTP 状态、响应时间、超时、连续失败；前端按截图的浅色风格只读展示状态、可用率、历史状态条与响应时间曲线；按配置推送邮件 / Webhook 告警。

**只读原则**：公开页面与 API 不含任何配置写能力，任何访问者都无法新增/编辑/删除监控项。监控项只在源码中维护，告警地址与开关只在 Cloudflare 后台维护。

明确边界：

- Cloudflare Workers 无法指定出站数据中心，也无法从中国大陆出口发起请求。因此"国内线路"必须由部署在中国大陆的自托管探针回传结果，Tools 不宣称纯 CF 方案覆盖国内。
- 告警送达依赖外部服务（邮件 API / 用户 Webhook），工具保证"按策略触发与发送"，不保证第三方最终投递。
- 免费额度下 KV 写入频率受限，默认最小检测间隔 60 秒，避免超出配额。

## 2. 总体架构

```
  管理员 ──改源码──▶ src/config.mjs (MONITORS 数组)
                              │ 服务端读取生成监控列表
                              ▼
                    ┌──────────────────────────────┐
   浏览器 ──HTTPS──▶│  Cloudflare Worker (入口)     │
                    │  · 只读 Dashboard             │
                    │  · 只读 /api/status           │
                    │  · Cron 调度器                │
                    └───────┬──────────────┬────────┘
                            │              │
              ┌─────────────▼──┐    ┌──────▼────────────┐
              │ KV 存储         │    │ 检测引擎           │
              │ · history:<id>  │    │ · SSRF 校验        │
              │ · incident:<id> │    │ · fetch + 计时     │
              │ · probe:<id>    │    │ · 状态/超时判定    │
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

探针抽象为 `ProbeResult { probeId, region, ok, status, latencyMs, error, errorClass, attempts, checkedAt }`。`errorClass` 为稳定错误类别（status/keyword/timeout/dns/tls/network/probe-missing），`attempts` 为实际检测次数（含重试）。

- **国外线路**：Cron 在 CF 网络内执行 `fetch`，出站 IP 属 Cloudflare 全球边缘。每次结果记录执行 colo（从 `request.cf.colo` 或环境变量 `PROBE_REGION`）作为线路标识。需要多地独立探测时，部署多个 Worker 实例并设置不同 `PROBE_REGION`。
- **国内线路**：`scripts/probe-cn` 提供无第三方依赖的 Node 探针，部署在大陆 VPS / 云函数。它调用受保护的 `/api/ingest` 上报结果，使用独立 `PROBE_TOKEN`，不暴露配置写权限。
- **聚合规则**：每个监控项可启用多个探针。一次"检查轮次"汇总所有已上报探针结果，按多数 / 任一成功策略（可配 `aggregate`，默认 `any`）判定整体可用性；每个探针的连续失败独立计数，避免单线路故障误判。

## 4. 配置与数据模型

**监控项配置源（唯一）：`src/config.mjs` 的 `MONITORS` 数组**（不在 KV、不通过 API 写入）。服务端 `parseTargets()` 将数组规范化为监控列表；`id` 省略时由 URL + 名称稳定派生，保证配置调整后历史连续。按配置内容缓存解析结果，变化即失效重解析。**告警地址与开关**独立来自 Cloudflare 后台变量（`ALERT_*`），由 `resolveAlertConfig()` 读取，不写死在代码中。改监控项需重新部署；改告警变量在新隔离实例立即生效。

| Key | 值 | 说明 |
|---|---|---|
| `history:<id>` | CheckRecord[] | 最近 N 条检查记录（默认 500，环形覆盖），含 ok/status/latencyMs/errorClass/attempts |
| `incident:<id>` | IncidentState | 告警状态机（连续失败数、事件 id、最近告警时间）+ 累计 up/down 计数 + 当前故障起点 |
| `events:<id>` | IncidentEvent[] | 最近 30 条故障事件（start/end/durationMs/errorClass/resolved） |
| `probe:<id>:<probeId>` | ProbeResult | 外部探针最近一次上报 |
| `lastrun:<id>` | number | 上次检测时间戳，用于间隔判定 |

Monitor 关键字段：`id, name, url, type, group, enabled, method, expectedStatus, expectedCodes, responseKeyword, responseForbiddenKeyword, headers, body, retries, timeoutMs, intervalSec, failureThreshold, alertCooldownSec, alertEnabled, probes[], aggregate, tooltip, statusPageLink, hideLatencyChart, webhookUrl, emailTo`。每个目标独立调度、独立历史、独立告警状态机。

IncidentState 关键字段：`consecutiveFailures, state(ok/firing), incidentId, lastAlertAt, lastSignature, totalChecks, upChecks, downChecks, outageStart`。累计计数与事件数组兼容旧状态（缺失字段按 0 / 空处理）。

## 5. 检测与判定

1. Cron 每分钟触发；从 `src/config.mjs` 生成监控列表，并行读取 `lastrun:<id>` 判断到期项，到期项并行探测（目标间相互独立）。
2. 探测（与 UptimeFlare 思路一致）：SSRF 校验 → 组装请求（方法/头/体）→ `fetch`（`redirect: 'manual'`，不自动跳转）→ 计时 → 记录 status / latency / error。
3. **成功判定**：status 必须落入 `expectedCodes`（默认 `[expectedStatus]`），且满足 `responseKeyword`（含）/ `responseForbiddenKeyword`（不含）正反匹配；关键字校验只读响应体前 64KB。
4. **重试**：仅 timeout/dns/tls/network 类瞬时故障按 `retries`（0-3）以 120ms 起指数退避重试；明确的 HTTP 状态/关键字不匹配不重试。记录 `attempts`。
5. **错误分类**：动态错误文本归一化为稳定 `errorClass`，供告警签名去重与 UI 展示。
6. **状态机**：连续失败数达 `failureThreshold` 才进入 firing，写入一条未恢复事件；恢复时补写事件的 end/duration 并发送恢复通知，重置计数。

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
| 公开访问者篡改监控配置 | 配置写接口整体移除（一律 405）；前端无增删改入口；监控项只在源码维护，需部署权限 |
| 探针越权 | 仅 `/api/probes/tasks` 与 `/api/ingest` 保留 `PROBE_TOKEN` 鉴权；ingest 只接受当前配置中存在的监控项 ID |
| SSRF（监控 URL / Webhook） | 仅 http(s)；拒绝 IP 字面量、localhost、内网域名后缀、元数据地址；DoH 解析后拒绝私网 IP；禁止跟随重定向（代码配置与环境变量同样校验） |
| XSS | 前端仅用 `textContent` / DOM API 渲染配置数据，零 `innerHTML` 拼接；严格 CSP 禁止内联脚本 |
| 告警签名伪造 | HMAC-SHA256，接收方可验签 |
| 敏感信息泄漏 | 按用户要求，Worker 变量全部以普通变量（plain_text）存放，Dashboard 中可见；前端与状态接口不返回任何密钥或告警邮箱（代价：Dashboard 可见，需控制账号权限） |
| 逻辑漏洞（重复告警） | 状态机 + incidentId + 冷却窗口 + 错误类别归一化，单测覆盖 |

## 8. 交付阶段

- **阶段 A（demo）**：单文件 Worker，检测 + Webhook 告警 + 极简页面，本地 dev server 跑通核心链路。
- **阶段 B（功能丰富）**：模块化、邮件通道、国内探针、统计与异常记录、GitHub Actions、文档。
- **阶段 C（安全测试）**：自动化用例覆盖 SSRF / XSS / 鉴权 / 逻辑漏洞，输出报告并修复。
- **阶段 D（只读改造）**：移除全部配置写接口与前端增删改入口，保留只读展示与告警核心。
- **阶段 E**：配置改为代码内集中维护（`src/config.mjs` 多目标），告警地址/开关改为环境变量驱动；UI 按截图重做为浅色状态页（徽章 + 分组卡片 + 状态条 + 响应时间曲线）。
- **阶段 F（本次）**：参考 UptimeFlare 整体升级——检测层加入多期望状态码、关键字正反匹配、自定义请求、瞬时故障重试与稳定错误分类；数据层加入累计计数与故障事件历史；接口层并行读取、新增 24h 可用率/摘要/事件；UI 加入主题切换、区间切换、状态标签、事件列表与响应式；到期目标并行探测提升性能。核心只读原则与既有 API 保持兼容，45 项测试全绿。
