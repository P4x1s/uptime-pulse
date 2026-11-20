# UptimePulse

轻量网站可用性监控工具。源码可托管 GitHub，运行时部署在 Cloudflare Workers；支持国内外多线路、邮件与 Webhook 告警、失败阈值、告警去重与恢复通知。

> **只读模式**：监控目标统一通过 Cloudflare 后台变量 `MONITOR_TARGETS` 配置，由服务端读取生成监控列表。公开页面为纯只读展示，**不提供任何新增/编辑/删除监控项的前端入口或接口**，任何访问者都无法修改监控配置。

## 特性

- 后台变量驱动：仅管理员可在 Cloudflare Dashboard / GitHub Actions Secrets 修改 `MONITOR_TARGETS`
- 多线路检测：Cloudflare 边缘线路（国外）+ 自托管探针（国内）
- 检测维度：HTTP 状态、响应时间、超时、连续失败
- 展示：实时状态、各线路结果、历史可用率、最近异常（只读）
- 告警：Webhook（HMAC 签名）、邮件（Resend），含恢复通知、失败阈值、冷却去重
- 安全：仅探针回传保留令牌、SSRF 防护、严格 CSP、零 `innerHTML` 用户渲染、写接口全部禁用

## 目录

```
src/demo.mjs           核心库（SSRF/检测/告警/只读页面）+ Demo Worker
src/index.mjs          完整版 Worker（多线路 + 邮件 + 探针回传）
scripts/dev-server.mjs 本地开发服务器（Node，无第三方依赖）
scripts/probe-cn/      国内自托管探针（Node，无第三方依赖）
tests/                 demo / 功能 / 安全 三套测试，共 22 项
docs/                  架构、部署、安全测试报告
```

## 配置监控目标（唯一入口）

在 Cloudflare Dashboard → Worker → Variables and Secrets 中设置变量 `MONITOR_TARGETS`，值为 JSON。支持两种写法：

```json
[
  {
    "id": "site-a",
    "name": "官网首页",
    "url": "https://example.com",
    "method": "GET",
    "expectedStatus": 200,
    "timeoutMs": 5000,
    "intervalSec": 60,
    "failureThreshold": 3,
    "alertCooldownSec": 300,
    "aggregate": "any",
    "probes": [
      { "id": "edge-main", "type": "edge", "region": "cf-edge" },
      { "id": "cn-sh-1", "type": "external", "region": "cn-shanghai" }
    ],
    "webhookUrl": "https://your-domain.com/hook",
    "emailTo": "you@example.com",
    "enabled": true
  }
]
```

- 最简配置只需 `url`；`id` 省略时由 URL 稳定派生（历史数据保持连续）。
- `probes` 省略时默认单条 `edge` 线路；`external` 探针 ID 需与探针的 `PROBE_ID` 一致。
- `aggregate`：`any`（默认，任一线路成功即正常）或 `all`（全部线路成功才正常）。
- **同步生效**：服务端每次读取 `MONITOR_TARGETS`，按原始字符串缓存解析结果；变量一旦更新即重新解析，新隔离实例立即按新列表检测与展示（Workers 变量变更会滚动更新隔离实例，通常数十秒内全部生效）。

## 本地快速开始

要求 Node.js >= 20（本机使用 22）。无需安装依赖。

```bash
# 完整版（推荐）—— 通过环境变量注入后台变量
MONITOR_TARGETS='[{"url":"https://example.com"}]' node scripts/dev-server.mjs --worker=src/index.mjs
# 浏览器打开 http://localhost:8787
```

本地模式使用内存 KV，进程退出即丢失数据，仅用于验证。

## 测试

```bash
node --test tests/*.test.mjs
```

22 项测试覆盖核心逻辑、后台变量驱动、只读接口与安全边界。所有外部依赖通过 `env` 注入，离线可跑。

## API 摘要（只读）

| 方法 | 路径 | 鉴权 | 说明 |
|---|---|---|---|
| GET | `/` | 无 | 只读状态页 |
| GET | `/app.css`、`/app.js` | 无 | 页面静态资源 |
| GET | `/api/status` | 无 | 只读：状态、可用率、最近异常 |
| GET | `/api/probes/tasks?probeId=` | Probe | 探针领取任务 |
| POST | `/api/ingest` | Probe | 探针回传结果（不可改配置） |

**已移除**：`POST/PUT/DELETE /api/monitors`、`POST /api/check`、历史查询接口等一切配置写操作，统一返回 `405`。探针令牌与配置令牌权限严格分离；由于配置改由后台变量管理，生产环境**不再需要 ADMIN_TOKEN**。

## 安全说明

- 配置写入能力被整体移除：公开页面无任何增删改入口，写接口一律 405。
- 探针回传仅接受当前后台变量中存在的监控项 ID，已移除的目标不再接收数据。
- 监控 URL 与 Webhook URL 均经过 SSRF 校验：仅 http(s)、拒绝凭据、拒绝混淆 IP 与内网域名、DNS 解析后拒绝私网地址、禁止跟随重定向。
- 错误签名使用归一化类别而非原始错误文本，避免文案波动引发告警风暴。
- 前端使用 `textContent` 渲染配置数据，配合严格 CSP（禁止内联脚本）。
- 详细结果见 `docs/SECURITY-TEST-REPORT.md`。

## 已知边界

- Cloudflare Workers 无法从中国大陆出口发起请求，国内线路必须由自托管探针实现。
- DNS 校验与实际连接之间存在极短时间窗（DNS rebinding 的 TOCTOU），Workers 环境无法完全消除；已通过"不跟随重定向 + 禁止 IP 字面量 + 解析后校验"将风险降至较低水平。
- 后台变量更新后，Workers 会滚动更新隔离实例；在切换窗口内可能有极短暂的新旧配置并存，最终一致。
- 告警送达依赖第三方服务（Resend / 用户 Webhook），工具保证按策略触发与发送，不保证最终投递。
