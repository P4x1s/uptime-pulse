# UptimePulse

轻量网站 / 服务可用性监控。源码托管 GitHub，运行时部署在 Cloudflare Workers；支持国内外多线路、邮件与 Webhook 告警、失败阈值、告警去重与恢复通知。

> **只读模式**：监控目标在源码 `src/config.mjs` 的 `MONITORS` 数组中集中维护；告警地址与开关在 Cloudflare 后台变量中配置。公开页面为纯只读展示，**不提供任何新增/编辑/删除监控项的前端入口或接口**。

## 特性

- 代码内集中配置：一个数组管理所有网站与服务，支持名称、地址、类型、启用状态与检测参数
- 目标独立检测：每个监控项独立调度、独立历史、独立告警状态机
- 多线路检测：Cloudflare 边缘线路（国外）+ 自托管探针（国内）
- 检测维度：HTTP 状态、响应时间、超时、连续失败
- 状态页：按截图的浅色风格，顶部徽章 + 分组卡片 + 历史状态条 + 响应时间折线图 + 总可用率
- 告警：Webhook（HMAC 签名）、邮件（Resend），地址与开关均可配置，含恢复通知、失败阈值、冷却去重
- 安全：仅探针回传保留令牌、SSRF 防护、严格 CSP、零 `innerHTML` 用户渲染、写接口全部禁用

## 目录

```
src/config.mjs         监控项集中配置（MONITORS）+ 告警变量解析
src/demo.mjs           核心库（SSRF/检测/告警）+ 截图风格只读页面
src/index.mjs          完整版 Worker（多线路 + 邮件 + 探针回传）
scripts/dev-server.mjs 本地开发服务器（Node，无第三方依赖）
scripts/probe-cn/      国内自托管探针（Node，无第三方依赖）
tests/                 demo / 功能 / 安全 / 配置与 UI 四套测试，共 30 项
docs/CONFIG.md         配置项与变量完整说明（先看这个）
docs/                  架构、部署、安全测试报告
```

## 配置监控目标

编辑 `src/config.mjs` 的 `MONITORS` 数组，然后重新部署：

```js
export const MONITORS = [
  {
    id: 'my-website',
    name: 'My Personal Website',
    url: 'https://example.com',
    type: 'website',       // website | api | service
    group: 'Public',
    enabled: true,
    method: 'GET',
    expectedStatus: 200,
    timeoutMs: 5000,
    intervalSec: 60,
    failureThreshold: 3,
    alertCooldownSec: 300,
    aggregate: 'any',      // any | all
    probes: [{ id: 'edge-main', type: 'edge', region: 'cf-edge' }],
  },
  // 继续添加更多网站或服务……
];
```

新增、删除、修改对象即可；`enabled: false` 可临时停用某项。完整字段说明见 `docs/CONFIG.md`。

告警地址与开关**不要写在代码里**，在 Cloudflare Dashboard 设置：

| 变量 | 作用 |
|---|---|
| `ALERT_WEBHOOK_ENABLED` / `ALERT_WEBHOOK_URL` | Webhook 开关与地址 |
| `ALERT_EMAIL_ENABLED` / `ALERT_EMAIL_TO` | 邮件开关与收件人 |
| `RESEND_API_KEY` / `EMAIL_FROM` | 邮件传输 |
| `ALERT_SIGNING_SECRET` | Webhook 验签 |
| `PROBE_TOKEN` / `PROBE_REGION` | 国内探针 |

## 本地快速开始

要求 Node.js >= 20（本机使用 22）。无需安装依赖。

```bash
# 默认读取 src/config.mjs 的 MONITORS
node scripts/dev-server.mjs --worker=src/index.mjs

# 也可用 MONITORS_JSON 临时覆盖（仅本地调试）
MONITORS_JSON='[{"id":"t","name":"测试","url":"https://example.com"}]' \
  node scripts/dev-server.mjs --worker=src/index.mjs

# 浏览器打开 http://localhost:8787
```

本地模式使用内存 KV，进程退出即丢失数据，仅用于验证。

## 测试

```bash
node --test tests/*.test.mjs
```

30 项测试覆盖核心逻辑、独立检测、配置变更、告警开关、截图风格 UI（含真实执行前端脚本的 DOM 渲染测试）与安全边界。所有外部依赖通过 `env` 注入，离线可跑。

## API 摘要（只读）

| 方法 | 路径 | 鉴权 | 说明 |
|---|---|---|---|
| GET | `/` | 无 | 只读状态页 |
| GET | `/app.css`、`/app.js` | 无 | 页面静态资源 |
| GET | `/api/status` | 无 | 只读：状态、可用率、历史数据点、最近异常 |
| GET | `/api/probes/tasks?probeId=` | Probe | 探针领取任务 |
| POST | `/api/ingest` | Probe | 探针回传结果（不可改配置） |

**已移除**：`POST/PUT/DELETE /api/monitors`、`POST /api/check`、历史查询接口等一切配置写操作，统一返回 `405`。生产环境不再需要 `ADMIN_TOKEN`。

## 安全说明

- 配置写入能力整体移除：公开页面无增删改入口，写接口一律 405。
- 探针回传仅接受当前配置中存在的监控项 ID，已移除的目标不再接收数据。
- 监控 URL 与 Webhook URL 均经过 SSRF 校验：仅 http(s)、拒绝凭据、拒绝混淆 IP 与内网域名、DNS 解析后拒绝私网地址、禁止跟随重定向。
- 告警签名使用归一化错误类别而非原始文本，避免文案波动引发告警风暴。
- 前端使用 DOM API + `textContent` 渲染，严格 CSP，无 `innerHTML` 拼接。
- 详细结果见 `docs/SECURITY-TEST-REPORT.md`。

## 已知边界

- Cloudflare Workers 无法从中国大陆出口发起请求，国内线路必须由自托管探针实现。
- Workers 的 `fetch` 无法做原始 TCP/端口探测；`service` 类型指 HTTP 健康检查端点。
- 修改 `src/config.mjs` 需要重新部署；告警变量修改在新隔离实例生效，可能有数十秒滚动窗口。
- DNS 校验与实际连接之间存在极短 TOCTOU 时间窗，Workers 环境无法完全消除；已通过"不跟随重定向 + 禁止 IP 字面量 + 解析后校验"降低风险。
- 告警送达依赖第三方服务（Resend / 用户 Webhook），工具保证按策略触发与发送，不保证最终投递。
