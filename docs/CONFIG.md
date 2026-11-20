# 配置说明（必读）

本版本有两处配置入口，职责不同：

| 配置内容 | 在哪里改 | 生效方式 |
|---|---|---|
| **监控项**（网站/服务列表、名称、地址、类型、启用状态、检测参数） | 源码 `src/config.mjs` 的 `MONITORS` 数组 | 改完重新部署 Worker（推送 main 触发 Actions 自动部署） |
| **告警地址与开关**（Webhook / 邮件） | Cloudflare Dashboard → Worker → Variables and Secrets（环境变量） | 变量更新后新隔离实例立即生效，无需改代码 |

> 配置写接口已全部移除，公开页面无任何新增/编辑/删除入口。任何访问者都无法修改监控配置。

## 1. 需要修改的文件

| 文件 | 作用 | 什么时候改 |
|---|---|---|
| `src/config.mjs` | **监控项主配置**；`MONITORS` 数组定义所有目标；`resolveAlertConfig()` 读取告警变量 | 新增/删除/调整监控项时改这里 |
| `src/index.mjs` | 完整版 Worker 入口；多线路聚合、探针回传、告警派发 | 一般无需改 |
| `src/demo.mjs` | 核心库与只读状态页 UI（顶部徽章、分组卡片、状态条、折线图） | 一般无需改 |
| `wrangler.toml` | KV / Cron / 变量注释 | 仅新增 KV 或改调度时 |
| `docs/CONFIG.md` | 本说明 | 配置规则变更时 |
| `tests/*.test.mjs` | 30 项自动化测试 | 改配置结构时同步补测试 |

## 2. 监控项配置（`src/config.mjs`）

每一项是一个对象，示例：

```js
{
  id: 'my-blog',                       // 唯一标识；省略时由 url+name 稳定派生
  name: 'My Blog',                     // 展示名称
  url: 'https://www.example.com',      // 检测地址（仅 http/https）
  type: 'website',                     // website | api | service（分类标签）
  group: 'Public',                     // 分组名，状态页按分组渲染卡片
  enabled: true,                       // false = 跳过检测且不在页面展示
  method: 'GET',                       // GET/HEAD/POST/PUT/PATCH/DELETE/OPTIONS
  expectedStatus: 200,                 // 单期望状态码（未填 expectedCodes 时生效）
  expectedCodes: [200, 201],           // [可选] 多个可接受状态码，任一命中即正常，优先于 expectedStatus
  responseKeyword: '"ok":true',        // [可选] 响应体必须包含的关键字（只读前 64KB）
  responseForbiddenKeyword: 'error',   // [可选] 响应体不得包含的关键字
  headers: { 'X-Api-Key': 'xxx' },     // [可选] 自定义请求头（Host 等危险逐跳头自动过滤，最多 20 个）
  body: '{"ping":1}',                  // [可选] 自定义请求体（GET/HEAD 忽略，最长 4096）
  retries: 1,                          // [可选] 瞬时网络故障重试次数 0-3，指数退避；默认 0
  tooltip: '首页健康检查',             // [可选] 状态页鼠标悬停提示
  statusPageLink: 'https://...',       // [可选] 状态页点击跳转地址（仅 http(s)，默认跳监控 url）
  hideLatencyChart: false,             // [可选] true=隐藏该项响应时间曲线
  timeoutMs: 5000,                     // 单次超时，1000-30000
  intervalSec: 60,                     // 检测间隔，>=60 秒
  failureThreshold: 3,                 // 连续失败几次才告警，1-20
  alertCooldownSec: 300,               // 同一事件告警冷却秒数
  aggregate: 'any',                    // any=任一线路成功即正常；all=全部成功才正常
  probes: [{ id: 'edge-main', type: 'edge', region: 'cf-edge' }],
}
```

字段约束：

- **成功判定**：状态码落入 `expectedCodes`（未填则用 `[expectedStatus]`），**且**响应体满足 `responseKeyword`（必须包含）与 `responseForbiddenKeyword`（不得包含）时才算正常。关键字校验最多读取响应体前 64KB，避免大响应拖慢 Worker。
- **重试策略**：仅超时 / DNS / TLS / 网络类瞬时故障按 `retries` 重试（120ms 起指数退避，上限 400ms）；明确的 HTTP 状态码或关键字不匹配不重试。`ProbeResult.attempts` 记录实际尝试次数。
- `method` 支持 `GET/HEAD/POST/PUT/PATCH/DELETE/OPTIONS`；`type` 仅 `website` / `api` / `service`；其余非法值回退默认值。
- 自定义 `headers` 仅接受字符串/数字/布尔标量，自动过滤 `Host`、`Content-Length`、`Connection` 等逐跳/危险头，最多 20 个、单值 512 字符。
- `probes[].type`：`edge`（Cloudflare 边缘即时检测）或 `external`（国内自托管探针回传）。省略 `probes` 时默认单条 edge 线路。**edge 与探针使用同一套判定逻辑**（多状态码 + 关键字 + 重试），结果一致。
- `external` 探针的 `id` 必须与探针进程 `PROBE_ID` 一致，否则任务领取不到、回传会被拒绝（404）。探针任务接口会下发上述检测字段，且仅含非敏感字段（不含告警邮箱/Webhook 地址）。
- `enabled: false` 的目标不检测、不展示；探针回传也只接受当前配置中存在的 ID。
- 所有目标仍会经过 SSRF 校验：仅 http(s)、拒绝凭据、拒绝混淆 IP / 内网域名、DNS 解析后拒绝私网地址、不跟随重定向。
- Cloudflare Workers 的 `fetch` 只能做 HTTP(S) 请求，`service` 类型表示通过 HTTP 健康检查端点监控服务，**不是**原始 TCP 端口探测。

新增/删除/调整：直接编辑数组中的对象，保存后提交并重新部署。每个目标独立调度、独立历史、独立告警状态机——某个服务故障不会误报其他服务。

## 3. 告警变量（Dashboard 设置，不写死在代码里）

| 变量名 | 类型 | 默认行为 | 说明 |
|---|---|---|---|
| `ALERT_WEBHOOK_ENABLED` | 变量 | 未设置时，填了地址即开启 | `true`/`false`（也接受 1/0、yes/no、on/off）；`false` 强制关闭 Webhook |
| `ALERT_WEBHOOK_URL` | 变量（不要选 Secret） | 空=不发送 | Webhook 接收地址（兼容旧变量 `WEBHOOK_URL`，新变量优先）；Server酱/Turbo 风格 `.send` 或 URL 带 `text`/`title`/`desp` 时，预设文案会被提取到 JSON body 的 `title`/`desp` 中，普通 Webhook 则发送完整 JSON 告警对象 |
| `ALERT_FAILURE_THRESHOLD` | 变量 | 未设置时沿用监控项 `failureThreshold`（默认 3） | **设为 1 = 检测到宕机/无法联通立即推送**（推荐）；1-20，对所有监控项生效，优先级高于单项配置 |
| `ALERT_EMAIL_ENABLED` | 变量 | 未设置时，邮件传输就绪即开启 | `false` 强制关闭邮件 |
| `ALERT_EMAIL_TO` | 变量 | 空=使用监控项上的 `emailTo` | 全局收件人（兼容旧变量 `EMAIL_TO`，新变量优先） |
| `RESEND_API_KEY` | 变量（不要选 Secret） | 空=邮件不可用 | Resend API 密钥 |
| `EMAIL_FROM` | 变量 | 空=邮件不可用 | 已验证的发件地址 |
| `ALERT_SIGNING_SECRET` | 变量（不要选 Secret） | 空=不签名 | Webhook HMAC-SHA256 签名密钥 |
| `PROBE_TOKEN` | 变量（不要选 Secret） | 空=探针接口拒绝 | 探针任务领取与回传令牌 |
| `PROBE_REGION` | 变量 | `cf-edge` | 本实例线路标识 |

规则：

- 通知地址与开关**均从环境变量读取**，代码中没有硬编码的收件人或 Webhook 地址。
- **所有 Cloudflare Worker 变量都作为普通变量（plain_text）填写，不要选 Secret**：当前线上 `ALERT_WEBHOOK_ENABLED`、`ALERT_WEBHOOK_URL`、`ALERT_FAILURE_THRESHOLD`、`ALERT_EMAIL_ENABLED` 均已从 Secret 转为普通变量，Dashboard 中可直接查看和修改。Webhook URL 含访问 token，也会明文显示，请控制 Dashboard 访问权限。GitHub Actions 的 `CLOUDFLARE_API_TOKEN` 是仓库 Secret，与此互不相关。
- **宕机立即推送**：设 `ALERT_FAILURE_THRESHOLD=1` 后，某目标第一次检测失败（超时、DNS/TLS/网络错误或非期望 HTTP 状态）即推送告警，无需等待连续多次；恢复后自动发送 recovered。同错误类别 + 冷却期内去重，避免告警风暴。
- 未设置该变量时，沿用每个监控项自己的 `failureThreshold`（默认 3），行为与旧版一致。
- 单项监控配置可可选地写 `webhookUrl` / `emailTo` 覆盖全局地址；写 `alertEnabled: false` 可关闭该项告警。
- 若配置了 `ALERT_SIGNING_SECRET`，Webhook 请求头 `X-UptimePulse-Signature: sha256=<hex>`，接收方应验签。
- **误报排查**：检测引擎出于防 SSRF 不跟随重定向。若站点未登录返回 `307` 跳登录页，或根路径（如 ntfy）返回 `401`，把该监控项的 `expectedStatus` 设为 `307`/`401` 即视为正常；否则会一直判故障。此项只影响健康判定，不影响告警通道。

### ntfy / Server酱 Webhook 示例（本次线上采用）

把带预设文案的完整 URL 直接填进 `ALERT_WEBHOOK_URL` 即可，查询参数在请求 URL 中原样保留，同时服务端会自动转换成接收端真正读取的 JSON body：

```
ALERT_WEBHOOK_ENABLED=true
ALERT_WEBHOOK_URL=https://ntfy.example.com/<your-token>.send?text=【服务监测】&desp=监测服务出现故障！
ALERT_FAILURE_THRESHOLD=1
ALERT_EMAIL_ENABLED=false
```

告警触发时：

- **Server酱 Turbo / `.send` 端点**：POST `{"title":"【服务监测】","desp":"监测服务出现故障！\n\n<故障详情>"}`。实测该端点忽略 query，只读取 body 中的 `title`/`desp`，因此预设文案与故障详情都会真正送达；恢复通知的标题会自动加上「已恢复」。
- **标准 Webhook / ntfy 原生端点**：POST 完整 JSON 对象（`type`、`monitor`、`result`、`state`、`timestamp`）。

如果配置了 `ALERT_SIGNING_SECRET`，签名覆盖实际发送的 JSON body。

## 4. 状态页 UI

在截图风格浅色极简基础上升级，信息层级与交互更完整：

- 顶栏：品牌名 + `◐ 主题`（跟随系统 / 浅色 / 深色 三态切换并记忆）+ `↻ 刷新`（手动立即拉取）。
- 顶部：绿色对勾徽章 + "系统一切正常" + "最后更新于: … (N 秒前)"；任一目标异常时切换为红色"部分服务异常"。
- **统计摘要**：`N/N 服务在线` + `24h 可用率`（全部监控项均值）。
- 中央卡片：分组标题（🌐 分组名）+ `N/N 在线` + 可折叠箭头。
- 每个监控项：
  - 状态图标 + 名称（支持 `tooltip` 悬停提示、`statusPageLink` 跳转）+ `正常/故障` 状态标签 + `总可用率: xx.x%`
  - 第二行元信息：`24h 可用率`、当前 `延迟 xxms`、连续失败次数
  - 历史状态条（绿=正常、红=故障、黄=耗时异常）
  - `响应时间(ms)` 折线图（Y 轴刻度 + X 轴小时标签，`hideLatencyChart: true` 可隐藏）
  - **区间切换**：`24小时` / `7天` / `全部`，同时影响状态条与折线图
- **最近故障事件**区：按时间倒序列出事件的监控项、错误类别、开始时间与持续时长（恢复后标注"已恢复"）。
- 主题：CSS 变量驱动，`prefers-color-scheme` 跟随系统，`data-theme` 手动覆盖，写入 `localStorage` 记忆。
- 前端零 `innerHTML` 用户数据、严格 CSP、30 秒自动刷新，不提供任何配置修改交互。

### `GET /api/status` 字段

在原有字段基础上新增（均为只读）：

| 字段 | 说明 |
|---|---|
| `type` / `group` | 监控项类型与分组 |
| `history` | 最近 120 个数据点（`checkedAt`/`ok`/`latencyMs`/`status`），供状态条与折线图渲染 |
| `uptime24h` / `samples24h` | 最近 24 小时可用率与样本数 |
| `latencyMs` | 当前最近一次检测的耗时 |
| `errorClass` | 最近一次错误类别（status/keyword/timeout/dns/tls/network） |
| `tooltip` / `statusPageLink` / `hideLatencyChart` | 展示控制 |
| `events` | 最近 10 条故障事件（每项）；顶层 `events` 为全局最近 20 条 |
| `totalChecks` | 累计检测次数 |
| `summary` | 全局摘要：`total`/`online`/`offline`/`uptime24h` |

事件存储在 KV 的 `events:<monitorId>`（最多保留 30 条）；累计 up/down 计数存储在 `incident:<monitorId>`，兼容旧状态结构。
