# UptimePulse

轻量网站可用性监控工具。源码可托管 GitHub，运行时部署在 Cloudflare Workers；支持国内外多线路、邮件与 Webhook 告警、失败阈值、告警去重与恢复通知。界面极简，只保留状态展示与配置功能。

## 特性

- 自定义监控项：URL、方法、期望状态码、超时、间隔、失败阈值、告警通道
- 多线路检测：Cloudflare 边缘线路（国外）+ 自托管探针（国内）
- 检测维度：HTTP 状态、响应时间、超时、连续失败
- 展示：实时状态、各线路结果、历史可用率、最近异常
- 告警：Webhook（HMAC 签名）、邮件（Resend），含恢复通知、失败阈值、冷却去重
- 安全：管理/探针令牌分离、SSRF 防护、CSP、零 `innerHTML` 用户渲染

## 目录

```
src/demo.mjs           阶段 A：单文件 demo（配置 + 检测 + Webhook 告警 + 极简页面）
src/index.mjs          阶段 B：完整版（多线路 + 邮件 + 完整 API）
scripts/dev-server.mjs 本地开发服务器（Node，无第三方依赖）
scripts/probe-cn/      国内自托管探针（Node，无第三方依赖）
tests/                 demo / 功能 / 安全 三套测试，共 21 项
docs/                  架构、部署、安全测试报告
```

## 本地快速开始

要求 Node.js >= 20（本机使用 22）。无需安装依赖。

```bash
# Demo 版本
node scripts/dev-server.mjs --worker=src/demo.mjs
# 浏览器打开 http://localhost:8787
# 默认管理员令牌：demo-admin-token
```

```bash
# 完整版
node scripts/dev-server.mjs --worker=src/index.mjs
```

本地模式使用内存 KV，进程退出即丢失数据，仅用于验证。

## 测试

```bash
node --test tests/*.test.mjs
```

三套测试分别覆盖核心逻辑、完整功能与安全边界。所有外部依赖通过 `env` 注入，离线可跑。

## API 摘要

| 方法 | 路径 | 鉴权 | 说明 |
|---|---|---|---|
| GET | `/` | 无 | 极简状态页 |
| GET | `/api/status` | 无 | 状态、可用率、最近异常 |
| POST | `/api/monitors` | Admin | 创建监控项 |
| PUT | `/api/monitors/:id` | Admin | 更新监控项 |
| DELETE | `/api/monitors/:id` | Admin | 删除监控项及关联数据 |
| GET | `/api/monitors/:id/history` | Admin | 历史记录 |
| POST | `/api/check` | Admin | 立即检测全部启用项 |
| GET | `/api/probes/tasks?probeId=` | Probe | 探针领取任务 |
| POST | `/api/ingest` | Probe | 探针回传结果 |

鉴权头：`Authorization: Bearer <token>`。Admin 与 Probe 令牌权限严格分离。

## 配置要点

- 检测间隔最小 60 秒（符合 Workers 免费额度）。
- 失败阈值 `failureThreshold`：连续失败达到该值才触发告警，避免抖动误报。
- 冷却 `alertCooldownSec`：同一事件、同一错误类别在窗口内不重复告警。
- 聚合 `aggregate`：`any`（默认，任一线路成功即正常）或 `all`（全部线路成功才正常）。
- 邮件需配置 `RESEND_API_KEY` 与 `EMAIL_FROM`；Webhook 建议配置 `ALERT_SIGNING_SECRET` 以便接收方验签。

## 安全说明

- 配置写操作与探针回传使用不同令牌；令牌不匹配时返回 401。
- 监控 URL 与 Webhook URL 均经过 SSRF 校验：仅 http(s)、拒绝凭据、拒绝 IP 字面量与内网域名、DNS 解析后拒绝私网地址、禁止跟随重定向。
- 错误签名使用归一化类别而非原始错误文本，避免文案波动引发告警风暴。
- 前端使用 `textContent` 渲染用户数据，配合严格 CSP。
- 详细结果见 `docs/SECURITY-TEST-REPORT.md`。

## 已知边界

- Cloudflare Workers 无法从中国大陆出口发起请求，国内线路必须由自托管探针实现。
- DNS 校验与实际连接之间存在极短时间窗（DNS rebinding 的 TOCTOU），Workers 环境无法完全消除；已通过"不跟随重定向 + 禁止 IP 字面量 + 解析后校验"将风险降至较低水平。
- 告警送达依赖第三方服务（Resend / 用户 Webhook），工具保证按策略触发与发送，不保证最终投递。
