/**
 * UptimePulse - 监控项集中配置
 *
 * 【怎么改监控项】
 *   直接编辑下面的 MONITORS 数组：新增一个对象、删除一个对象、或修改某个字段。
 *   改完重新部署 Worker（推送到 GitHub 会触发 Actions 自动部署）即可生效。
 *
 * 【告警地址与开关】
 *   不要写死在代码里。请在 Cloudflare Dashboard → Worker → Variables and Secrets
 *   以普通变量（plain_text）添加，不要选 Secret（用户要求变量值不加密）。
 *   设置 ALERT_WEBHOOK_ENABLED / ALERT_WEBHOOK_URL / ALERT_EMAIL_ENABLED /
 *   ALERT_EMAIL_TO 等变量（完整说明见 docs/CONFIG.md）。
 *
 * 【字段说明】
 *   id               唯一标识（字母数字、_、-）；省略时由 url+name 稳定派生
 *   name             展示名称
 *   url              检测地址（仅 http/https，禁止内网地址）
 *   type             类型标签：website | api | service（分类展示用；检测均为 HTTP(S) 请求）
 *   group            分组名，状态页按分组渲染卡片，默认 "Public"
 *   enabled          false 时跳过检测且不在状态页展示
 *   method           HTTP 方法（GET/HEAD/POST/PUT/PATCH/DELETE/OPTIONS），默认 GET
 *   expectedStatus   期望 HTTP 状态码，默认 200；登录跳转可设 307，受保护根路径可设 401
 *   expectedCodes    期望状态码数组（如 [200, 201]），优先于 expectedStatus；未填则用 expectedStatus
 *   responseKeyword     响应体必须包含的关键字（做成功判定，只读前 64KB）
 *   responseForbiddenKeyword 响应体不得包含的关键字（出现即判故障）
 *   headers          自定义请求头（标量，自动过滤 Host 等危险逐跳头，最多 20 个）
 *   body             自定义请求体字符串（GET/HEAD 忽略，最长 4096）
 *   retries          瞬时网络故障（超时/DNS/TLS/网络）重试次数 0-3，默认 0；指数退避
 *   timeoutMs        单次超时（1000-30000），默认 5000
 *   intervalSec      检测间隔（>=60），默认 60
 *   failureThreshold 连续失败多少次才触发告警（1-20），默认 3
 *   alertCooldownSec 同一事件告警冷却秒数，默认 300
 *   aggregate        多线路聚合：any（任一线路成功即正常）| all（全部成功才正常）
 *   probes           线路数组；edge=CF 边缘即时检测，external=国内自托管探针回传
 *   tooltip          状态页鼠标悬停提示
 *   statusPageLink   状态页点击跳转地址（默认跳监控 url）
 *   hideLatencyChart true 时隐藏该项目的响应时间曲线
 *
 * 判定规则（参考 UptimeFlare）：状态码需在 expectedCodes 内（默认 2xx 语义由 expectedStatus 指定），
 * 且满足 responseKeyword / responseForbiddenKeyword 的正反匹配，才算一次成功检测。
 * 只有超时/DNS/TLS/网络类瞬时故障会按 retries 重试；明确的状态码/关键字不匹配不重试。
 *
 * 注意：Cloudflare Workers 的 fetch 只能做 HTTP(S) 请求，无法发起原始 TCP/端口探测。
 *       "service" 类型指通过 HTTP 健康检查端点监控服务，不是端口连通性探测。
 */

export const MONITORS = [
  {
    id: 'tv',
    name: 'TV',
    url: 'https://tv.588816.xyz/',
    type: 'website',
    group: 'Public',
    enabled: true,
    method: 'GET',
    expectedStatus: 307, // 未登录时跳 /login，307 即视为站点正常（检测不跟随重定向）
    // 进阶可选字段（其余监控项同样支持，按需添加即可）：
    // expectedCodes: [200, 307],          // 多个可接受状态码，优先于 expectedStatus
    // responseKeyword: '"ok"',            // 响应体必须包含
    // responseForbiddenKeyword: 'error',  // 响应体不得包含
    // method: 'GET', headers: { 'X-Api-Key': '...' }, body: '', retries: 1,
    // tooltip: '首页健康检查', statusPageLink: 'https://tv.588816.xyz/', hideLatencyChart: false,
    timeoutMs: 5000,
    intervalSec: 60,
    failureThreshold: 3,
    aggregate: 'any',
    probes: [{ id: 'edge-main', type: 'edge', region: 'cf-edge' }],
  },
  {
    id: 'car',
    name: 'Car',
    url: 'https://car.588816.xyz/',
    type: 'website',
    group: 'Public',
    enabled: true,
    method: 'GET',
    expectedStatus: 200,
    timeoutMs: 5000,
    intervalSec: 60,
    failureThreshold: 3,
    alertCooldownSec: 300,
    aggregate: 'any',
    probes: [{ id: 'edge-main', type: 'edge', region: 'cf-edge' }],
  },
  {
    id: 'news',
    name: 'News',
    url: 'https://news.588816.xyz/',
    type: 'website',
    group: 'Public',
    enabled: true,
    method: 'GET',
    expectedStatus: 200,
    timeoutMs: 5000,
    intervalSec: 60,
    failureThreshold: 2,
    aggregate: 'any',
    probes: [{ id: 'edge-main', type: 'edge', region: 'cf-edge' }],
  },
   {
    id: 'note',
    name: 'Note',
    url: 'https://note.588816.xyz/',
    type: 'website',
    group: 'Public',
    enabled: true,
    method: 'GET',
    expectedStatus: 200,
    timeoutMs: 5000,
    intervalSec: 60,
    failureThreshold: 2,
    aggregate: 'any',
    probes: [{ id: 'edge-main', type: 'edge', region: 'cf-edge' }],
  },
  {
    id: 'res',
    name: 'Res',
    url: 'https://res.588816.xyz/',
    type: 'website',
    group: 'Public',
    enabled: true,
    method: 'GET',
    expectedStatus: 200,
    timeoutMs: 5000,
    intervalSec: 60,
    failureThreshold: 2,
    aggregate: 'any',
    probes: [{ id: 'edge-main', type: 'edge', region: 'cf-edge' }],
  },
  {
    id: 'notify',
    name: 'Notify',
    url: 'https://ntfy.588816.xyz/',
    type: 'website',
    group: 'Public',
    enabled: true,
    method: 'GET',
    expectedStatus: 401, // 根路径受保护，401 即视为服务正常；告警仍走 .send 端点
    timeoutMs: 5000,
    intervalSec: 60,
    failureThreshold: 2,
    aggregate: 'any',
    probes: [{ id: 'edge-main', type: 'edge', region: 'cf-edge' }],
  },
];

/** 解析布尔开关：未设置时按"配置了目标地址就开启"处理，避免只填地址却收不到告警 */
function boolFlag(env, name, fallback) {
  const raw = env[name];
  if (raw === undefined || raw === null || String(raw).trim() === '') return fallback;
  return /^(1|true|yes|on)$/i.test(String(raw).trim());
}
function str(env, ...names) {
  for (const n of names) {
    const v = env[n];
    if (typeof v === 'string' && v.trim()) return v.trim();
  }
  return '';
}

/**
 * 告警配置：地址与开关全部来自环境变量，不在代码中写死。
 * - webhook.url: ALERT_WEBHOOK_URL（兼容旧变量 WEBHOOK_URL）
 * - email.to:   ALERT_EMAIL_TO（兼容旧变量 EMAIL_TO）
 * - 邮件发送还依赖 RESEND_API_KEY 与 EMAIL_FROM。
 */
export function resolveAlertConfig(env = {}) {
  const webhookUrl = str(env, 'ALERT_WEBHOOK_URL', 'WEBHOOK_URL');
  const emailTo = str(env, 'ALERT_EMAIL_TO', 'EMAIL_TO');
  // 邮件传输（API Key + 发件人）就绪即视为通道可用；收件人可来自全局配置或单个监控项的 emailTo。
  // 显式设置 ALERT_EMAIL_ENABLED=false 可关闭整条邮件通道。
  const mailReady = !!(str(env, 'RESEND_API_KEY') && str(env, 'EMAIL_FROM'));
  // 失败阈值：Workers 变量 ALERT_FAILURE_THRESHOLD 优先，未设置时返回 null 表示沿用监控项自身配置。
  // 设为 1 即"检测到故障立即推送"。范围 1-20。
  const thresholdRaw = env.ALERT_FAILURE_THRESHOLD;
  const failureThreshold = (thresholdRaw === undefined || thresholdRaw === null || String(thresholdRaw).trim() === '')
    ? null
    : Math.min(20, Math.max(1, Math.round(Number(thresholdRaw) || 1)));
  return {
    webhook: { enabled: boolFlag(env, 'ALERT_WEBHOOK_ENABLED', !!webhookUrl), url: webhookUrl },
    email: { enabled: boolFlag(env, 'ALERT_EMAIL_ENABLED', mailReady), to: emailTo },
    signingSecret: str(env, 'ALERT_SIGNING_SECRET'),
    mail: { apiKey: str(env, 'RESEND_API_KEY'), from: str(env, 'EMAIL_FROM') },
    failureThreshold,
  };
}

/**
 * 构造 Webhook 请求正文，兼容两类接收端：
 *  1) Server酱 / Turbo / 同类网关（URL 以 .send 结尾，或 query 含 text/title/desp）：
 *     服务端只从 body 读 title/desp，忽略 query。此处读取 URL 中的预设文案作为模板，
 *     并把告警详情附到 desp，返回 { style:'serverchan', body:{title,desp} }。
 *  2) 标准 Webhook / ntfy 原生：返回 { style:'json', body:payload }。
 * 预设文案（如 text=【服务监测】、desp=监测服务出现故障！）始终被保留。
 */
export function buildWebhookBody(url, payload) {
  let u;
  try { u = new URL(url); } catch { return { style: 'json', body: payload }; }
  const isServerChan = /\.send$/i.test(u.pathname) || u.searchParams.has('text')
    || u.searchParams.has('title') || u.searchParams.has('desp');
  const detail = [
    `监控项: ${payload.monitor?.name || payload.monitor?.id || ''}`,
    `目标: ${payload.monitor?.url || ''}`,
    `状态: ${payload.type === 'firing' ? '故障 firing' : '恢复 recovered'}`,
    `HTTP: ${payload.result?.status ?? '-'}`,
    `耗时: ${payload.result?.latencyMs ?? '-'}ms`,
    `线路: ${payload.result?.region || ''}`,
    payload.result?.error ? `错误: ${payload.result.error}` : '',
    `时间: ${payload.timestamp}`,
  ].filter(Boolean).join('\n');
  if (isServerChan) {
    const presetTitle = u.searchParams.get('text') || u.searchParams.get('title') || '【服务监测】';
    const presetDesp = u.searchParams.get('desp') || '监测服务出现故障！';
    const title = payload.type === 'recovered' ? `${presetTitle} 已恢复` : presetTitle;
    const desp = `${presetDesp}\n\n${detail}`;
    return { style: 'serverchan', body: { title, desp } };
  }
  return { style: 'json', body: payload };
}
