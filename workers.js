/* ============================================================================
 * UptimePulse 单文件版 Worker（workers.js）—— 监控地址全部集中在下面 MONITORS 数组
 *
 * 【如何添加监控地址】在 MONITORS 数组里复制一个 { ... } 对象，改掉 id / name / url。
 * 【如何删除监控地址】删掉对应的 { ... } 对象（注意保留对象之间的逗号）。
 * 【临时停用】把该项的 enabled 改为 false，检测与状态页都会跳过它。
 * 【告警通知】地址与开关不写在这里，在 Cloudflare 后台 Worker 的 Variables 变量配置
 *   （ALERT_WEBHOOK_ENABLED / ALERT_WEBHOOK_URL / ALERT_EMAIL_ENABLED / ALERT_EMAIL_TO 等）。
 *
 * 修改保存后点击编辑器右上角 Deploy 即刻生效，无需改其它任何地方。
 * 每个字段的作用见 MONITORS 上方的字段说明注释。
 * ========================================================================== */

/**
 * UptimePulse - 监控项集中配置
 *
 * 【怎么改监控项】
 *   直接编辑下面的 MONITORS 数组：新增一个对象、删除一个对象、或修改某个字段。
 *   改完在 Cloudflare Dashboard 编辑器点击 Deploy 即刻生效。
 *
 * 【告警地址与开关】
 *   不要写死在代码里。请在 Cloudflare Dashboard → Worker → Variables and Secrets
 *   以普通变量（plain_text）添加，不要选 Secret（用户要求变量值不加密）。
 *   设置 ALERT_WEBHOOK_ENABLED / ALERT_WEBHOOK_URL / ALERT_EMAIL_ENABLED /
 *   ALERT_EMAIL_TO 等变量（各变量含义见 wrangler.toml 注释）。
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
 *   intervalSec      检测间隔（>=60），默认 60；KV 免费额度按写入次数计费（全账户共享 1000 次/天），
 *                    本代码已合并为每轮检测仅 1 次 KV 写入，建议 intervalSec >= 1200（20 分钟，72 写/天）
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
    id: "tv",
    name: "TV",
    url: "https://tv.example.com/",
    type: "website",
    group: "Public",
    enabled: true,
    method: "GET",
    expectedStatus: 307,
    // 未登录时跳 /login，307 即视为站点正常（检测不跟随重定向）
    // 进阶可选字段（其余监控项同样支持，按需添加即可）：
    // expectedCodes: [200, 307],          // 多个可接受状态码，优先于 expectedStatus
    // responseKeyword: '"ok"',            // 响应体必须包含
    // responseForbiddenKeyword: 'error',  // 响应体不得包含
    // method: 'GET', headers: { 'X-Api-Key': '...' }, body: '', retries: 1,
    // tooltip: '首页健康检查', statusPageLink: 'https://tv.example.com/', hideLatencyChart: false,
    timeoutMs: 5000,
    intervalSec: 1200,
    failureThreshold: 3,
    aggregate: "any",
    probes: [{ id: "edge-main", type: "edge", region: "cf-edge" }]
  },
  {
    id: "car",
    name: "Car",
    url: "https://car.example.com/",
    type: "website",
    group: "Public",
    enabled: true,
    method: "GET",
    expectedStatus: 200,
    timeoutMs: 5000,
    intervalSec: 1200,
    failureThreshold: 3,
    alertCooldownSec: 300,
    aggregate: "any",
    probes: [{ id: "edge-main", type: "edge", region: "cf-edge" }]
  },
  {
    id: "news",
    name: "News",
    url: "https://news.example.com/",
    type: "website",
    group: "Public",
    enabled: true,
    method: "GET",
    expectedStatus: 200,
    timeoutMs: 5000,
    intervalSec: 1200,
    failureThreshold: 2,
    aggregate: "any",
    probes: [{ id: "edge-main", type: "edge", region: "cf-edge" }]
  },
  {
    id: "note",
    name: "Note",
    url: "https://note.example.com/",
    type: "website",
    group: "Public",
    enabled: true,
    method: "GET",
    expectedStatus: 200,
    timeoutMs: 5000,
    intervalSec: 1200,
    failureThreshold: 2,
    aggregate: "any",
    probes: [{ id: "edge-main", type: "edge", region: "cf-edge" }]
  },
  {
    id: "res",
    name: "Res",
    url: "https://res.example.com/",
    type: "website",
    group: "Public",
    enabled: true,
    method: "GET",
    expectedStatus: 200,
    timeoutMs: 5000,
    intervalSec: 1200,
    failureThreshold: 2,
    aggregate: "any",
    probes: [{ id: "edge-main", type: "edge", region: "cf-edge" }]
  },
  {
    id: "notify",
    name: "Notify",
    url: "https://ntfy.example.com/",
    type: "website",
    group: "Public",
    enabled: true,
    method: "GET",
    expectedStatus: 401,
    // 根路径受保护，401 即视为服务正常；告警仍走 .send 端点
    timeoutMs: 5000,
    intervalSec: 1200,
    failureThreshold: 2,
    aggregate: "any",
    probes: [{ id: "edge-main", type: "edge", region: "cf-edge" }]
  }
];

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

/**
 * UptimePulse - 核心库（安全原语 / 检测引擎 / 状态机辅助 / 只读 UI）
 *
 * 监控目标统一在本文件顶部 MONITORS 数组中集中维护。
 * 告警通知地址与开关来自环境变量（resolveAlertConfig），不在代码中写死。
 * 服务端读取配置生成监控列表；前端只读展示；不提供任何修改监控配置的接口或入口。
 * 同一份代码可部署为 Worker，也可由 scripts/dev-server.mjs 本地运行。
 *
 * 升级要点（参考 UptimeFlare 设计思路）：
 *  - 检测：多期望状态码、响应关键字正反匹配、自定义 headers/body、网络故障重试与退避
 *  - 判定：稳定错误分类（status/keyword/timeout/dns/tls/network），区分确定性与瞬时故障
 *  - 记录：累计 up/down 计数、故障事件历史（起止/持续时长/原因）、可选 KV 写冷却
 *  - 展示：24h/全量可用率、当前延迟、事件列表、摘要统计、主题切换、区间切换
 */
// ---------- 常量与类型 ----------
const SECURITY_HEADERS = {
  'X-Content-Type-Options': 'nosniff',
  'Referrer-Policy': 'no-referrer',
  'X-Frame-Options': 'DENY',
  'Content-Security-Policy': "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; connect-src 'self'; img-src 'self' data:; object-src 'none'; base-uri 'none'; frame-ancestors 'none'",
};
const MAX_HISTORY = 500;
const MAX_TARGETS = 100;
const MAX_BODY_BYTES = 65536;   // 关键字校验时最多读取的响应体字节数
const MAX_BODY_FIELD = 4096;    // 自定义请求体最大长度
const MAX_EVENTS = 30;          // 每个监控项保留的故障事件数
const DAY_MS = 86400000;
const encoder = new TextEncoder();
const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/;
const SAFE_METHODS = ['GET', 'HEAD', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'];
const FORBIDDEN_HEADERS = new Set(['host', 'content-length', 'connection', 'upgrade',
  'proxy-authorization', 'proxy-authenticate', 'transfer-encoding', 'te', 'trailer']);

/**
 * @typedef {{id:string,name:string,url:string,method:string,expectedStatus:number,expectedCodes:number[],timeoutMs:number,intervalSec:number,failureThreshold:number,alertCooldownSec:number,aggregate:string,probes:Array,webhookUrl:string,emailTo:string,enabled:boolean,retries:number,headers:Object,body:string,responseKeyword:string,responseForbiddenKeyword:string,tooltip:string,statusPageLink:string,hideLatencyChart:boolean}} Monitor
 * @typedef {{probeId:string,region:string,ok:boolean,status:number,latencyMs:number,error:string|null,errorClass:string,checkedAt:string,attempts:number}} ProbeResult
 * @typedef {{state:'ok'|'firing',consecutiveFailures:number,incidentId:string|null,lastAlertAt:number,lastSignature:string|null,totalChecks:number,upChecks:number,downChecks:number,outageStart:number}} IncidentState
 */

function json(data, status = 200, extra = {}) {
  return new Response(JSON.stringify(data), {
    status, headers: { 'content-type': 'application/json; charset=utf-8', ...SECURITY_HEADERS, ...extra },
  });
}
function text(body, status = 200, contentType = 'text/html; charset=utf-8') {
  return new Response(body, { status, headers: { 'content-type': contentType, ...SECURITY_HEADERS } });
}

/** 常量时间比较，避免时序侧信道 */
function safeEqual(a, b) {
  if (typeof a !== 'string' || typeof b !== 'string' || a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return diff === 0;
}

/** 将 32 位整数还原为点分十进制 IPv4 */
function u32ToIp(n) {
  return `${(n >>> 24) & 255}.${(n >>> 16) & 255}.${(n >>> 8) & 255}.${n & 255}`;
}

/**
 * 判断 IP 是否属于私网 / 保留地址。
 * 覆盖：点分十进制、IPv4-mapped IPv6、6to4(2002::/16)、Teredo(2001::/32)、
 *       NAT64(64:ff9b::/96) 内嵌 IPv4，以及本地/链路本地/ULA 等保留前缀。
 */
function isPrivateIp(input) {
  let ip = String(input).toLowerCase().trim().replace(/^\[/, '').replace(/\]$/, '');
  if (!ip || ip.length > 128) return true;

  // IPv4-mapped IPv6：::ffff:a.b.c.d 或 ::ffff:xxxx:xxxx（含省略形式）
  if (ip.startsWith('::ffff:')) {
    const rest = ip.slice(7);
    const dotted = rest.match(/^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/);
    if (dotted) return isPrivateIp(rest);
    const hex = rest.split(':').filter(Boolean);
    if (hex.length === 1 && /^[0-9a-f]{1,8}$/.test(hex[0])) {
      return isPrivateIp(u32ToIp(parseInt(hex[0], 16) >>> 0));
    }
    if (hex.length === 2 && /^[0-9a-f]{1,4}$/.test(hex[0]) && /^[0-9a-f]{1,4}$/.test(hex[1])) {
      return isPrivateIp(u32ToIp(((parseInt(hex[0], 16) << 16) | parseInt(hex[1], 16)) >>> 0));
    }
    return true; // 无法解析的映射地址一律拒绝
  }

  // IPv6 隧道内嵌 IPv4：这些前缀专线用于穿越 NAT，绝不应作为监控目标
  // 6to4  2002:WWXX:YYZZ::  -> W.X.Y.Z（WW/XX/YY/ZZ 为 8 位十六进制组）
  const sixtofour = ip.match(/^2002:([0-9a-f]{1,4}):([0-9a-f]{1,4})(?::|$)/);
  if (sixtofour) {
    const hi = parseInt(sixtofour[1], 16), lo = parseInt(sixtofour[2], 16);
    return isPrivateIp(u32ToIp(((hi << 16) | lo) >>> 0));
  }
  // Teredo 2001:0000::/32：客户端 IPv4 在末 32 位（按位取反）
  if (/^2001:0(?::|:0)/.test(ip)) {
    const groups = ip.split(':');
    const tail = groups.slice(-2);
    if (tail.length === 2 && tail.every((g) => /^[0-9a-f]{1,4}$/.test(g))) {
      const raw = ((parseInt(tail[0], 16) << 16) | parseInt(tail[1], 16)) >>> 0;
      return isPrivateIp(u32ToIp((~raw) >>> 0)) || isPrivateIp(u32ToIp(raw));
    }
    return true;
  }
  // NAT64 64:ff9b::/96：IPv4 在末 32 位
  const nat64 = ip.match(/^64:ff9b:(?::)*([0-9a-f]{1,4}):([0-9a-f]{1,4})$/);
  if (nat64) {
    const hi = parseInt(nat64[1], 16), lo = parseInt(nat64[2], 16);
    return isPrivateIp(u32ToIp(((hi << 16) | lo) >>> 0));
  }

  // 点分十进制 IPv4；拒绝含前导零的段（八进制混淆写法）
  const v4 = ip.match(/^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/);
  if (v4) {
    if (v4.slice(1).some((seg) => seg.length > 1 && seg[0] === '0')) return true;
    const a = Number(v4[1]), b = Number(v4[2]);
    if (a === 0 || a === 10 || a === 127 || a >= 224) return true;
    if (a === 172 && b >= 16 && b <= 31) return true;
    if (a === 192 && b === 168) return true;
    if (a === 169 && b === 254) return true;
    if (a === 100 && b >= 64 && b <= 127) return true;
    if (a === 192 && b === 0) return true;
    if (a === 198 && (b === 18 || b === 19)) return true;
    return false;
  }
  if (ip === '::1' || ip === '::' || ip.startsWith('fc') || ip.startsWith('fd') || ip.startsWith('fe80')) return true;
  return false;
}

/** 默认 DNS 解析器：Cloudflare DoH（Workers 内可用） */
async function dohResolve(host) {
  const results = [];
  for (const type of [1, 28]) {
    const url = `https://cloudflare-dns.com/dns-query?name=${encodeURIComponent(host)}&type=${type}`;
    const resp = await fetch(url, { headers: { accept: 'application/dns-json' } });
    if (!resp.ok) continue;
    const data = await resp.json();
    for (const ans of data.Answer || []) {
      if (ans.type === type && typeof ans.data === 'string') results.push(ans.data);
    }
  }
  return results;
}

/**
 * SSRF 防护：校验目标 URL 是否可安全出站访问。
 * 即使目标来自受信任的后台变量，检测引擎仍对每个目标执行此校验（纵深防御）。
 */
async function assertPublicTarget(raw, resolveDns) {
  if (typeof raw !== 'string' || raw.length > 2048) throw new Error('URL 无效或过长');
  let u;
  try { u = new URL(raw); } catch { throw new Error('URL 格式错误'); }
  if (u.protocol !== 'http:' && u.protocol !== 'https:') throw new Error('仅支持 http/https 协议');
  if (u.username || u.password) throw new Error('URL 不允许包含凭据');
  const host = u.hostname.toLowerCase().replace(/^\[|\]$/g, '').replace(/\.$/, '');
  if (!host) throw new Error('缺少主机名');
  // 拒绝整数/十六进制/八进制等混淆 IP 写法（WHATWG URL 会规范化部分形式，这里兜底）
  if (/^0[xX][0-9a-f]+$/.test(host) || /^0[oO][0-7]+$/.test(host)) throw new Error('禁止使用混淆 IP 写法');
  if (/^0[0-7]+$/.test(host)) throw new Error('禁止使用混淆 IP 写法');
  if (/^\d+$/.test(host)) throw new Error('禁止使用整数 IP 写法');
  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(host) || host.includes(':')) {
    if (isPrivateIp(host)) throw new Error('目标 IP 属于内网/保留地址');
    return u;
  }
  const blockedSuffix = ['.localhost', '.local', '.internal', '.lan', '.home.arpa', '.test', '.invalid'];
  if (host === 'localhost' || blockedSuffix.some((s) => host.endsWith(s))) throw new Error('禁止访问内网域名');
  let ips;
  try { ips = await resolveDns(host); } catch { throw new Error('DNS 解析失败'); }
  if (!ips.length) throw new Error('域名无解析记录');
  if (ips.some(isPrivateIp)) throw new Error('域名解析到内网/保留地址');
  return u;
}

/** KV 数据健壮性：被污染的非数组/非对象一律回退为空值，避免 unshift/filter 抛错 */
function asArray(v) { return Array.isArray(v) ? v : []; }
function asObject(v) { return v && typeof v === 'object' && !Array.isArray(v) ? v : {}; }

/** 告警状态机默认结构（每次返回新对象，避免共享可变引用） */
function defaultIncident() {
  return {
    state: 'ok', consecutiveFailures: 0, incidentId: null, lastAlertAt: 0, lastSignature: null,
    totalChecks: 0, upChecks: 0, downChecks: 0, outageStart: 0,
  };
}

async function hmacSign(payload, secret) {
  const key = await crypto.subtle.importKey('raw', encoder.encode(secret), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  const sig = await crypto.subtle.sign('HMAC', key, encoder.encode(payload));
  return Array.from(new Uint8Array(sig)).map((b) => b.toString(16).padStart(2, '0')).join('');
}

// ---------- 配置层：后台变量 -> 监控列表 ----------
async function getJson(kv, key, fallback) {
  try { const v = await kv.get(key, 'json'); return v === null ? fallback : v; } catch { return fallback; }
}

function clampInt(value, min, max, fallback) {
  const n = Number(value);
  if (!Number.isFinite(n)) return fallback;
  return Math.min(max, Math.max(min, Math.round(n)));
}

/** 由 URL + 名称生成稳定 ID：变量更新 / 实例重启后历史数据仍可对应同一目标 */
function stableId(url, name) {
  let h = 0x811c9dc5;
  const s = `${url}|${name || ''}`;
  for (let i = 0; i < s.length; i++) { h ^= s.charCodeAt(i); h = Math.imul(h, 0x01000193) >>> 0; }
  return `cfg-${h.toString(36)}`;
}

function normalizeProbes(value) {
  const arr = Array.isArray(value) ? value : [{ id: 'edge-main', type: 'edge', region: 'cf-edge' }];
  return arr.slice(0, 10).map((p, i) => ({
    id: String(p.id || `probe-${i}`).slice(0, 40).replace(/[^a-zA-Z0-9_-]/g, ''),
    type: p.type === 'external' ? 'external' : 'edge',
    region: String(p.region || 'unknown').slice(0, 40),
  })).filter((p) => p.id);
}

/** 规范化期望状态码数组：支持 [200,201] 等；非法值回退到 expectedStatus */
function normalizeCodes(raw, fallback) {
  const base = clampInt(fallback, 100, 599, 200);
  if (!Array.isArray(raw)) return [base];
  const codes = [];
  for (const v of raw) {
    const c = clampInt(v, 100, 599, 0);
    if (c && !codes.includes(c)) codes.push(c);
    if (codes.length >= 12) break;
  }
  return codes.length ? codes : [base];
}

/** 规范化自定义请求头：仅字符串标量，过滤危险逐跳头，限制数量与长度 */
function normalizeHeaders(raw) {
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) return {};
  const out = {};
  let count = 0;
  for (const [key, value] of Object.entries(raw)) {
    if (count >= 20) break;
    const k = String(key).trim();
    if (!k || k.length > 64 || FORBIDDEN_HEADERS.has(k.toLowerCase())) continue;
    if (typeof value !== 'string' && typeof value !== 'number' && typeof value !== 'boolean') continue;
    out[k] = String(value).slice(0, 512);
    count++;
  }
  return out;
}

/** 将单条后台变量配置规范化为 Monitor；非法条目返回 null（不崩溃） */
function normalizeTarget(raw) {
  if (!raw || typeof raw.url !== 'string') return null;
  const url = raw.url.trim();
  let u;
  try { u = new URL(url); } catch { return null; }
  if (u.protocol !== 'http:' && u.protocol !== 'https:') return null;
  const name = String(raw.name || '').slice(0, 80);
  const id = (typeof raw.id === 'string' && /^[a-zA-Z0-9_-]{1,64}$/.test(raw.id)) ? raw.id : stableId(url, name);
  const emailTo = typeof raw.emailTo === 'string' && EMAIL_RE.test(raw.emailTo) ? raw.emailTo : '';
  const method = SAFE_METHODS.includes(String(raw.method || '').toUpperCase())
    ? String(raw.method).toUpperCase() : 'GET';
  const expectedStatus = clampInt(raw.expectedStatus, 100, 599, 200);
  return {
    id, name, url,
    type: ['website', 'api', 'service'].includes(raw.type) ? raw.type : 'website',
    group: String(raw.group || 'Public').slice(0, 60),
    alertEnabled: raw.alertEnabled !== false,
    method,
    expectedStatus,
    expectedCodes: normalizeCodes(raw.expectedCodes, expectedStatus),
    timeoutMs: clampInt(raw.timeoutMs, 1000, 30000, 5000),
    intervalSec: clampInt(raw.intervalSec, 60, 86400, 60),
    failureThreshold: clampInt(raw.failureThreshold, 1, 20, 3),
    alertCooldownSec: clampInt(raw.alertCooldownSec ?? 300, 0, 86400, 300),
    aggregate: raw.aggregate === 'all' ? 'all' : 'any',
    probes: normalizeProbes(raw.probes),
    webhookUrl: typeof raw.webhookUrl === 'string' ? raw.webhookUrl.slice(0, 2048) : '',
    emailTo,
    enabled: raw.enabled !== false,
    retries: clampInt(raw.retries ?? 0, 0, 3, 0),
    headers: normalizeHeaders(raw.headers),
    body: typeof raw.body === 'string' ? raw.body.slice(0, MAX_BODY_FIELD) : '',
    responseKeyword: typeof raw.responseKeyword === 'string' ? raw.responseKeyword.slice(0, 256) : '',
    responseForbiddenKeyword: typeof raw.responseForbiddenKeyword === 'string' ? raw.responseForbiddenKeyword.slice(0, 256) : '',
    tooltip: typeof raw.tooltip === 'string' ? raw.tooltip.slice(0, 200) : '',
    statusPageLink: typeof raw.statusPageLink === 'string' && /^https?:\/\//i.test(raw.statusPageLink)
      ? raw.statusPageLink.slice(0, 2048) : '',
    hideLatencyChart: raw.hideLatencyChart === true,
  };
}

/** 解析监控配置：支持数组、JSON 字符串，或 { "targets": [...] } */
function parseTargets(raw) {
  let data = raw;
  if (typeof raw === 'string') {
    if (!raw.trim()) return [];
    try { data = JSON.parse(raw); } catch (e) { console.error('监控配置解析失败：', e.message); return []; }
  }
  const arr = Array.isArray(data) ? data : (data && Array.isArray(data.targets) ? data.targets : []);
  const out = [];
  const seen = new Set();
  for (const item of arr) {
    const t = normalizeTarget(item);
    if (!t || seen.has(t.id)) continue;
    seen.add(t.id);
    out.push(t);
    if (out.length >= MAX_TARGETS) break;
  }
  return out;
}

// 默认配置来自 src/config.mjs；env.MONITORS 仅用于测试/本地注入，不参与生产运行时。
// 缓存按配置内容失效：配置不变时避免重复解析，配置一改立即重新生成列表。
let _configCache = { raw: null, monitors: null };
async function getMonitors(env) {
  const source = (env && env.MONITORS !== undefined && env.MONITORS !== null) ? env.MONITORS : MONITORS;
  const raw = typeof source === 'string' ? source : JSON.stringify(source);
  if (_configCache.raw === raw && _configCache.monitors) return _configCache.monitors;
  const monitors = parseTargets(source);
  _configCache = { raw, monitors };
  return monitors;
}

// ---------- 检测引擎 ----------
/** 动态错误文本归一化为稳定类别，避免错误文案变化导致去重失效（告警风暴） */
function errorClass(error) {
  if (!error) return 'ok';
  const e = String(error).toLowerCase();
  if (e.includes('timeout') || e.includes('abort')) return 'timeout';
  if (e.includes('keyword')) return 'keyword';
  if (e.startsWith('http ') || e.includes('status')) return 'status';
  if (e.includes('no-probe-data') || e.includes('stale') || e.includes('probe-missing')) return 'probe-missing';
  if (e.includes('dns') || e.includes('resolve') || e.includes('enotfound')) return 'dns';
  if (e.includes('tls') || e.includes('certificate') || e.includes('ssl')) return 'tls';
  return 'network';
}

/** 仅对瞬时网络类故障重试；确定性 HTTP 状态/关键字不匹配不重试 */
function isRetryable(cls) {
  return cls === 'timeout' || cls === 'dns' || cls === 'tls' || cls === 'network';
}

/** 受大小限制地读取响应文本，用于关键字校验，避免超大响应体拖慢 Worker */
async function readBodyCapped(resp, cap) {
  if (!resp || !resp.body) return '';
  const reader = resp.body.getReader ? resp.body.getReader() : null;
  if (!reader) { try { return (await resp.text()).slice(0, cap); } catch { return ''; } }
  const decoder = new TextDecoder();
  let out = '', received = 0;
  try {
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      const chunk = value.length > cap - received ? value.subarray(0, Math.max(0, cap - received)) : value;
      if (chunk.length) { out += decoder.decode(chunk, { stream: true }); received += chunk.length; }
      if (received >= cap) break;
    }
    out += decoder.decode();
  } catch { /* 读取中断时保留已获取内容 */ }
  try { await reader.cancel().catch(() => {}); } catch { /* noop */ }
  return out;
}

/** 单次 HTTP(S) 请求：应用自定义方法/头/体、多状态码判定与关键字正反匹配 */
async function probeAttempt(monitor, target, env) {
  const started = Date.now();
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), monitor.timeoutMs || 5000);
  const headers = {
    'user-agent': 'UptimePulse/2.0 (+monitor)',
    accept: '*/*',
    ...monitor.headers,
  };
  const init = {
    method: monitor.method || 'GET',
    redirect: 'manual', // SSRF：绝不跟随重定向
    signal: controller.signal,
    headers,
  };
  if (monitor.body && !['GET', 'HEAD'].includes(init.method)) init.body = monitor.body;
  let resp;
  try {
    resp = await (env.fetchImpl || fetch)(target.toString(), init);
  } finally { clearTimeout(timer); }
  const status = resp.status;
  const needBody = !!(monitor.responseKeyword || monitor.responseForbiddenKeyword);
  if (needBody) {
    const body = await readBodyCapped(resp, MAX_BODY_BYTES);
    const codes = monitor.expectedCodes && monitor.expectedCodes.length
      ? monitor.expectedCodes : [monitor.expectedStatus || 200];
    let error = null;
    if (!codes.includes(status)) error = `HTTP ${status}`;
    else if (monitor.responseKeyword && !body.includes(monitor.responseKeyword)) error = 'keyword-missing';
    else if (monitor.responseForbiddenKeyword && body.includes(monitor.responseForbiddenKeyword)) error = 'keyword-forbidden';
    return { status, error, latencyMs: Date.now() - started };
  }
  if (resp.body) await resp.body.cancel().catch(() => {});
  const codes = monitor.expectedCodes && monitor.expectedCodes.length
    ? monitor.expectedCodes : [monitor.expectedStatus || 200];
  return {
    status,
    error: codes.includes(status) ? null : `HTTP ${status}`,
    latencyMs: Date.now() - started,
  };
}

const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

/** 对目标执行一次完整探测（含 SSRF 校验与瞬时故障重试），返回统一 ProbeResult */
async function probeOnce(monitor, env) {
  const started = Date.now();
  const region = env.PROBE_REGION || 'cf-edge';
  const base = {
    probeId: `${region}-${monitor.id}`, region, ok: false, status: 0,
    latencyMs: 0, error: null, errorClass: 'network', checkedAt: new Date().toISOString(), attempts: 0,
  };
  let target;
  try {
    target = await assertPublicTarget(monitor.url, env.resolveDns || dohResolve);
  } catch (e) {
    const error = String((e && e.message) || e).slice(0, 200);
    return { ...base, error, errorClass: errorClass(error), latencyMs: Date.now() - started, attempts: 1 };
  }
  const maxAttempts = 1 + clampInt(monitor.retries, 0, 3, 0);
  let last = { status: 0, error: 'unknown', latencyMs: 0 };
  for (let attempt = 1; attempt <= maxAttempts; attempt++) {
    try {
      last = await probeAttempt(monitor, target, env);
    } catch (e) {
      last = {
        status: 0,
        error: e && e.name === 'AbortError' ? 'timeout' : String((e && e.message) || e).slice(0, 200),
        latencyMs: Date.now() - started,
      };
    }
    base.attempts = attempt;
    if (!last.error || !isRetryable(errorClass(last.error)) || attempt >= maxAttempts) break;
    await sleep(Math.min(400, 120 * (2 ** (attempt - 1))));
  }
  const cls = last.error ? errorClass(last.error) : 'ok';
  return {
    ...base,
    ok: !last.error,
    status: last.status,
    latencyMs: Date.now() - started,
    error: last.error,
    errorClass: cls,
    checkedAt: new Date().toISOString(),
  };
}


/** 写入一条故障事件（开始或恢复），保留最近 MAX_EVENTS 条 */
async function recordEvent(env, monitorId, event) {
  const key = `events:${monitorId}`;
  const events = asArray(await getJson(env.KV, key, []));
  events.unshift(event);
  if (events.length > MAX_EVENTS) events.length = MAX_EVENTS;
  await env.KV.put(key, JSON.stringify(events));
}


// ---------- 只读 Dashboard ----------
/** 统一把两种历史结构（demo 单次结果 / 完整版多线路轮次）压成绘图用的数据点 */
function historyPoint(h) {
  const checkedAt = h.checkedAt || new Date().toISOString();
  if (Array.isArray(h.results)) {
    const lat = h.results.map((r) => Number(r.latencyMs) || 0);
    return {
      checkedAt, ok: h.ok === true, latencyMs: Number(h.latencyMs ?? Math.max(0, ...lat)) || 0,
      status: Number(h.status) || 0, region: (h.results[0] || {}).region || '',
    };
  }
  return {
    checkedAt, ok: h.ok === true, latencyMs: Number(h.latencyMs) || 0,
    status: Number(h.status) || 0, region: h.region || '',
  };
}

/** 在指定时间窗口内计算可用率；无样本时返回 1（未被证明故障） */
function windowUptime(history, sinceMs) {
  const points = history.filter((h) => !sinceMs || Date.parse(h.checkedAt) >= sinceMs);
  if (!points.length) return { uptime: 1, samples: 0 };
  const ok = points.filter((h) => h.ok).length;
  return { uptime: ok / points.length, samples: points.length };
}

/** 状态接口数据（demo 与完整版共用），history 供状态条与响应时间曲线渲染 */
async function getStatusPayload(env) {
  const monitors = await getMonitors(env);
  const enabled = monitors.filter((m) => m.enabled);
  const now = Date.now();

  // 快照单键读取（1 次 KV 读）；事件仍为独立键、并行读取
  const snap = await loadSnapshot(env, monitors);
  const snapshots = await Promise.all(enabled.map(async (m) => ({
    m,
    history: asArray(snap.history[m.id] || []),
    incident: asObject(snap.incident[m.id] || { state: 'ok', consecutiveFailures: 0 }),
    events: asArray(await getJson(env.KV, `events:${m.id}`, [])),
  })));

  const out = [], recentErrors = [], allEvents = [];
  for (const { m, history, incident, events } of snapshots) {
    const lastPoint = history[0] || null;
    const all = windowUptime(history, 0);
    const day = windowUptime(history, now - DAY_MS);
    out.push({
      id: m.id, name: m.name, url: m.url, enabled: m.enabled, type: m.type, group: m.group,
      state: incident.state, consecutiveFailures: incident.consecutiveFailures,
      last: lastPoint,
      uptime: all.uptime, samples: all.samples,
      uptime24h: day.uptime, samples24h: day.samples,
      latencyMs: lastPoint ? (Number(lastPoint.latencyMs) || 0) : null,
      errorClass: lastPoint ? errorClass(lastPoint.error) : 'ok',
      tooltip: m.tooltip || '', statusPageLink: m.statusPageLink || '',
      hideLatencyChart: m.hideLatencyChart === true,
      history: history.slice(0, 120).map(historyPoint),
      events: events.slice(0, 10),
      totalChecks: Number(incident.totalChecks) || 0,
    });
    for (const ev of events.slice(0, 5)) {
      allEvents.push({ monitorId: m.id, monitorName: m.name || m.url, ...ev });
    }
    if (lastPoint && !lastPoint.ok) {
      const failed = (lastPoint.results && lastPoint.results.length)
        ? lastPoint.results.filter((r) => !r.ok)
        : [lastPoint];
      for (const r of failed) {
        // 公开接口只暴露稳定错误分类，不回传原始异常文本（可能含内部主机/IP/TLS 细节）
        recentErrors.push({
          checkedAt: lastPoint.checkedAt, monitorName: m.name || m.url,
          region: r.region, status: r.status, errorClass: r.errorClass || errorClass(r.error),
        });
      }
    }
  }
  allEvents.sort((a, b) => (b.end || b.start || 0) - (a.end || a.start || 0));
  const online = out.filter((m) => m.state === 'ok' && (!m.last || m.last.ok !== false)).length;
  const avg24h = out.length ? out.reduce((sum, m) => sum + m.uptime24h, 0) / out.length : 1;
  return {
    monitors: out,
    recentErrors: recentErrors.slice(0, 30),
    events: allEvents.slice(0, 20),
    summary: { total: out.length, online, offline: out.length - online, uptime24h: avg24h },
    serverTime: new Date().toISOString(),
  };
}

function dashboardHtml() {
  return `<!doctype html>
<html lang="zh-CN"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="color-scheme" content="light dark">
<title>服务状态 · UptimePulse</title><link rel="stylesheet" href="/app.css"></head><body>
<main class="page">
  <header class="hero">
    <div class="topbar">
      <span class="brand">UptimePulse</span>
      <span class="top-actions">
        <button id="themeBtn" class="iconbtn" type="button" aria-label="切换主题">◐ 主题</button>
        <button id="refresh" class="iconbtn" type="button" aria-label="立即刷新">↻ 刷新</button>
      </span>
    </div>
    <div id="heroIcon" class="badge ok">
      <svg id="icoOk" class="ico" viewBox="0 0 48 48" aria-hidden="true"><circle cx="24" cy="24" r="19" fill="none" stroke="currentColor" stroke-width="3.5"/><path d="M15 24.5l6 6 12-13" fill="none" stroke="currentColor" stroke-width="3.8" stroke-linecap="round" stroke-linejoin="round"/></svg>
      <svg id="icoBad" class="ico" viewBox="0 0 48 48" aria-hidden="true" style="display:none"><circle cx="24" cy="24" r="19" fill="none" stroke="currentColor" stroke-width="3.5"/><path d="M24 14v13M24 32v2" stroke="currentColor" stroke-width="4" stroke-linecap="round"/></svg>
    </div>
    <h1 id="heroTitle">系统一切正常</h1>
    <p class="sub">最后更新于: <span id="updatedAt">—</span> (<span id="age">0</span> 秒前)</p>
    <div id="summary" class="summary"></div>
  </header>
  <div id="groups"></div>
  <section id="events" class="events"></section>
  <footer class="foot">UptimePulse · 只读状态面板 · 监控项由服务端统一维护 <span id="msg" class="msg"></span></footer>
</main><script src="/app.js" defer></script></body></html>`;
}

const APP_CSS = `:root{color-scheme:light;--bg:#fff;--fg:#1f2937;--muted:#6b7280;--faint:#9aa2ae;--card:#fafbfc;--border:#e5e8ee;--head:#f3f5f8;--ok:#16a34a;--okbar:#22c55e;--bad:#dc2626;--badbar:#ef4444;--warn:#f59e0b;--line:#64748b;--grid:#e8ebf0}
:root[data-theme="dark"]{color-scheme:dark;--bg:#0b1220;--fg:#e5e7eb;--muted:#9ca3af;--faint:#6b7280;--card:#121b2e;--border:#26324a;--head:#1a2438;--ok:#34d399;--okbar:#22c55e;--bad:#f87171;--badbar:#ef4444;--warn:#fbbf24;--line:#94a3b8;--grid:#26324a}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--fg);font:14px/1.5 -apple-system,BlinkMacSystemFont,"Segoe UI","PingFang SC","Microsoft YaHei",sans-serif}
.page{max-width:960px;margin:0 auto;padding:24px 20px 48px}
.topbar{display:flex;align-items:center;justify-content:space-between;margin-bottom:18px}
.brand{font-weight:800;font-size:13px;letter-spacing:.4px;color:var(--muted)}
.top-actions{display:flex;gap:8px}
.iconbtn{border:1px solid var(--border);background:var(--card);color:var(--muted);border-radius:7px;padding:5px 10px;font:inherit;font-size:12px;cursor:pointer;transition:.15s}
.iconbtn:hover{color:var(--fg);border-color:var(--line)}
.hero{text-align:center;margin-bottom:26px}
.badge{width:52px;height:52px;margin:0 auto 16px;color:var(--ok)}.badge.bad{color:var(--bad)}.ico{width:52px;height:52px;display:block}
.hero h1{font-size:30px;line-height:1.25;font-weight:800;letter-spacing:-.5px;margin:0 0 10px;color:var(--fg)}
.hero .sub{color:var(--muted);font-size:13px;margin:0}
.summary{display:flex;flex-wrap:wrap;gap:8px;justify-content:center;margin-top:14px}
.summary-pill{background:var(--card);border:1px solid var(--border);border-radius:999px;padding:4px 12px;font-size:12px;color:var(--muted)}
.summary-pill b{color:var(--fg)}
.card{background:var(--card);border:1px solid var(--border);border-radius:10px;margin-bottom:18px;overflow:hidden}
.group-head{display:flex;align-items:center;justify-content:space-between;padding:14px 18px;background:var(--head)}
.group-title{display:flex;align-items:center;gap:8px;font-weight:700;font-size:14px;color:var(--fg)}
.group-title svg{width:16px;height:16px;color:#2563eb}
.group-right{display:flex;align-items:center;gap:10px;font-size:13px;font-weight:600}
.online{color:var(--ok)}.offline{color:var(--bad)}
.toggle{border:0;background:transparent;color:var(--muted);font-size:16px;cursor:pointer;padding:0 2px;line-height:1}
.group-body.collapsed{display:none}
.monitor{border-top:1px solid var(--border);padding:14px 18px 16px}
.monitor-head{display:flex;align-items:center;gap:8px;flex-wrap:wrap}
.monitor-head .ico{width:18px;height:18px;flex:none;color:var(--ok)}
.monitor-head .ico.bad{color:var(--bad)}
.mon-name{color:var(--fg);font-weight:700;font-size:14px;text-decoration:underline;text-underline-offset:2px}
.tag{font-size:11px;color:var(--muted);border:1px solid var(--border);border-radius:4px;padding:0 5px}
.status-pill{font-size:11px;border-radius:999px;padding:1px 8px;font-weight:600}
.status-pill.ok{color:var(--ok);background:rgba(34,197,94,.12)}
.status-pill.bad{color:var(--bad);background:rgba(239,68,68,.12)}
.rate{margin-left:auto;color:var(--ok);font-weight:700;font-size:13px;white-space:nowrap}
.rate.bad{color:var(--bad)}
.meta{display:flex;gap:14px;flex-wrap:wrap;font-size:12px;color:var(--muted);margin-top:2px}
.bars{display:flex;gap:1px;height:16px;margin:10px 0 8px}
.bar{flex:1;min-width:2px;background:var(--okbar);border-radius:1px}
.bar.down{background:var(--badbar)}.bar.warn{background:var(--warn)}
.chart-label{font-size:11px;color:var(--muted);margin-bottom:2px}
.spark{display:block;width:100%;height:82px}
.spark .grid{stroke:var(--grid);stroke-width:1}
.spark .line{fill:none;stroke:var(--line);stroke-width:1.6;stroke-linejoin:round;stroke-linecap:round}
.spark .axis{fill:var(--faint);font-size:10px;font-family:inherit}
.ranges{display:flex;gap:4px;margin:6px 0}
.range-btn{border:1px solid var(--border);background:transparent;color:var(--muted);border-radius:5px;padding:1px 8px;font:inherit;font-size:11px;cursor:pointer}
.range-btn.active{background:var(--head);color:var(--fg);border-color:var(--line)}
.events-title{font-size:14px;font-weight:700;margin:22px 0 10px;color:var(--fg)}
.event-row{border:1px solid var(--border);background:var(--card);border-radius:8px;padding:10px 14px;margin-bottom:8px;font-size:13px}
.event-row .event-meta{color:var(--muted);font-size:12px;margin-top:2px}
.muted{color:var(--faint)}.small{font-size:12px}
.empty{padding:24px;text-align:center;color:var(--faint);font-size:13px}
.foot{text-align:center;color:var(--faint);font-size:11px;margin-top:22px}
.msg{color:var(--bad);margin-left:6px}
@media(max-width:640px){.page{padding:18px 12px 36px}.hero h1{font-size:24px}.monitor{padding:12px}.group-head{padding:12px}.rate{font-size:12px}.summary-pill{font-size:11px}}`;

const APP_JS = `var $=function(id){return document.getElementById(id)};
var NS='http://www.w3.org/2000/svg';
var lastUpdate=0;
function el(tag,text,cls){var n=document.createElement(tag);if(cls)n.className=cls;if(text!==undefined&&text!==null)n.textContent=String(text);return n}
function sv(tag,attrs){var n=document.createElementNS(NS,tag);for(var k in attrs)n.setAttribute(k,attrs[k]);return n}
function axis(x,y,txt,anchor){var t=sv('text',{x:x,y:y,'class':'axis'});if(anchor)t.setAttribute('text-anchor',anchor);t.textContent=txt;return t}
function hour(ms){var d=new Date(ms),h=d.getHours();return (h%12||12)+(h<12?'AM':'PM')}
function nice(v){v=Math.max(1,Number(v)||1);var e=Math.pow(10,Math.floor(Math.log10(v))),n=v/e;var m=n<=1?1:n<=2?2:n<=2.5?2.5:n<=5?5:10;return m*e}
function seq(hist,range){var h=(hist||[]).slice();if(range==='24h'){var c=Date.now()-86400000;h=h.filter(function(p){return Date.parse(p.checkedAt)>=c})}else if(range==='7d'){var c7=Date.now()-604800000;h=h.filter(function(p){return Date.parse(p.checkedAt)>=c7})}return h.slice(0,90).reverse()}
function okState(m){return m.state==='ok'&&(!m.last||m.last.ok!==false)}
function pct(v){return ((v||0)*100).toFixed(1)+'%'}
function icon(ok){var s=sv('svg',{viewBox:'0 0 24 24','class':ok?'ico':'ico bad'});s.appendChild(sv('circle',{cx:12,cy:12,r:10,fill:'none',stroke:'currentColor','stroke-width':2}));if(ok){s.appendChild(sv('path',{d:'M7 12.4l3.2 3.2L17 9',fill:'none',stroke:'currentColor','stroke-width':2.2,'stroke-linecap':'round','stroke-linejoin':'round'}))}else{s.appendChild(sv('path',{d:'M12 7v7M12 17v1',stroke:'currentColor','stroke-width':2.4,'stroke-linecap':'round'}))}return s}
function globe(){var s=sv('svg',{viewBox:'0 0 24 24'});s.appendChild(sv('circle',{cx:12,cy:12,r:9,fill:'none',stroke:'currentColor','stroke-width':2}));s.appendChild(sv('path',{d:'M3 12h18M12 3c3 3 3 15 0 18M12 3c-3 3-3 15 0 18',fill:'none',stroke:'currentColor','stroke-width':1.6}));return s}
function bars(hist,range){var box=el('div',null,'bars'),data=seq(hist,range);if(!data.length){box.appendChild(el('span','暂无检测数据','muted small'));return box}var okLat=data.filter(function(p){return p.ok}).map(function(p){return p.latencyMs||0}).sort(function(a,b){return a-b});var med=okLat.length?okLat[Math.floor(okLat.length/2)]:0;data.forEach(function(p){var cls=p.ok?(med&&p.latencyMs>med*2?'bar warn':'bar'):'bar down';var b=el('span','',cls);b.title=(p.ok?'正常':'异常')+' / '+(p.latencyMs||0)+'ms / '+p.checkedAt;box.appendChild(b)});return box}
function chart(hist,range){var wrap=el('div',null,'chart');wrap.appendChild(el('div','chart-label','响应时间(ms)'));var pts=seq(hist,range).map(function(p){return {t:Date.parse(p.checkedAt),v:Number(p.latencyMs)||0}}).filter(function(p){return isFinite(p.t)});if(pts.length<2){wrap.appendChild(el('div','muted small','暂无足够数据绘制曲线'));return wrap}
var W=820,H=82,L=38,R=8,T=6,B=18,max=nice(Math.max.apply(null,pts.map(function(p){return p.v})));var svg=sv('svg',{viewBox:'0 0 '+W+' '+H,preserveAspectRatio:'none','class':'spark'});
[1,0.5,0].forEach(function(f){var y=T+(1-f)*(H-T-B);svg.appendChild(sv('line',{x1:L,y1:y,x2:W-R,y2:y,'class':'grid'}));svg.appendChild(axis(L-5,y+3,String(Math.round(max*f)),'end'))});
var coords=pts.map(function(p,i){var x=L+i/(pts.length-1)*(W-L-R),y=T+(1-Math.min(1,p.v/max))*(H-T-B);return x+','+y}).join(' ');svg.appendChild(sv('polyline',{points:coords,'class':'line'}));
var steps=Math.min(7,pts.length-1);for(var i=0;i<=steps;i++){var idx=Math.round(i/steps*(pts.length-1)),x=L+idx/(pts.length-1)*(W-L-R);svg.appendChild(axis(x,H-4,hour(pts[idx].t),'middle'))}
wrap.appendChild(svg);return wrap}
function monitor(m){var row=el('article',null,'monitor'),head=el('div',null,'monitor-head'),ok=okState(m);head.appendChild(icon(ok));
var link=m.statusPageLink||m.url||'#';var nm=el('a',m.name||m.url,'mon-name');nm.href=link;nm.target='_blank';nm.rel='noopener noreferrer';if(m.tooltip)nm.title=m.tooltip;head.appendChild(nm);
if(m.type&&m.type!=='website')head.appendChild(el('span',m.type,'tag'));
head.appendChild(el('span',ok?'正常':'故障',ok?'status-pill ok':'status-pill bad'));
head.appendChild(el('span','总可用率: '+pct(m.uptime),ok?'rate':'rate bad'));row.appendChild(head);
var meta=el('div',null,'meta');meta.appendChild(el('span','24h: '+pct(m.uptime24h===undefined?m.uptime:m.uptime24h)));if(m.latencyMs!==null&&m.latencyMs!==undefined)meta.appendChild(el('span','延迟: '+m.latencyMs+'ms'));if(m.consecutiveFailures)meta.appendChild(el('span','连续失败: '+m.consecutiveFailures));row.appendChild(meta);
var ranges=el('div',null,'ranges'),viz=el('div',null,'viz'),state={range:'all'};
function draw(){viz.textContent='';viz.appendChild(bars(m.history,state.range));if(!m.hideLatencyChart)viz.appendChild(chart(m.history,state.range))}
draw();
[['24h','24小时'],['7d','7天'],['all','全部']].forEach(function(pair){var b=el('button',pair[1],'range-btn'+(state.range===pair[0]?' active':''));b.type='button';b.addEventListener('click',function(){state.range=pair[0];for(var i=0;i<ranges.children.length;i++)ranges.children[i].className='range-btn';b.className='range-btn active';draw()});ranges.appendChild(b)});
row.appendChild(ranges);row.appendChild(viz);return row}
function group(name,list){var card=el('section',null,'card'),head=el('div',null,'group-head'),title=el('div',null,'group-title');title.appendChild(globe());title.appendChild(el('span',name));var online=list.filter(okState).length,right=el('div',null,'group-right');right.appendChild(el('span',online+'/'+list.length+' 在线',online===list.length?'online':'offline'));var btn=el('button','','toggle');btn.type='button';btn.textContent='⌃';btn.setAttribute('aria-label','折叠或展开分组');var body=el('div',null,'group-body');btn.addEventListener('click',function(){body.classList.toggle('collapsed');btn.textContent=body.classList.contains('collapsed')?'⌄':'⌃'});right.appendChild(btn);head.appendChild(title);head.appendChild(right);card.appendChild(head);list.forEach(function(m){body.appendChild(monitor(m))});card.appendChild(body);return card}
function renderSummary(d){var host=$('summary');if(!host)return;host.textContent='';var s=d.summary||{};if(s.total===undefined)return;host.appendChild(el('span',(s.online||0)+'/'+(s.total||0)+' 服务在线','summary-pill'));host.appendChild(el('span','24h 可用率: '+pct(s.uptime24h),'summary-pill'))}
function renderEvents(d){var host=$('events');if(!host)return;host.textContent='';var evs=d.events||[];if(!evs.length)return;host.appendChild(el('h2','最近故障事件','events-title'));evs.slice(0,8).forEach(function(e){var row=el('div',null,'event-row');row.appendChild(el('div',e.monitorName+' · '+e.errorClass+(e.resolved?' · 已恢复':' · 持续中')));var t=e.start?new Date(e.start).toLocaleString('zh-CN',{hour12:false}):'-';var dur=e.durationMs?Math.round(e.durationMs/1000)+'s':'-';row.appendChild(el('div','开始 '+t+' · 持续 '+dur,'event-meta'));host.appendChild(row)})}
function render(d){var ms=d.monitors||[],allOk=ms.length>0&&ms.every(okState);var badge=$('heroIcon');badge.className='badge '+(allOk?'ok':'bad');$('icoOk').style.display=allOk?'':'none';$('icoBad').style.display=allOk?'none':'';$('heroTitle').textContent=allOk?'系统一切正常':'部分服务异常';
lastUpdate=Date.parse(d.serverTime)||Date.now();$('updatedAt').textContent=new Date(lastUpdate).toLocaleString('zh-CN',{year:'numeric',month:'2-digit',day:'2-digit',hour:'2-digit',minute:'2-digit',second:'2-digit',hour12:false});age();
renderSummary(d);renderEvents(d);
var groups={},order=[];ms.forEach(function(m){var g=m.group||'Public';if(!groups[g]){groups[g]=[];order.push(g)}groups[g].push(m)});var host=$('groups');host.textContent='';if(!ms.length){host.appendChild(el('div','尚未配置监控项','empty'));return}order.forEach(function(g){host.appendChild(group(g,groups[g]))})}
function age(){if(lastUpdate)$('age').textContent=String(Math.max(0,Math.floor((Date.now()-lastUpdate)/1000)))}
async function load(){var r;try{r=await fetch('/api/status',{headers:{accept:'application/json'}})}catch(e){$('msg').textContent='网络异常';return}if(!r.ok){$('msg').textContent='加载失败 '+r.status;return}var d=await r.json();$('msg').textContent='';render(d)}
function applyTheme(){var t=theme;if(t==='auto'){try{t=(typeof window!=='undefined'&&window.matchMedia&&window.matchMedia('(prefers-color-scheme: dark)').matches)?'dark':'light'}catch(e){t='light'}}var doc=(typeof document!=='undefined')&&document.documentElement;if(doc&&doc.setAttribute)doc.setAttribute('data-theme',t);var b=$('themeBtn');if(b)b.textContent=t==='dark'?'☀ 浅色':t==='light'?'◐ 深色':'◐ 自动'}
var theme='auto';
function initTheme(){var b=$('themeBtn');if(!b)return;var s=null;try{s=(typeof localStorage!=='undefined')&&localStorage.getItem('up-theme')}catch(e){}theme=s==='dark'||s==='light'?s:'auto';b.addEventListener('click',function(){theme=theme==='dark'?'light':theme==='light'?'auto':'dark';try{if(typeof localStorage!=='undefined')localStorage.setItem('up-theme',theme)}catch(e){}applyTheme()});applyTheme()}
$('refresh')&&($('refresh').onclick=load);initTheme();load();setInterval(load,30000);setInterval(age,1000);`;


/**
 * UptimePulse - 生产 Worker 入口（多线路聚合 / 探针回传 / 告警双通道）
 *
 * 监控目标在本文件顶部 MONITORS 数组中集中维护，每个目标独立检测、独立告警。
 * 告警通知地址与开关来自环境变量（ALERT_*），不在代码中写死。
 * 前端只读展示；不提供任何修改监控配置的接口或入口。
 * 保留：多线路聚合、国内探针回传、邮件 + Webhook 双通道、历史与异常查询。
 * 安全原语、检测引擎、状态接口与 UI 即上方核心库部分，避免两套实现产生分歧。
 *
 * 升级要点（参考 UptimeFlare）：多期望状态码 / 关键字校验 / 自定义请求 / 重试由
 * probeOnce 统一处理；生产版叠加多线路聚合、故障事件记录与瞬时故障判定。
 */
// ---------- 告警通道 ----------
async function postJson(env, target, body, headers) {
  return (env.fetchImpl || fetch)(target, {
    method: 'POST', headers: { 'content-type': 'application/json', ...headers }, body,
  });
}

async function sendWebhook(url, payload, env) {
  const target = await assertPublicTarget(url, env.resolveDns || dohResolve);
  // Server酱/Turbo（.send 或带 text/title/desp）只认 body 中的 title/desp，忽略 query；
  // 标准 Webhook（含 ntfy 原生端点）继续接收完整 JSON 告警 payload。
  const built = buildWebhookBody(url, payload);
  const body = JSON.stringify(built.body);
  const headers = { 'user-agent': 'UptimePulse/2.0 (+alert)' };
  if (env.ALERT_SIGNING_SECRET) headers['x-uptimepulse-signature'] = `sha256=${await hmacSign(body, env.ALERT_SIGNING_SECRET)}`;
  const resp = await postJson(env, target.toString(), body, headers);
  if (!resp.ok) throw new Error(`Webhook HTTP ${resp.status}`);
  return true;
}

async function sendEmail(to, payload, env) {
  const cfg = resolveAlertConfig(env);
  if (!cfg.mail.apiKey || !cfg.mail.from || !to) return;
  // 邮件端点为硬编码可信域名，不接受用户输入
  const subject = `[UptimePulse][${payload.type === 'firing' ? '故障' : '恢复'}] ${payload.monitor.name || payload.monitor.url}`;
  const lines = [
    `类型: ${payload.type === 'firing' ? '故障' : '恢复'}`,
    `监控项: ${payload.monitor.name || payload.monitor.id}`,
    `目标: ${payload.monitor.url}`,
    `线路: ${payload.result.region || 'edge'}`,
    `HTTP: ${payload.result.status}`,
    `耗时: ${payload.result.latencyMs}ms`,
    `错误类别: ${payload.result.errorClass || '-'}`,
    `时间: ${payload.timestamp}`,
    `连续失败: ${payload.state.consecutiveFailures}`,
    payload.result.error ? `错误: ${payload.result.error}` : '',
  ].filter(Boolean);
  const resp = await postJson(env, 'https://api.resend.com/emails', JSON.stringify({
    from: cfg.mail.from, to: [to], subject, text: lines.join('\n'),
  }), { authorization: `Bearer ${cfg.mail.apiKey}` });
  if (!resp.ok) throw new Error(`邮件 HTTP ${resp.status}`);
  return true;
}

/**
 * 告警地址与开关来自 env（ALERT_*）；监控项可选覆盖，但 alertEnabled:false 可整体关闭该项告警。
 * @returns {Promise<number>} 成功投递的通道数（0 表示全部失败，调用方不应写入冷却标记）
 */
async function dispatchAlerts(monitor, type, aggregated, state, env) {
  if (monitor.alertEnabled === false) return 0;
  const cfg = resolveAlertConfig(env);
  const payload = {
    type,
    monitor: { id: monitor.id, name: monitor.name, url: monitor.url },
    result: aggregated,
    state,
    timestamp: new Date().toISOString(),
  };
  const jobs = [];
  const webhookUrl = monitor.webhookUrl || cfg.webhook.url;
  if (cfg.webhook.enabled && webhookUrl) {
    jobs.push(sendWebhook(webhookUrl, payload, env).then(() => true).catch((e) => {
      console.error('Webhook 告警失败', e); return false;
    }));
  }
  const emailTo = monitor.emailTo || cfg.email.to;
  if (cfg.email.enabled && emailTo) {
    jobs.push(sendEmail(emailTo, payload, env).then(() => true).catch((e) => {
      console.error('邮件告警失败', e); return false;
    }));
  }
  const results = await Promise.all(jobs);
  return results.filter(Boolean).length;
}

// ---------- 状态机与聚合 ----------
function aggregateResults(results, mode) {
  if (!results.length) return { ok: false, status: 0, latencyMs: 0, error: 'no-probe-data', errorClass: 'probe-missing' };
  const ok = mode === 'all' ? results.every((r) => r.ok) : results.some((r) => r.ok);
  const primary = results.find((r) => r.ok) || results[0];
  const failed = results.filter((r) => !r.ok);
  const error = ok ? null : (primary.error || `HTTP ${primary.status}`);
  const errorClassValue = ok ? 'ok' : (failed.find((r) => r.errorClass && r.errorClass !== 'ok')?.errorClass || errorClass(error));
  return {
    ok,
    status: primary.status,
    latencyMs: Math.max(...results.map((r) => r.latencyMs || 0)),
    error,
    errorClass: errorClassValue,
    attempts: Math.max(...results.map((r) => Number(r.attempts) || 0)),
  };
}

async function applyIncident(monitor, aggregated, env, snap) {
  let state = { ...defaultIncident(), ...asObject(snap.incident[monitor.id] || {}) };
  state.totalChecks = Number(state.totalChecks) || 0;
  state.upChecks = Number(state.upChecks) || 0;
  state.downChecks = Number(state.downChecks) || 0;
  state.outageStart = Number(state.outageStart) || 0;
  state.consecutiveFailures = Number(state.consecutiveFailures) || 0;
  state.lastAlertAt = Number(state.lastAlertAt) || 0;
  // Workers 变量 ALERT_FAILURE_THRESHOLD 优先；未设置时沿用监控项自身阈值（默认 3）
  const alertCfg = resolveAlertConfig(env);
  const threshold = alertCfg.failureThreshold ?? Math.max(1, monitor.failureThreshold || 3);
  const cooldownMs = Math.max(0, monitor.alertCooldownSec ?? 300) * 1000;
  const now = Date.now();
  state.totalChecks += 1;

  if (aggregated.ok) {
    const wasFiring = state.state === 'firing';
    state.upChecks += 1;
    const outageStart = state.outageStart;
    state = { ...state, state: 'ok', consecutiveFailures: 0, incidentId: null,
      lastAlertAt: 0, lastSignature: null, outageStart: 0 };
    if (wasFiring) {
      try {
        await recordEvent(env, monitor.id, {
          start: outageStart || now, end: now, durationMs: Math.max(0, now - (outageStart || now)),
          errorClass: aggregated.errorClass || 'unknown', resolved: true,
        });
      } catch (e) { console.error('记录恢复事件失败', e); }
      await dispatchAlerts(monitor, 'recovered', aggregated, state, env);
    }
  } else {
    state.downChecks += 1;
    state.consecutiveFailures += 1;
    if (state.consecutiveFailures >= threshold) {
      if (state.state !== 'firing') {
        state.state = 'firing';
        state.incidentId = crypto.randomUUID();
        state.outageStart = now;
        try {
          await recordEvent(env, monitor.id, {
            start: now, end: null, durationMs: 0, errorClass: aggregated.errorClass || 'unknown', resolved: false,
          });
        } catch (e) { console.error('记录故障事件失败', e); }
      }
      const signature = `${aggregated.status}:${aggregated.errorClass || errorClass(aggregated.error)}`;
      const shouldNotify = signature !== state.lastSignature || now - state.lastAlertAt >= cooldownMs;
      if (shouldNotify) {
        const delivered = await dispatchAlerts(monitor, 'firing', aggregated, state, env);
        // 只有至少一路成功投递才写入冷却标记；全部失败时保留旧标记，下一轮可立即重试，
        // 避免"发送失败却被当成已通知"导致故障告警永久丢失。
        if (delivered > 0) {
          state.lastAlertAt = now;
          state.lastSignature = signature;
        }
      }
    }
  }
  // 状态写回内存快照，由调用方在整轮结束时统一单次写回 KV
  snap.incident[monitor.id] = state;
  return state;
}

async function commitRound(monitor, results, env, snap) {
  const aggregated = aggregateResults(results, monitor.aggregate);
  const state = await applyIncident(monitor, aggregated, env, snap);
  const history = asArray(snap.history[monitor.id] || []);
  history.unshift({ checkedAt: new Date().toISOString(), ...aggregated, results, incidentState: state.state });
  if (history.length > MAX_HISTORY) history.length = MAX_HISTORY;
  snap.history[monitor.id] = history;
  snap.lastrun[monitor.id] = Date.now();
  return { aggregated, state };
}

// ---------- KV 快照合并（免费额度优化：每轮检测仅 1 次写入） ----------
// 所有监控的 incident / history / lastrun 合并存于 snapshot:all 单键：
// 每轮 Cron 开始时读 1 次、检测结束后写回 1 次，写入次数与监控数量解耦。
// 注意单写者原则：只有 Cron 轮次写快照；探针回传只写 probe:* 独立键，由下一轮到期时收割评估。
const SNAPSHOT_KEY = 'snapshot:all';

function emptySnapshot() {
  return { v: 1, lastrun: {}, incident: {}, history: {} };
}

/** 读取快照；键不存在（首次运行/新 KV）时从旧版分散键迁移，避免历史数据丢失 */
async function loadSnapshot(env, monitors) {
  const snap = asObject(await getJson(env.KV, SNAPSHOT_KEY, {}));
  if (snap.v === 1) {
    snap.lastrun = asObject(snap.lastrun);
    snap.incident = asObject(snap.incident);
    snap.history = asObject(snap.history);
    return snap;
  }
  const fresh = emptySnapshot();
  await Promise.all(monitors.map(async (m) => {
    fresh.incident[m.id] = { ...defaultIncident(), ...asObject(await getJson(env.KV, `incident:${m.id}`, {})) };
    fresh.history[m.id] = asArray(await getJson(env.KV, `history:${m.id}`, []));
    fresh.lastrun[m.id] = Number(await getJson(env.KV, `lastrun:${m.id}`, 0)) || 0;
  }));
  return fresh;
}

/** 整份快照单次写回（替代旧版每监控 3 次 put） */
function saveSnapshot(env, snap) {
  return env.KV.put(SNAPSHOT_KEY, JSON.stringify(snap));
}

/** 到期监控项：edge 线路即时探测；external 线路读取最近上报 */
async function runDueChecks(env, force = false) {
  const monitors = await getMonitors(env);
  const now = Date.now();
  const snap = await loadSnapshot(env, monitors);
  const candidates = monitors.filter((m) => m.enabled).map((m) => ({
    m, intervalMs: Math.max(60, m.intervalSec || 60) * 1000,
  }));
  const due = candidates
    .filter(({ m, intervalMs }) => force || now - (Number(snap.lastrun[m.id]) || 0) >= intervalMs)
    .map(({ m }) => m);
  if (!due.length) return [];

  const rounds = await Promise.all(due.map(async (m) => {
    const results = [];
    for (const probe of m.probes || []) {
      if (probe.type === 'edge') {
        results.push(await probeOnce(m, env));
      } else {
        const report = asObject(await getJson(env.KV, `probe:${m.id}:${probe.id}`, null));
        const freshMs = Math.max(120, m.intervalSec * 3) * 1000;
        if (report.receivedAt && now - report.receivedAt <= freshMs) {
          results.push({ ...report, errorClass: report.errorClass || errorClass(report.error), attempts: report.attempts || 1 });
        } else {
          results.push({
            probeId: probe.id, region: probe.region, ok: false, status: 0,
            latencyMs: 0, error: 'probe-stale', errorClass: 'probe-missing', attempts: 0,
            checkedAt: new Date().toISOString(),
          });
        }
      }
    }
    return { id: m.id, ...(await commitRound(m, results, env, snap)) };
  }));
  await saveSnapshot(env, snap); // 整轮仅 1 次 KV 写入
  return rounds;
}

// ---------- 鉴权（仅探针回传仍需令牌；配置接口已移除） ----------
function bearer(request) {
  const h = request.headers.get('authorization') || '';
  const token = h.startsWith('Bearer ') ? h.slice(7) : '';
  return /\s/.test(token) ? '' : token;
}
function isProbe(request, env) { return !!env.PROBE_TOKEN && safeEqual(bearer(request), env.PROBE_TOKEN); }

// ---------- 入口（只读） ----------
/** @param {any} env */
export function createWorker(env) {
  async function fetchHandler(request) {
    const url = new URL(request.url);
    const path = url.pathname;
    const method = request.method;

    if (path === '/' && method === 'GET') return text(dashboardHtml());
    if (path === '/app.css' && method === 'GET') return text(APP_CSS, 200, 'text/css; charset=utf-8');
    if (path === '/app.js' && method === 'GET') return text(APP_JS, 200, 'application/javascript; charset=utf-8');

    if (path === '/api/status' && method === 'GET') {
      return json(await getStatusPayload(env), 200, { 'Cache-Control': 'no-store, max-age=0' });
    }

    // 只读模式：任何修改监控配置的接口一律禁用（含历史接口，避免暴露内部数据）
    if (path === '/api/monitors' || path.startsWith('/api/monitors/') || path === '/api/check'
      || /^\/api\/monitors\/[^/]+\/history$/.test(path)) {
      return json({ error: '只读模式：监控目标由服务端配置统一管理，不支持修改' }, 405);
    }

    // 探针任务：仅返回分配给该探针的非敏感字段；附带新检测参数供探针侧一致判定
    if (path === '/api/probes/tasks' && method === 'GET') {
      if (!isProbe(request, env)) return json({ error: '未授权' }, 401);
      const probeId = url.searchParams.get('probeId') || '';
      const monitors = await getMonitors(env);
      const tasks = monitors.filter((m) => m.enabled && (m.probes || []).some((p) => p.id === probeId && p.type === 'external'))
        .map((m) => ({
          id: m.id, url: m.url, method: m.method, expectedStatus: m.expectedStatus,
          expectedCodes: m.expectedCodes, headers: m.headers, body: m.body,
          responseKeyword: m.responseKeyword, responseForbiddenKeyword: m.responseForbiddenKeyword,
          retries: m.retries, timeoutMs: m.timeoutMs, intervalSec: m.intervalSec, probeId,
        }));
      return json({ tasks, serverTime: Date.now() });
    }

    // 探针回传：独立令牌；只能回传当前配置中的监控项，不能改配置
    if (path === '/api/ingest' && method === 'POST') {
      if (!isProbe(request, env)) return json({ error: '未授权' }, 401);
      let body;
      try { body = await request.json(); } catch { return json({ error: 'JSON 格式错误' }, 400); }
      const id = String(body.monitorId || '').slice(0, 80);
      const probeId = String(body.probeId || '').slice(0, 40);
      const monitors = await getMonitors(env);
      const monitor = monitors.find((m) => m.id === id);
      if (!monitor || !(monitor.probes || []).some((p) => p.id === probeId && p.type === 'external')) {
        return json({ error: '未知监控项或探针' }, 404);
      }
      const rawError = typeof body.error === 'string' ? body.error.slice(0, 200) : null;
      const report = {
        probeId,
        region: String(body.region || probeId).slice(0, 40),
        ok: body.ok === true,
        status: clampInt(body.status, 0, 599, 0),
        latencyMs: clampInt(body.latencyMs, 0, 300000, 0),
        error: rawError,
        errorClass: body.ok === true ? 'ok' : (typeof body.errorClass === 'string' ? body.errorClass.slice(0, 32) : errorClass(rawError)),
        attempts: clampInt(body.attempts, 0, 5, 1),
        checkedAt: new Date().toISOString(),
        receivedAt: Date.now(),
      };
      await env.KV.put(`probe:${id}:${probeId}`, JSON.stringify(report));
      // 单写者原则：探针结果只落 probe:* 独立键，快照仅由 Cron 轮次在到期时
      // 读取并评估（external 线路取新鲜上报），避免 ingest 与 Cron 并发写快照互相覆盖。
      return json({ ok: true, stored: true });
    }

    return json({ error: '未找到' }, 404);
  }

  async function scheduledHandler() { await runDueChecks(env, false); }
  return { fetch: fetchHandler, scheduled: scheduledHandler };
}

export { runDueChecks };

export default {
  async fetch(request, env) { return createWorker(env).fetch(request); },
  async scheduled(controller, env) { await createWorker(env).scheduled(controller); },
};

