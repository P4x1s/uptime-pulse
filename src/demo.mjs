/**
 * UptimePulse - 核心库 + Demo Worker（只读版）
 *
 * 监控目标统一在 src/config.mjs 的 MONITORS 数组中集中维护（改代码 + 重新部署即生效）。
 * 告警通知地址与开关来自环境变量（resolveAlertConfig），不在代码中写死。
 * 服务端读取配置生成监控列表；前端只读展示；不提供任何修改监控配置的接口或入口。
 * 同一份代码可部署为 Worker，也可由 scripts/dev-server.mjs 本地运行。
 */
import { MONITORS, resolveAlertConfig, buildWebhookBody } from './config.mjs';

// ---------- 常量与类型 ----------
const SECURITY_HEADERS = {
  'X-Content-Type-Options': 'nosniff',
  'Referrer-Policy': 'no-referrer',
  'X-Frame-Options': 'DENY',
  'Content-Security-Policy': "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; connect-src 'self'; img-src 'self' data:; object-src 'none'; base-uri 'none'; frame-ancestors 'none'",
};
const MAX_HISTORY = 500;
const MAX_TARGETS = 100;
const encoder = new TextEncoder();
const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/;

/**
 * @typedef {{id:string,name:string,url:string,method:string,expectedStatus:number,timeoutMs:number,intervalSec:number,failureThreshold:number,alertCooldownSec:number,aggregate:string,probes:Array,webhookUrl:string,emailTo:string,enabled:boolean}} Monitor
 * @typedef {{probeId:string,region:string,ok:boolean,status:number,latencyMs:number,error:string|null,checkedAt:string}} ProbeResult
 * @typedef {{state:'ok'|'firing',consecutiveFailures:number,incidentId:string|null,lastAlertAt:number,lastSignature:string|null}} IncidentState
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

/** 判断 IP 是否属于私网 / 保留地址（含 IPv4-mapped IPv6 的十进制与十六进制写法） */
function isPrivateIp(input) {
  let ip = String(input).toLowerCase().trim().replace(/^\[/, '').replace(/\]$/, '');
  if (ip.startsWith('::ffff:')) {
    const rest = ip.slice(7);
    const parts = rest.split(':');
    if (parts.length === 2 && !rest.includes('.')) {
      const hi = parseInt(parts[0], 16), lo = parseInt(parts[1], 16);
      if (Number.isFinite(hi) && Number.isFinite(lo)) {
        return isPrivateIp(`${hi >> 8}.${hi & 255}.${lo >> 8}.${lo & 255}`);
      }
    }
    return isPrivateIp(rest);
  }
  const v4 = ip.match(/^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/);
  if (v4) {
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
  if (/^[0-9]+$/.test(host) || /^0x[0-9a-f]+$/i.test(host)) throw new Error('禁止使用混淆 IP 写法');
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
  return {
    id, name, url,
    type: ['website', 'api', 'service'].includes(raw.type) ? raw.type : 'website',
    group: String(raw.group || 'Public').slice(0, 60),
    alertEnabled: raw.alertEnabled !== false,
    method: raw.method === 'HEAD' ? 'HEAD' : 'GET',
    expectedStatus: clampInt(raw.expectedStatus, 100, 599, 200),
    timeoutMs: clampInt(raw.timeoutMs, 1000, 30000, 5000),
    intervalSec: clampInt(raw.intervalSec, 60, 86400, 60),
    failureThreshold: clampInt(raw.failureThreshold, 1, 20, 3),
    alertCooldownSec: clampInt(raw.alertCooldownSec ?? 300, 0, 86400, 300),
    aggregate: raw.aggregate === 'all' ? 'all' : 'any',
    probes: normalizeProbes(raw.probes),
    webhookUrl: typeof raw.webhookUrl === 'string' ? raw.webhookUrl.slice(0, 2048) : '',
    emailTo,
    enabled: raw.enabled !== false,
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
async function probeOnce(monitor, env) {
  const started = Date.now();
  const region = env.PROBE_REGION || 'cf-edge';
  let status = 0, error = null, ok = false;
  try {
    const target = await assertPublicTarget(monitor.url, env.resolveDns || dohResolve);
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), monitor.timeoutMs || 5000);
    let resp;
    try {
      resp = await (env.fetchImpl || fetch)(target.toString(), {
        method: monitor.method || 'GET',
        redirect: 'manual',
        signal: controller.signal,
        headers: { 'user-agent': 'UptimePulse/1.0 (+monitor)', accept: '*/*' },
      });
    } finally { clearTimeout(timer); }
    status = resp.status;
    ok = status === (monitor.expectedStatus || 200);
    if (resp.body) await resp.body.cancel().catch(() => {});
  } catch (e) {
    error = e && e.name === 'AbortError' ? 'timeout' : String((e && e.message) || e).slice(0, 200);
  }
  return {
    probeId: `${region}-${monitor.id}`,
    region,
    ok,
    status,
    latencyMs: Date.now() - started,
    error,
    checkedAt: new Date().toISOString(),
  };
}

/** 动态错误文本归一化为稳定类别，避免错误文案变化导致去重失效（告警风暴） */
function errorClass(error) {
  if (!error) return 'http';
  const e = String(error).toLowerCase();
  if (e.includes('timeout') || e.includes('abort')) return 'timeout';
  if (e.includes('no-probe-data') || e.includes('stale') || e.includes('probe-missing')) return 'probe-missing';
  if (e.includes('dns') || e.includes('resolve') || e.includes('enotfound')) return 'dns';
  if (e.includes('tls') || e.includes('certificate') || e.includes('ssl')) return 'tls';
  return 'network';
}

// ---------- 告警 ----------
async function sendWebhook(monitor, type, record, state, env) {
  const cfg = resolveAlertConfig(env);
  const url = (monitor.alertEnabled !== false && monitor.webhookUrl) ? monitor.webhookUrl : cfg.webhook.url;
  if (!cfg.webhook.enabled || !url) return;
  const target = await assertPublicTarget(url, env.resolveDns || dohResolve);
  const alert = {
    type,
    monitor: { id: monitor.id, name: monitor.name, url: monitor.url },
    result: record,
    state,
    timestamp: new Date().toISOString(),
  };
  // 兼容 Server酱 .send（body 必须含 title/desp）与标准 JSON Webhook/ntfy 原生端点
  const built = buildWebhookBody(url, alert);
  const body = JSON.stringify(built.body);
  const secret = cfg.signingSecret;
  const headers = { 'content-type': 'application/json', 'user-agent': 'UptimePulse/1.0 (+alert)' };
  if (secret) headers['x-uptimepulse-signature'] = `sha256=${await hmacSign(body, secret)}`;
  await (env.fetchImpl || fetch)(target.toString(), { method: 'POST', headers, body });
}

/** @returns {Promise<IncidentState>} */
async function applyIncident(monitor, record, env) {
  const key = `incident:${monitor.id}`;
  let state = await getJson(env.KV, key, {
    state: 'ok', consecutiveFailures: 0, incidentId: null, lastAlertAt: 0, lastSignature: null,
  });
  // Workers 变量 ALERT_FAILURE_THRESHOLD 优先；未设置时沿用监控项自身阈值（默认 3）
  const alertCfg = resolveAlertConfig(env);
  const threshold = alertCfg.failureThreshold ?? Math.max(1, monitor.failureThreshold || 3);
  const cooldownMs = Math.max(0, monitor.alertCooldownSec ?? 300) * 1000;

  if (record.ok) {
    const wasFiring = state.state === 'firing';
    state = { state: 'ok', consecutiveFailures: 0, incidentId: null, lastAlertAt: 0, lastSignature: null };
    if (wasFiring) {
      try { await sendWebhook(monitor, 'recovered', record, state, env); } catch (e) { console.error('通知恢复失败', e); }
    }
  } else {
    state.consecutiveFailures += 1;
    if (state.consecutiveFailures >= threshold) {
      if (state.state !== 'firing') {
        state.state = 'firing';
        state.incidentId = crypto.randomUUID();
      }
      const signature = `${record.status}:${errorClass(record.error)}`;
      const now = Date.now();
      const shouldNotify = signature !== state.lastSignature || now - state.lastAlertAt >= cooldownMs;
      if (shouldNotify) {
        try {
          await sendWebhook(monitor, 'firing', record, state, env);
          state.lastAlertAt = now;
          state.lastSignature = signature;
        } catch (e) { console.error('告警发送失败', e); }
      }
    }
  }
  await env.KV.put(key, JSON.stringify(state));
  return state;
}

async function runCheck(env, monitor) {
  const record = await probeOnce(monitor, env);
  const state = await applyIncident(monitor, record, env);
  const history = await getJson(env.KV, `history:${monitor.id}`, []);
  history.unshift({ ...record, incidentState: state.state });
  if (history.length > MAX_HISTORY) history.length = MAX_HISTORY;
  await env.KV.put(`history:${monitor.id}`, JSON.stringify(history));
  await env.KV.put(`lastrun:${monitor.id}`, Date.now());
  return { record, state };
}

async function runDueChecks(env, force = false) {
  const monitors = await getMonitors(env);
  const now = Date.now();
  const results = [];
  for (const m of monitors) {
    if (!m.enabled) continue;
    const intervalMs = Math.max(60, m.intervalSec || 60) * 1000;
    const lastRun = Number(await getJson(env.KV, `lastrun:${m.id}`, 0)) || 0;
    if (!force && now - lastRun < intervalMs) continue;
    results.push({ id: m.id, ...(await runCheck(env, m)) });
  }
  return results;
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

/** 状态接口数据（demo 与完整版共用），history 供状态条与响应时间曲线渲染 */
async function getStatusPayload(env) {
  const monitors = await getMonitors(env);
  const out = [], recentErrors = [];
  for (const m of monitors) {
    if (!m.enabled) continue; // 禁用项不检测、不展示
    const history = await getJson(env.KV, `history:${m.id}`, []);
    const incident = await getJson(env.KV, `incident:${m.id}`, { state: 'ok', consecutiveFailures: 0 });
    const okCount = history.filter((h) => h.ok).length;
    out.push({
      id: m.id, name: m.name, url: m.url, enabled: m.enabled, type: m.type, group: m.group,
      state: incident.state, consecutiveFailures: incident.consecutiveFailures,
      last: history[0] || null,
      uptime: history.length ? okCount / history.length : 1, samples: history.length,
      history: history.slice(0, 120).map(historyPoint),
    });
    if (history[0] && !history[0].ok) {
      const failed = (history[0].results && history[0].results.length)
        ? history[0].results.filter((r) => !r.ok)
        : [history[0]];
      for (const r of failed) {
        recentErrors.push({ checkedAt: history[0].checkedAt, monitorName: m.name || m.url, region: r.region, status: r.status, error: r.error });
      }
    }
  }
  return { monitors: out, recentErrors: recentErrors.slice(0, 30), serverTime: new Date().toISOString() };
}

function dashboardHtml() {
  return `<!doctype html>
<html lang="zh-CN"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>服务状态 · UptimePulse</title><link rel="stylesheet" href="/app.css"></head><body>
<main class="page">
  <header class="hero">
    <div id="heroIcon" class="badge ok">
      <svg id="icoOk" class="ico" viewBox="0 0 48 48" aria-hidden="true"><circle cx="24" cy="24" r="19" fill="none" stroke="currentColor" stroke-width="3.5"/><path d="M15 24.5l6 6 12-13" fill="none" stroke="currentColor" stroke-width="3.8" stroke-linecap="round" stroke-linejoin="round"/></svg>
      <svg id="icoBad" class="ico" viewBox="0 0 48 48" aria-hidden="true" style="display:none"><circle cx="24" cy="24" r="19" fill="none" stroke="currentColor" stroke-width="3.5"/><path d="M24 14v13M24 32v2" stroke="currentColor" stroke-width="4" stroke-linecap="round"/></svg>
    </div>
    <h1 id="heroTitle">系统一切正常</h1>
    <p class="sub">最后更新于: <span id="updatedAt">—</span> (<span id="age">0</span> 秒前)</p>
  </header>
  <div id="groups"></div>
  <footer class="foot">UptimePulse · 只读状态面板 · 监控项由服务端统一维护 <span id="msg" class="msg"></span></footer>
</main><script src="/app.js" defer></script></body></html>`;
}

const APP_CSS = `:root{color-scheme:light}*{box-sizing:border-box}
body{margin:0;background:#fff;color:#1f2937;font:14px/1.5 -apple-system,BlinkMacSystemFont,"Segoe UI","PingFang SC","Microsoft YaHei",sans-serif}
.page{max-width:920px;margin:0 auto;padding:34px 20px 48px}
.hero{text-align:center;margin-bottom:26px}
.badge{width:52px;height:52px;margin:0 auto 16px;color:#16a34a}.badge.bad{color:#dc2626}.ico{width:52px;height:52px;display:block}
.hero h1{font-size:30px;line-height:1.25;font-weight:800;letter-spacing:-.5px;margin:0 0 10px;color:#111827}
.hero .sub{color:#6b7280;font-size:13px;margin:0}
.card{background:#fafbfc;border:1px solid #e5e8ee;border-radius:10px;margin-bottom:18px;overflow:hidden}
.group-head{display:flex;align-items:center;justify-content:space-between;padding:14px 18px;background:#f3f5f8}
.group-title{display:flex;align-items:center;gap:8px;font-weight:700;font-size:14px;color:#1f2937}
.group-title svg{width:16px;height:16px;color:#2563eb}
.group-right{display:flex;align-items:center;gap:10px;font-size:13px;font-weight:600}
.online{color:#16a34a}.offline{color:#dc2626}
.toggle{border:0;background:transparent;color:#6b7280;font-size:16px;cursor:pointer;padding:0 2px;line-height:1}
.group-body.collapsed{display:none}
.monitor{border-top:1px solid #eceff3;padding:14px 18px 16px}
.monitor-head{display:flex;align-items:center;gap:8px}
.monitor-head .ico{width:18px;height:18px;flex:none;color:#16a34a}
.monitor-head .ico.bad{color:#dc2626}
.mon-name{color:#111827;font-weight:700;font-size:14px;text-decoration:underline;text-underline-offset:2px}
.tag{font-size:11px;color:#6b7280;border:1px solid #dfe3ea;border-radius:4px;padding:0 5px}
.rate{margin-left:auto;color:#16a34a;font-weight:700;font-size:13px;white-space:nowrap}
.rate.bad{color:#dc2626}
.bars{display:flex;gap:1px;height:16px;margin:10px 0 8px}
.bar{flex:1;min-width:2px;background:#22c55e;border-radius:1px}
.bar.down{background:#ef4444}.bar.warn{background:#f59e0b}
.chart-label{font-size:11px;color:#6b7280;margin-bottom:2px}
.spark{display:block;width:100%;height:82px}
.spark .grid{stroke:#e8ebf0;stroke-width:1}
.spark .line{fill:none;stroke:#64748b;stroke-width:1.6;stroke-linejoin:round;stroke-linecap:round}
.spark .axis{fill:#9aa2ae;font-size:10px;font-family:inherit}
.muted{color:#9aa2ae}.small{font-size:12px}
.empty{padding:24px;text-align:center;color:#9aa2ae;font-size:13px}
.foot{text-align:center;color:#9aa2ae;font-size:11px;margin-top:22px}
.msg{color:#dc2626;margin-left:6px}
@media(max-width:640px){.page{padding:22px 12px 36px}.hero h1{font-size:24px}.monitor{padding:12px}.group-head{padding:12px}.rate{font-size:12px}}`;

const APP_JS = `var $=function(id){return document.getElementById(id)};
var NS='http://www.w3.org/2000/svg';
var lastUpdate=0;
function el(tag,text,cls){var n=document.createElement(tag);if(cls)n.className=cls;if(text!==undefined&&text!==null)n.textContent=String(text);return n}
function sv(tag,attrs){var n=document.createElementNS(NS,tag);for(var k in attrs)n.setAttribute(k,attrs[k]);return n}
function axis(x,y,txt,anchor){var t=sv('text',{x:x,y:y,'class':'axis'});if(anchor)t.setAttribute('text-anchor',anchor);t.textContent=txt;return t}
function hour(ms){var d=new Date(ms),h=d.getHours();return (h%12||12)+(h<12?'AM':'PM')}
function nice(v){v=Math.max(1,Number(v)||1);var e=Math.pow(10,Math.floor(Math.log10(v))),n=v/e;var m=n<=1?1:n<=2?2:n<=2.5?2.5:n<=5?5:10;return m*e}
function seq(hist){return (hist||[]).slice(0,90).reverse()}
function okState(m){return m.state==='ok'&&(!m.last||m.last.ok!==false)}
function icon(ok){var s=sv('svg',{viewBox:'0 0 24 24','class':ok?'ico':'ico bad'});s.appendChild(sv('circle',{cx:12,cy:12,r:10,fill:'none',stroke:'currentColor','stroke-width':2}));if(ok){s.appendChild(sv('path',{d:'M7 12.4l3.2 3.2L17 9',fill:'none',stroke:'currentColor','stroke-width':2.2,'stroke-linecap':'round','stroke-linejoin':'round'}))}else{s.appendChild(sv('path',{d:'M12 7v7M12 17v1',stroke:'currentColor','stroke-width':2.4,'stroke-linecap':'round'}))}return s}
function globe(){var s=sv('svg',{viewBox:'0 0 24 24'});s.appendChild(sv('circle',{cx:12,cy:12,r:9,fill:'none',stroke:'currentColor','stroke-width':2}));s.appendChild(sv('path',{d:'M3 12h18M12 3c3 3 3 15 0 18M12 3c-3 3-3 15 0 18',fill:'none',stroke:'currentColor','stroke-width':1.6}));return s}
function bars(hist){var box=el('div',null,'bars'),data=seq(hist);if(!data.length){box.appendChild(el('span','暂无检测数据','muted small'));return box}var okLat=data.filter(function(p){return p.ok}).map(function(p){return p.latencyMs||0}).sort(function(a,b){return a-b});var med=okLat.length?okLat[Math.floor(okLat.length/2)]:0;data.forEach(function(p){var cls=p.ok?(med&&p.latencyMs>med*2?'bar warn':'bar'):'bar down';var b=el('span','',cls);b.title=(p.ok?'正常':'异常')+' / '+(p.latencyMs||0)+'ms / '+p.checkedAt;box.appendChild(b)});return box}
function chart(hist){var wrap=el('div',null,'chart');wrap.appendChild(el('div','chart-label','响应时间(ms)'));var pts=seq(hist).map(function(p){return {t:Date.parse(p.checkedAt),v:Number(p.latencyMs)||0}}).filter(function(p){return isFinite(p.t)});if(pts.length<2){wrap.appendChild(el('div','muted small','暂无足够数据绘制曲线'));return wrap}
var W=820,H=82,L=38,R=8,T=6,B=18,max=nice(Math.max.apply(null,pts.map(function(p){return p.v})));var svg=sv('svg',{viewBox:'0 0 '+W+' '+H,preserveAspectRatio:'none','class':'spark'});
[1,0.5,0].forEach(function(f){var y=T+(1-f)*(H-T-B);svg.appendChild(sv('line',{x1:L,y1:y,x2:W-R,y2:y,'class':'grid'}));svg.appendChild(axis(L-5,y+3,String(Math.round(max*f)),'end'))});
var coords=pts.map(function(p,i){var x=L+i/(pts.length-1)*(W-L-R),y=T+(1-Math.min(1,p.v/max))*(H-T-B);return x+','+y}).join(' ');svg.appendChild(sv('polyline',{points:coords,'class':'line'}));
var steps=Math.min(7,pts.length-1);for(var i=0;i<=steps;i++){var idx=Math.round(i/steps*(pts.length-1)),x=L+idx/(pts.length-1)*(W-L-R);svg.appendChild(axis(x,H-4,hour(pts[idx].t),'middle'))}
wrap.appendChild(svg);return wrap}
function monitor(m){var row=el('article',null,'monitor'),head=el('div',null,'monitor-head'),ok=okState(m);head.appendChild(icon(ok));var nm=el('a',m.name||m.url,'mon-name');nm.href=m.url||'#';nm.target='_blank';nm.rel='noopener noreferrer';head.appendChild(nm);if(m.type&&m.type!=='website')head.appendChild(el('span',m.type,'tag'));head.appendChild(el('span','总可用率: '+((m.uptime||0)*100).toFixed(1)+'%',ok?'rate':'rate bad'));row.appendChild(head);row.appendChild(bars(m.history));row.appendChild(chart(m.history));return row}
function group(name,list){var card=el('section',null,'card'),head=el('div',null,'group-head'),title=el('div',null,'group-title');title.appendChild(globe());title.appendChild(el('span',name));var online=list.filter(okState).length,right=el('div',null,'group-right');right.appendChild(el('span',online+'/'+list.length+' 在线',online===list.length?'online':'offline'));var btn=el('button','','toggle');btn.type='button';btn.textContent='⌃';btn.setAttribute('aria-label','折叠或展开分组');var body=el('div',null,'group-body');btn.addEventListener('click',function(){body.classList.toggle('collapsed');btn.textContent=body.classList.contains('collapsed')?'⌄':'⌃'});right.appendChild(btn);head.appendChild(title);head.appendChild(right);card.appendChild(head);list.forEach(function(m){body.appendChild(monitor(m))});card.appendChild(body);return card}
function render(d){var ms=d.monitors||[],allOk=ms.length>0&&ms.every(okState);var badge=$('heroIcon');badge.className='badge '+(allOk?'ok':'bad');$('icoOk').style.display=allOk?'':'none';$('icoBad').style.display=allOk?'none':'';$('heroTitle').textContent=allOk?'系统一切正常':'部分服务异常';
lastUpdate=Date.parse(d.serverTime)||Date.now();$('updatedAt').textContent=new Date(lastUpdate).toLocaleString('zh-CN',{year:'numeric',month:'2-digit',day:'2-digit',hour:'2-digit',minute:'2-digit',second:'2-digit',hour12:false});age();
var groups={},order=[];ms.forEach(function(m){var g=m.group||'Public';if(!groups[g]){groups[g]=[];order.push(g)}groups[g].push(m)});var host=$('groups');host.textContent='';if(!ms.length){host.appendChild(el('div','尚未配置监控项','empty'));return}order.forEach(function(g){host.appendChild(group(g,groups[g]))})}
function age(){if(lastUpdate)$('age').textContent=String(Math.max(0,Math.floor((Date.now()-lastUpdate)/1000)))}
async function load(){var r;try{r=await fetch('/api/status',{headers:{accept:'application/json'}})}catch(e){$('msg').textContent='网络异常';return}if(!r.ok){$('msg').textContent='加载失败 '+r.status;return}var d=await r.json();$('msg').textContent='';render(d)}
$('refresh')&&($('refresh').onclick=load);load();setInterval(load,30000);setInterval(age,1000);`;

// ---------- 路由与入口（只读） ----------
/** @param {any} env */
export function createWorker(env) {
  async function fetchHandler(request) {
    const url = new URL(request.url);
    const path = url.pathname;

    if (path === '/' && request.method === 'GET') return text(dashboardHtml());
    if (path === '/app.css' && request.method === 'GET') return text(APP_CSS, 200, 'text/css; charset=utf-8');
    if (path === '/app.js' && request.method === 'GET') return text(APP_JS, 200, 'application/javascript; charset=utf-8');

    if (path === '/api/status' && request.method === 'GET') return json(await getStatusPayload(env));

    // 只读模式：任何修改监控配置的接口一律禁用
    if (path === '/api/monitors' || path.startsWith('/api/monitors/') || path === '/api/check') {
      return json({ error: '只读模式：监控目标由服务端配置统一管理，不支持修改' }, 405);
    }

    return json({ error: '未找到' }, 404);
  }

  async function scheduledHandler() { await runDueChecks(env, false); }
  return { fetch: fetchHandler, scheduled: scheduledHandler };
}

export {
  isPrivateIp, safeEqual, assertPublicTarget, hmacSign, dohResolve, getJson,
  getMonitors, parseTargets, clampInt, normalizeProbes, probeOnce, errorClass,
  applyIncident, runCheck, runDueChecks, dashboardHtml, APP_CSS, APP_JS,
  getStatusPayload, historyPoint,
};

export default {
  async fetch(request, env) { return createWorker(env).fetch(request); },
  async scheduled(controller, env) { await createWorker(env).scheduled(controller); },
};
