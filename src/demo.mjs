/**
 * UptimePulse - 核心库 + Demo Worker（只读版）
 *
 * 监控目标统一由后台变量 MONITOR_TARGETS 提供（Cloudflare Dashboard 变量/Secret）。
 * 服务端读取变量生成监控列表；前端只读展示；不提供任何修改监控配置的接口或入口。
 * 同一份代码可部署为 Worker，也可由 scripts/dev-server.mjs 本地运行。
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

/** 解析 MONITOR_TARGETS：支持 [...], 或 { "targets": [...] } */
function parseTargets(raw) {
  if (typeof raw !== 'string' || !raw.trim()) return [];
  let data;
  try { data = JSON.parse(raw); } catch (e) { console.error('MONITOR_TARGETS 解析失败：', e.message); return []; }
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

// 缓存按原始变量字符串失效：变量不变时避免重复解析，变量一改立即重新生成列表
let _configCache = { raw: null, monitors: null };
async function getMonitors(env) {
  const raw = env.MONITOR_TARGETS || '';
  if (_configCache.raw === raw && _configCache.monitors) return _configCache.monitors;
  const monitors = parseTargets(raw);
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
  if (!env.WEBHOOK_URL) return;
  const target = await assertPublicTarget(env.WEBHOOK_URL, env.resolveDns || dohResolve);
  const body = JSON.stringify({
    type,
    monitor: { id: monitor.id, name: monitor.name, url: monitor.url },
    result: record,
    state,
    timestamp: new Date().toISOString(),
  });
  const secret = env.ALERT_SIGNING_SECRET || '';
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
  const threshold = Math.max(1, monitor.failureThreshold || 3);
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
function dashboardHtml() {
  return `<!doctype html>
<html lang="zh-CN"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>UptimePulse</title><link rel="stylesheet" href="/app.css"></head><body><main>
<header><h1>UptimePulse</h1><p>轻量可用性监控 · 只读状态面板</p></header>
<section class="note">监控目标由服务端后台变量统一管理，本页仅展示检测状态，不提供任何配置修改操作。<span id="msg"></span></section>
<section><div class="bar"><h2>当前状态</h2><button id="refresh" type="button">刷新</button></div>
<table><thead><tr><th>目标</th><th>状态</th><th>线路</th><th>HTTP</th><th>耗时</th><th>可用率</th><th>连续失败</th></tr></thead><tbody id="rows"></tbody></table></section>
<section><h2>最近异常</h2><table><thead><tr><th>时间</th><th>目标</th><th>线路</th><th>错误</th></tr></thead><tbody id="errors"></tbody></table></section>
<footer id="updated" class="muted"></footer>
</main><script src="/app.js" defer></script></body></html>`;
}

const APP_CSS = `:root{color-scheme:dark}*{box-sizing:border-box}body{margin:0;background:#0f1115;color:#e6e8eb;font:14px/1.5 ui-monospace,SFMono-Regular,Consolas,monospace}
main{max-width:980px;margin:0 auto;padding:28px 20px}h1{font-size:18px;margin:0 0 4px}header p{margin:0 0 16px;color:#8b93a1}
section{border:1px solid #262b36;border-radius:6px;padding:14px;margin-bottom:16px}h2{font-size:13px;margin:0;color:#8b93a1;font-weight:600}
.note{color:#8b93a1;font-size:12px;line-height:1.6}.bar{display:flex;justify-content:space-between;align-items:center;margin-bottom:12px}
button{font:inherit;padding:6px 12px;background:#171b22;color:#e6e8eb;border:1px solid #333a47;border-radius:4px;cursor:pointer}button:hover{background:#222834}
table{width:100%;border-collapse:collapse}th,td{text-align:left;padding:8px 6px;border-bottom:1px solid #262b36;font-size:13px}th{color:#8b93a1;font-weight:600}
.ok{color:#4ade80}.bad{color:#f87171}.muted{color:#6b7280}footer{margin-top:8px;font-size:12px}`;

const APP_JS = `const $=id=>document.getElementById(id);
function el(tag,text,cls){const n=document.createElement(tag);if(cls)n.className=cls;n.textContent=text??'';return n}
async function load(){let r;try{r=await fetch('/api/status',{headers:{accept:'application/json'}})}catch(e){$('msg').textContent='网络异常';return}
if(!r.ok){$('msg').textContent='加载失败 '+r.status;return}const d=await r.json();
const rows=$('rows');rows.textContent='';
for(const m of d.monitors){const tr=document.createElement('tr');const ok=m.state==='ok'&&m.last&&m.last.ok;
tr.appendChild(el('td',m.name||m.url));tr.appendChild(el('td',ok?'正常':'异常',ok?'ok':'bad'));
const tdLine=document.createElement('td');const rs=(m.last&&m.last.results)||[];
if(rs.length){for(const x of rs){tdLine.appendChild(el('span',x.region+':'+(x.ok?'OK':'FAIL'),x.ok?'ok':'bad'));tdLine.appendChild(document.createTextNode(' '))}}else{tdLine.textContent='—';tdLine.className='muted'}
tr.appendChild(tdLine);tr.appendChild(el('td',m.last?String(m.last.status):'-'));tr.appendChild(el('td',m.last?m.last.latencyMs+'ms':'-'));
tr.appendChild(el('td',(m.uptime*100).toFixed(1)+'%'));tr.appendChild(el('td',String(m.consecutiveFailures)));rows.appendChild(tr)}
if(!d.monitors.length){const tr=document.createElement('tr');const td=el('td','后台变量中尚未配置监控目标','muted');td.colSpan=7;tr.appendChild(td);rows.appendChild(tr)}
const er=$('errors');er.textContent='';for(const e of d.recentErrors){const tr=document.createElement('tr');tr.appendChild(el('td',e.checkedAt));tr.appendChild(el('td',e.monitorName));tr.appendChild(el('td',e.region));tr.appendChild(el('td',e.error||('HTTP '+e.status),'bad'));er.appendChild(tr)}
if(!d.recentErrors.length){const tr=document.createElement('tr');const td=el('td','暂无异常记录','muted');td.colSpan=4;tr.appendChild(td);er.appendChild(tr)}
$('updated').textContent='更新于 '+new Date(d.serverTime||Date.now()).toLocaleString('zh-CN')}
$('refresh').onclick=load;load();setInterval(load,30000);`;

// ---------- 路由与入口（只读） ----------
/** @param {any} env */
export function createWorker(env) {
  async function fetchHandler(request) {
    const url = new URL(request.url);
    const path = url.pathname;

    if (path === '/' && request.method === 'GET') return text(dashboardHtml());
    if (path === '/app.css' && request.method === 'GET') return text(APP_CSS, 200, 'text/css; charset=utf-8');
    if (path === '/app.js' && request.method === 'GET') return text(APP_JS, 200, 'application/javascript; charset=utf-8');

    if (path === '/api/status' && request.method === 'GET') {
      const monitors = await getMonitors(env);
      const out = [], recentErrors = [];
      for (const m of monitors) {
        const history = await getJson(env.KV, `history:${m.id}`, []);
        const incident = await getJson(env.KV, `incident:${m.id}`, { state: 'ok', consecutiveFailures: 0 });
        const okCount = history.filter((h) => h.ok).length;
        out.push({
          id: m.id, name: m.name, url: m.url, enabled: m.enabled, probes: m.probes,
          state: incident.state, consecutiveFailures: incident.consecutiveFailures,
          last: history[0] || null,
          uptime: history.length ? okCount / history.length : 1, samples: history.length,
        });
        if (history[0] && !history[0].ok) {
          // 完整版历史项含 results[]；demo 历史项本身即单次探测结果
          const failed = (history[0].results && history[0].results.length)
            ? history[0].results.filter((r) => !r.ok)
            : [history[0]];
          for (const r of failed) {
            recentErrors.push({ checkedAt: history[0].checkedAt, monitorName: m.name || m.url, region: r.region, status: r.status, error: r.error });
          }
        }
      }
      return json({ monitors: out, recentErrors: recentErrors.slice(0, 30), serverTime: new Date().toISOString() });
    }

    // 只读模式：任何修改监控配置的接口一律禁用
    if (path === '/api/monitors' || path.startsWith('/api/monitors/') || path === '/api/check') {
      return json({ error: '只读模式：监控目标由服务端后台变量管理，不支持修改' }, 405);
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
};

export default {
  async fetch(request, env) { return createWorker(env).fetch(request); },
  async scheduled(controller, env) { await createWorker(env).scheduled(controller); },
};
