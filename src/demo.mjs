/**
 * UptimePulse - Demo 单文件 Worker
 * 阶段 A：配置 CRUD / SSRF 防护 / 检测 / Webhook 告警(阈值+去重+恢复) / 极简页面
 * 同一份代码可部署到 Cloudflare Workers，也可由 scripts/dev-server.mjs 在本地 Node 运行。
 */

// ---------- 类型（JSDoc，便于编辑器推断，无需构建） ----------
/**
 * @typedef {{id:string,name:string,url:string,method:string,expectedStatus:number,timeoutMs:number,intervalSec:number,failureThreshold:number,alertCooldownSec:number,webhookUrl:string,enabled:boolean,createdAt:string,lastRunAt:number}} Monitor
 * @typedef {{probeId:string,region:string,ok:boolean,status:number,latencyMs:number,error:string|null,checkedAt:string}} ProbeResult
 * @typedef {{state:'ok'|'firing',consecutiveFailures:number,incidentId:string|null,lastAlertAt:number,lastSignature:string|null}} IncidentState
 */

const SECURITY_HEADERS = {
  'X-Content-Type-Options': 'nosniff',
  'Referrer-Policy': 'no-referrer',
  'X-Frame-Options': 'DENY',
  'Content-Security-Policy': "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; connect-src 'self'; img-src 'self' data:; object-src 'none'; base-uri 'none'; frame-ancestors 'none'",
};

const MAX_HISTORY = 500;
const encoder = new TextEncoder();

function json(data, status = 200, extra = {}) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { 'content-type': 'application/json; charset=utf-8', ...SECURITY_HEADERS, ...extra },
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
      // IPv4-mapped IPv6 十六进制写法：::ffff:7f00:1 -> 127.0.0.1
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
    if (a === 100 && b >= 64 && b <= 127) return true; // CGNAT
    if (a === 192 && b === 0) return true; // IETF protocol assignments
    if (a === 198 && (b === 18 || b === 19)) return true; // benchmark
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
 * @param {string} raw
 * @param {(host:string)=>Promise<string[]>} resolveDns
 */
async function assertPublicTarget(raw, resolveDns) {
  if (typeof raw !== 'string' || raw.length > 2048) throw new Error('URL 无效或过长');
  let u;
  try { u = new URL(raw); } catch { throw new Error('URL 格式错误'); }
  if (u.protocol !== 'http:' && u.protocol !== 'https:') throw new Error('仅支持 http/https 协议');
  if (u.username || u.password) throw new Error('URL 不允许包含凭据');
  // URL.hostname 对 IPv6 会保留方括号，需先剥离再判断
  const host = u.hostname.toLowerCase().replace(/^\[|\]$/g, '').replace(/\.$/, '');
  if (!host) throw new Error('缺少主机名');
  // 纯数字 / 十六进制主机名是 IP 的混淆写法（如 2130706433 = 127.0.0.1），直接拒绝
  if (/^[0-9]+$/.test(host) || /^0x[0-9a-f]+$/i.test(host)) throw new Error('禁止使用混淆 IP 写法');

  // 明文 IP 字面量：直接判定
  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(host) || host.includes(':')) {
    if (isPrivateIp(host)) throw new Error('目标 IP 属于内网/保留地址');
    return u;
  }
  // 域名黑名单
  const blockedSuffix = ['.localhost', '.local', '.internal', '.lan', '.home.arpa', '.test', '.invalid'];
  if (host === 'localhost' || blockedSuffix.some((s) => host.endsWith(s))) throw new Error('禁止访问内网域名');

  // DNS 解析后校验：阻止域名指向内网（DNS rebinding 的基础防护）
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

// ---------- 存储层 ----------
async function getJson(kv, key, fallback) {
  try { const v = await kv.get(key, 'json'); return v === null ? fallback : v; } catch { return fallback; }
}
async function listMonitors(env) {
  const ids = await getJson(env.KV, 'monitor:index', []);
  const out = [];
  for (const id of ids) {
    const m = await getJson(env.KV, `monitor:${id}`, null);
    if (m) out.push(m);
  }
  return out;
}
async function saveMonitor(env, monitor) {
  const ids = await getJson(env.KV, 'monitor:index', []);
  if (!ids.includes(monitor.id)) ids.push(monitor.id);
  await env.KV.put('monitor:index', JSON.stringify(ids));
  await env.KV.put(`monitor:${monitor.id}`, JSON.stringify(monitor));
}

// ---------- 检测引擎 ----------
/** @returns {Promise<ProbeResult>} */
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
        headers: { 'user-agent': 'UptimePulse/0.1 (+monitor)', accept: '*/*' },
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

// ---------- 告警 ----------
async function sendWebhook(monitor, type, record, state, env) {
  if (!env.WEBHOOK_URL) return;
  // 出站告警同样做 SSRF 校验
  const target = await assertPublicTarget(env.WEBHOOK_URL, env.resolveDns || dohResolve);
  const body = JSON.stringify({
    type, // 'firing' | 'recovered'
    monitor: { id: monitor.id, name: monitor.name, url: monitor.url },
    result: record,
    state,
    timestamp: new Date().toISOString(),
  });
  const secret = env.ALERT_SIGNING_SECRET || '';
  const headers = { 'content-type': 'application/json', 'user-agent': 'UptimePulse/0.1 (+alert)' };
  if (secret) headers['x-uptimepulse-signature'] = `sha256=${await hmacSign(body, secret)}`;
  await (env.fetchImpl || fetch)(target.toString(), { method: 'POST', headers, body });
}

/** 动态错误文本归一化为稳定类别，防止文案波动造成告警风暴 */
function errorClass(error) {
  if (!error) return 'http';
  const e = String(error).toLowerCase();
  if (e.includes('timeout') || e.includes('abort')) return 'timeout';
  if (e.includes('dns') || e.includes('resolve') || e.includes('enotfound')) return 'dns';
  if (e.includes('tls') || e.includes('certificate') || e.includes('ssl')) return 'tls';
  return 'network';
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
  const key = `history:${monitor.id}`;
  const history = await getJson(env.KV, key, []);
  history.unshift({ ...record, incidentState: state.state });
  if (history.length > MAX_HISTORY) history.length = MAX_HISTORY;
  await env.KV.put(key, JSON.stringify(history));
  monitor.lastRunAt = Date.now();
  await saveMonitor(env, monitor);
  return { record, state };
}

async function runDueChecks(env, force = false) {
  const monitors = await listMonitors(env);
  const now = Date.now();
  const results = [];
  for (const m of monitors) {
    if (!m.enabled) continue;
    const intervalMs = Math.max(60, m.intervalSec || 60) * 1000;
    if (!force && now - (m.lastRunAt || 0) < intervalMs) continue;
    results.push({ id: m.id, ...(await runCheck(env, m)) });
  }
  return results;
}

// ---------- 极简 Dashboard ----------
function dashboardHtml() {
  return `<!doctype html>
<html lang="zh-CN"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>UptimePulse</title>
<style>
:root{color-scheme:dark}*{box-sizing:border-box}body{margin:0;background:#0f1115;color:#e6e8eb;font:14px/1.5 ui-monospace,SFMono-Regular,Consolas,monospace}
main{max-width:860px;margin:0 auto;padding:28px 20px}h1{font-size:18px;margin:0 0 4px}header p{margin:0 0 20px;color:#8b93a1}
section{border:1px solid #262b36;border-radius:6px;padding:14px;margin-bottom:16px}h2{font-size:13px;margin:0 0 12px;color:#8b93a1;font-weight:600}
form{display:grid;grid-template-columns:1fr 110px 90px auto;gap:8px}input,select,button{font:inherit;padding:7px 9px;background:#171b22;color:#e6e8eb;border:1px solid #333a47;border-radius:4px}
button{cursor:pointer;background:#2b6cb0;border-color:#2b6cb0}button:hover{background:#2c5f96}
table{width:100%;border-collapse:collapse}th,td{text-align:left;padding:8px 6px;border-bottom:1px solid #262b36;font-size:13px}th{color:#8b93a1;font-weight:600}
.ok{color:#4ade80}.bad{color:#f87171}.muted{color:#6b7280}.del{background:transparent;border:none;color:#f87171;padding:2px 6px}
.actions{display:flex;gap:8px;align-items:center;margin-top:12px}#msg{color:#fbbf24}
</style></head><body><main>
<header><h1>UptimePulse</h1><p>轻量网站可用性监控 · Demo</p></header>
<section><h2>添加监控项</h2>
<form id="addForm"><input id="url" placeholder="https://example.com" required><input id="name" placeholder="名称(可选)"><input id="threshold" type="number" value="3" min="1" title="失败阈值"><button type="submit">添加</button></form>
<div class="actions"><button id="refresh">刷新</button><button id="checkNow">立即检测</button><span id="msg"></span></div>
</section>
<section><h2>当前状态</h2><table><thead><tr><th>目标</th><th>状态</th><th>HTTP</th><th>耗时</th><th>可用率</th><th>连续失败</th><th></th></tr></thead><tbody id="rows"></tbody></table></section>
<section><h2>最近异常记录</h2><table><thead><tr><th>时间</th><th>目标</th><th>线路</th><th>错误</th></tr></thead><tbody id="errors"></tbody></table></section>
</main><script>
const $=id=>document.getElementById(id);
let token='';
async function api(path,opt={}){opt.headers=opt.headers||{};if(token)opt.headers.Authorization='Bearer '+token;const r=await fetch(path,opt);if(r.status===401){token=prompt('管理员令牌：')||'';return api(path,opt)}return r}
function el(tag,text,cls){const n=document.createElement(tag);if(cls)n.className=cls;n.textContent=text??'';return n}
async function load(){const r=await api('/api/status');if(!r.ok){$('msg').textContent='加载失败 '+r.status;return}const d=await r.json();
const rows=$('rows');rows.textContent='';
for(const m of d.monitors){const tr=document.createElement('tr');const ok=m.state==='ok'&&m.last&&m.last.ok;
tr.appendChild(el('td',m.name||m.url));tr.appendChild(el('td',ok?'正常':'异常',ok?'ok':'bad'));
tr.appendChild(el('td',m.last?String(m.last.status):'-'));tr.appendChild(el('td',m.last?m.last.latencyMs+'ms':'-'));
tr.appendChild(el('td',(m.uptime*100).toFixed(1)+'%'));tr.appendChild(el('td',String(m.consecutiveFailures)));
const td=document.createElement('td');const b=el('button','删除');b.className='del';b.onclick=async()=>{await api('/api/monitors/'+encodeURIComponent(m.id),{method:'DELETE'});load()};td.appendChild(b);tr.appendChild(td);rows.appendChild(tr)}
const er=$('errors');er.textContent='';for(const e of d.recentErrors){const tr=document.createElement('tr');
tr.appendChild(el('td',e.checkedAt));tr.appendChild(el('td',e.monitorName));tr.appendChild(el('td',e.region));tr.appendChild(el('td',e.error||('HTTP '+e.status),'bad'));er.appendChild(tr)}
if(!d.monitors.length){const tr=document.createElement('tr');const td=el('td','暂无监控项','muted');td.colSpan=7;tr.appendChild(td);rows.appendChild(tr)}}
$('addForm').onsubmit=async e=>{e.preventDefault();const url=$('url').value.trim();const body={url,name:$('name').value.trim(),failureThreshold:Number($('threshold').value)||3};
const r=await api('/api/monitors',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify(body)});
const d=await r.json();$('msg').textContent=r.ok?'已添加':'添加失败: '+(d.error||r.status);if(r.ok){$('url').value='';$('name').value='';load()}};
$('refresh').onclick=load;$('checkNow').onclick=async()=>{await api('/api/check',{method:'POST'});load()};load();
</script></body></html>`;
}

// ---------- 路由与入口 ----------
function authorize(request, env) {
  if (!env.ADMIN_TOKEN) return false;
  const header = request.headers.get('authorization') || '';
  const token = header.startsWith('Bearer ') ? header.slice(7) : '';
  if (/\s/.test(token)) return false;
  return safeEqual(token, env.ADMIN_TOKEN);
}

/** @param {any} env */
export function createWorker(env) {
  async function fetchHandler(request) {
    const url = new URL(request.url);
    const path = url.pathname;
    const method = request.method;

    if (path === '/' && method === 'GET') return text(dashboardHtml());

    if (path === '/api/status' && method === 'GET') {
      const monitors = await listMonitors(env);
      const out = [], recentErrors = [];
      for (const m of monitors) {
        const history = await getJson(env.KV, `history:${m.id}`, []);
        const incident = await getJson(env.KV, `incident:${m.id}`, { state: 'ok', consecutiveFailures: 0 });
        const okCount = history.filter((h) => h.ok).length;
        out.push({
          id: m.id, name: m.name, url: m.url, enabled: m.enabled,
          state: incident.state, consecutiveFailures: incident.consecutiveFailures,
          last: history[0] || null,
          uptime: history.length ? okCount / history.length : 1,
          samples: history.length,
        });
        if (history[0] && !history[0].ok) {
          recentErrors.push({ checkedAt: history[0].checkedAt, monitorName: m.name || m.url, region: history[0].region, status: history[0].status, error: history[0].error });
        }
      }
      return json({ monitors: out, recentErrors: recentErrors.slice(0, 20), serverTime: new Date().toISOString() });
    }

    if (path === '/api/monitors' && method === 'POST') {
      if (!authorize(request, env)) return json({ error: '未授权' }, 401);
      let body;
      try { body = await request.json(); } catch { return json({ error: 'JSON 格式错误' }, 400); }
      if (!body || typeof body.url !== 'string') return json({ error: '缺少 url' }, 400);
      try { await assertPublicTarget(body.url, env.resolveDns || dohResolve); }
      catch (e) { return json({ error: '目标不安全: ' + e.message }, 400); }
      if (body.webhookUrl) {
        try { await assertPublicTarget(body.webhookUrl, env.resolveDns || dohResolve); }
        catch (e) { return json({ error: 'Webhook 不安全: ' + e.message }, 400); }
      }
      const monitor = {
        id: crypto.randomUUID(),
        name: typeof body.name === 'string' ? body.name.slice(0, 80) : '',
        url: body.url,
        method: body.method === 'HEAD' ? 'HEAD' : 'GET',
        expectedStatus: Number(body.expectedStatus) || 200,
        timeoutMs: Math.min(30000, Math.max(1000, Number(body.timeoutMs) || 5000)),
        intervalSec: Math.max(60, Number(body.intervalSec) || 60),
        failureThreshold: Math.min(20, Math.max(1, Number(body.failureThreshold) || 3)),
        alertCooldownSec: Math.min(86400, Math.max(0, Number(body.alertCooldownSec) ?? 300)),
        webhookUrl: typeof body.webhookUrl === 'string' ? body.webhookUrl : '',
        enabled: body.enabled !== false,
        createdAt: new Date().toISOString(),
        lastRunAt: 0,
      };
      await saveMonitor(env, monitor);
      return json({ ok: true, monitor }, 201);
    }

    const delMatch = path.match(/^\/api\/monitors\/([^/]+)$/);
    if (delMatch && method === 'DELETE') {
      if (!authorize(request, env)) return json({ error: '未授权' }, 401);
      const id = delMatch[1];
      const ids = await getJson(env.KV, 'monitor:index', []);
      await env.KV.put('monitor:index', JSON.stringify(ids.filter((x) => x !== id)));
      await env.KV.delete(`monitor:${id}`);
      await env.KV.delete(`history:${id}`);
      await env.KV.delete(`incident:${id}`);
      return json({ ok: true });
    }

    if (path === '/api/check' && method === 'POST') {
      if (!authorize(request, env)) return json({ error: '未授权' }, 401);
      const results = await runDueChecks(env, true);
      return json({ ok: true, results });
    }

    return json({ error: '未找到' }, 404);
  }

  async function scheduledHandler() {
    await runDueChecks(env, false);
  }

  return { fetch: fetchHandler, scheduled: scheduledHandler };
}

export { isPrivateIp, safeEqual, assertPublicTarget, hmacSign, probeOnce, applyIncident, runCheck, dashboardHtml };

/** Cloudflare Workers 默认导出（本地 dev server 不使用） */
export default {
  async fetch(request, env) { return createWorker(env).fetch(request); },
  async scheduled(controller, env) { await createWorker(env).scheduled(controller); },
};
