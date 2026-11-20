/**
 * UptimePulse - 完整版 Worker
 * 在 demo 基础上增加：多线路聚合、国内探针回传、邮件(Webhook/邮件)双通道、
 * 完整配置 API、历史与异常查询。安全原语复用 src/demo.mjs，避免两套实现产生分歧。
 */
import {
  assertPublicTarget, safeEqual, hmacSign, probeOnce,
} from './demo.mjs';

const SECURITY_HEADERS = {
  'X-Content-Type-Options': 'nosniff',
  'Referrer-Policy': 'no-referrer',
  'X-Frame-Options': 'DENY',
  'Content-Security-Policy': "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; connect-src 'self'; img-src 'self' data:; object-src 'none'; base-uri 'none'; frame-ancestors 'none'",
};
const MAX_HISTORY = 500;
const encoder = new TextEncoder();

function json(data, status = 200, extra = {}) {
  return new Response(JSON.stringify(data), {
    status, headers: { 'content-type': 'application/json; charset=utf-8', ...SECURITY_HEADERS, ...extra },
  });
}
function html(body) {
  return new Response(body, { headers: { 'content-type': 'text/html; charset=utf-8', ...SECURITY_HEADERS } });
}
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

// ---------- 告警通道 ----------
async function postJson(env, target, body, headers) {
  return (env.fetchImpl || fetch)(target, {
    method: 'POST', headers: { 'content-type': 'application/json', ...headers }, body,
  });
}

async function sendWebhook(url, payload, env) {
  const target = await assertPublicTarget(url, env.resolveDns);
  const body = JSON.stringify(payload);
  const headers = { 'user-agent': 'UptimePulse/1.0 (+alert)' };
  if (env.ALERT_SIGNING_SECRET) headers['x-uptimepulse-signature'] = `sha256=${await hmacSign(body, env.ALERT_SIGNING_SECRET)}`;
  await postJson(env, target.toString(), body, headers);
}

async function sendEmail(to, payload, env) {
  if (!env.RESEND_API_KEY || !env.EMAIL_FROM) return;
  // 邮件端点为硬编码可信域名，不接受用户输入
  const subject = `[UptimePulse][${payload.type === 'firing' ? '故障' : '恢复'}] ${payload.monitor.name || payload.monitor.url}`;
  const lines = [
    `类型: ${payload.type === 'firing' ? '故障' : '恢复'}`,
    `监控项: ${payload.monitor.name || payload.monitor.id}`,
    `目标: ${payload.monitor.url}`,
    `线路: ${payload.result.region}`,
    `HTTP: ${payload.result.status}`,
    `耗时: ${payload.result.latencyMs}ms`,
    `时间: ${payload.timestamp}`,
    `连续失败: ${payload.state.consecutiveFailures}`,
    payload.result.error ? `错误: ${payload.result.error}` : '',
  ].filter(Boolean);
  await postJson(env, 'https://api.resend.com/emails', JSON.stringify({
    from: env.EMAIL_FROM, to: [to], subject, text: lines.join('\n'),
  }), { authorization: `Bearer ${env.RESEND_API_KEY}` });
}

async function dispatchAlerts(monitor, type, record, state, env) {
  const payload = {
    type,
    monitor: { id: monitor.id, name: monitor.name, url: monitor.url },
    result: record,
    state,
    timestamp: new Date().toISOString(),
  };
  const jobs = [];
  if (env.WEBHOOK_URL) jobs.push(sendWebhook(env.WEBHOOK_URL, payload, env).catch((e) => console.error('全局 Webhook 失败', e)));
  if (monitor.webhookUrl) jobs.push(sendWebhook(monitor.webhookUrl, payload, env).catch((e) => console.error('监控项 Webhook 失败', e)));
  if (monitor.emailTo) jobs.push(sendEmail(monitor.emailTo, payload, env).catch((e) => console.error('邮件告警失败', e)));
  await Promise.allSettled(jobs);
}

// ---------- 状态机与聚合 ----------
function aggregateResults(results, mode) {
  if (!results.length) return { ok: false, status: 0, latencyMs: 0, error: 'no-probe-data' };
  const ok = mode === 'all' ? results.every((r) => r.ok) : results.some((r) => r.ok);
  const primary = results.find((r) => r.ok) || results[0];
  return {
    ok,
    status: primary.status,
    latencyMs: Math.max(...results.map((r) => r.latencyMs || 0)),
    error: ok ? null : (primary.error || `HTTP ${primary.status}`),
  };
}

/** 将动态错误文本归一化为稳定类别，避免错误文案变化导致去重失效（告警风暴） */
function errorClass(error) {
  if (!error) return 'http';
  const e = String(error).toLowerCase();
  if (e.includes('timeout') || e.includes('abort')) return 'timeout';
  if (e.includes('no-probe-data') || e.includes('stale') || e.includes('probe-missing')) return 'probe-missing';
  if (e.includes('dns') || e.includes('resolve') || e.includes('enotfound')) return 'dns';
  if (e.includes('tls') || e.includes('certificate') || e.includes('ssl')) return 'tls';
  return 'network';
}

async function applyIncident(monitor, aggregated, env) {
  const key = `incident:${monitor.id}`;
  let state = await getJson(env.KV, key, {
    state: 'ok', consecutiveFailures: 0, incidentId: null, lastAlertAt: 0, lastSignature: null,
  });
  const threshold = Math.max(1, monitor.failureThreshold || 3);
  const cooldownMs = Math.max(0, monitor.alertCooldownSec ?? 300) * 1000;

  if (aggregated.ok) {
    const wasFiring = state.state === 'firing';
    state = { state: 'ok', consecutiveFailures: 0, incidentId: null, lastAlertAt: 0, lastSignature: null };
    if (wasFiring) await dispatchAlerts(monitor, 'recovered', aggregated, state, env);
  } else {
    state.consecutiveFailures += 1;
    if (state.consecutiveFailures >= threshold) {
      if (state.state !== 'firing') {
        state.state = 'firing';
        state.incidentId = crypto.randomUUID();
      }
      const signature = `${aggregated.status}:${errorClass(aggregated.error)}`;
      const now = Date.now();
      if (signature !== state.lastSignature || now - state.lastAlertAt >= cooldownMs) {
        await dispatchAlerts(monitor, 'firing', aggregated, state, env);
        state.lastAlertAt = now;
        state.lastSignature = signature;
      }
    }
  }
  await env.KV.put(key, JSON.stringify(state));
  return state;
}

async function commitRound(monitor, results, env) {
  const aggregated = aggregateResults(results, monitor.aggregate);
  const state = await applyIncident(monitor, aggregated, env);
  const history = await getJson(env.KV, `history:${monitor.id}`, []);
  history.unshift({ checkedAt: new Date().toISOString(), ...aggregated, incidentState: state.state, results });
  if (history.length > MAX_HISTORY) history.length = MAX_HISTORY;
  await env.KV.put(`history:${monitor.id}`, JSON.stringify(history));
  monitor.lastRunAt = Date.now();
  await saveMonitor(env, monitor);
  return { aggregated, state };
}

/** 到期监控项：edge 线路即时探测；external 线路读取最近上报 */
async function runDueChecks(env, force = false) {
  const monitors = await listMonitors(env);
  const now = Date.now();
  const output = [];
  for (const m of monitors) {
    if (!m.enabled) continue;
    const intervalMs = Math.max(60, m.intervalSec || 60) * 1000;
    if (!force && now - (m.lastRunAt || 0) < intervalMs) continue;
    const results = [];
    for (const probe of m.probes || []) {
      if (probe.type === 'edge') {
        results.push(await probeOnce(m, env));
      } else {
        const report = await getJson(env.KV, `probe:${m.id}:${probe.id}`, null);
        const freshMs = Math.max(120, m.intervalSec * 3) * 1000;
        if (report && now - report.receivedAt <= freshMs) results.push(report);
        else results.push({
          probeId: probe.id, region: probe.region, ok: false, status: 0,
          latencyMs: 0, error: 'probe-stale', checkedAt: new Date().toISOString(),
        });
      }
    }
    output.push({ id: m.id, ...(await commitRound(m, results, env)) });
  }
  return output;
}

// ---------- 输入校验 ----------
const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/;
function clampInt(value, min, max, fallback) {
  const n = Number(value);
  if (!Number.isFinite(n)) return fallback;
  return Math.min(max, Math.max(min, Math.round(n)));
}
function normalizeProbes(value) {
  const arr = Array.isArray(value) ? value : [{ id: 'edge-main', type: 'edge', region: 'cf-edge' }];
  return arr.slice(0, 10).map((p, i) => ({
    id: String(p.id || `probe-${i}`).slice(0, 40).replace(/[^a-zA-Z0-9_-]/g, ''),
    type: p.type === 'external' ? 'external' : 'edge',
    region: String(p.region || 'unknown').slice(0, 40),
  })).filter((p) => p.id);
}
async function validateMonitorBody(body, env) {
  if (!body || typeof body.url !== 'string') throw new Error('缺少 url');
  await assertPublicTarget(body.url, env.resolveDns);
  if (body.webhookUrl) await assertPublicTarget(body.webhookUrl, env.resolveDns);
  if (body.emailTo && !EMAIL_RE.test(body.emailTo)) throw new Error('邮箱格式错误');
  return {
    name: String(body.name || '').slice(0, 80),
    url: body.url,
    method: body.method === 'HEAD' ? 'HEAD' : 'GET',
    expectedStatus: clampInt(body.expectedStatus, 100, 599, 200),
    timeoutMs: clampInt(body.timeoutMs, 1000, 30000, 5000),
    intervalSec: clampInt(body.intervalSec, 60, 86400, 60),
    failureThreshold: clampInt(body.failureThreshold, 1, 20, 3),
    alertCooldownSec: clampInt(body.alertCooldownSec ?? 300, 0, 86400, 300),
    aggregate: body.aggregate === 'all' ? 'all' : 'any',
    probes: normalizeProbes(body.probes),
    webhookUrl: typeof body.webhookUrl === 'string' ? body.webhookUrl : '',
    emailTo: typeof body.emailTo === 'string' ? body.emailTo : '',
    enabled: body.enabled !== false,
  };
}

// ---------- 鉴权 ----------
function bearer(request) {
  const h = request.headers.get('authorization') || '';
  const token = h.startsWith('Bearer ') ? h.slice(7) : '';
  // 令牌内部出现空白即视为格式非法；头部首尾 OWS 由 HTTP 栈按规范剥离，不构成绕过
  return /\s/.test(token) ? '' : token;
}
function isAdmin(request, env) { return !!env.ADMIN_TOKEN && safeEqual(bearer(request), env.ADMIN_TOKEN); }
function isProbe(request, env) { return !!env.PROBE_TOKEN && safeEqual(bearer(request), env.PROBE_TOKEN); }

// ---------- 极简 Dashboard ----------
function dashboardHtml() {
  return `<!doctype html>
<html lang="zh-CN"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>UptimePulse</title><link rel="stylesheet" href="/app.css"></head><body><main>
<header><h1>UptimePulse</h1><p>轻量可用性监控 · 多线路</p></header>
<section><h2>添加监控项</h2>
<form id="addForm">
<input id="url" placeholder="https://example.com" required>
<input id="name" placeholder="名称(可选)">
<input id="threshold" type="number" value="3" min="1" title="失败阈值">
<input id="probes" placeholder="探针: edge-main, cn-1" title="探针 ID，逗号分隔">
<button type="submit">添加</button></form>
<div class="actions"><button id="refresh">刷新</button><button id="checkNow">立即检测</button><span id="msg"></span></div></section>
<section><h2>当前状态</h2><table><thead><tr><th>目标</th><th>状态</th><th>线路</th><th>HTTP</th><th>耗时</th><th>可用率</th><th>连续失败</th><th></th></tr></thead><tbody id="rows"></tbody></table></section>
<section><h2>最近异常</h2><table><thead><tr><th>时间</th><th>目标</th><th>线路</th><th>错误</th></tr></thead><tbody id="errors"></tbody></table></section>
</main><script src="/app.js" defer></script></body></html>`;
}
const APP_CSS = `:root{color-scheme:dark}*{box-sizing:border-box}body{margin:0;background:#0f1115;color:#e6e8eb;font:14px/1.5 ui-monospace,SFMono-Regular,Consolas,monospace}
main{max-width:980px;margin:0 auto;padding:28px 20px}h1{font-size:18px;margin:0 0 4px}header p{margin:0 0 20px;color:#8b93a1}
section{border:1px solid #262b36;border-radius:6px;padding:14px;margin-bottom:16px}h2{font-size:13px;margin:0 0 12px;color:#8b93a1;font-weight:600}
form{display:grid;grid-template-columns:2fr 1fr 80px 1fr auto;gap:8px}input,select,button{font:inherit;padding:7px 9px;background:#171b22;color:#e6e8eb;border:1px solid #333a47;border-radius:4px}
button{cursor:pointer;background:#2b6cb0;border-color:#2b6cb0}button:hover{background:#2c5f96}
table{width:100%;border-collapse:collapse}th,td{text-align:left;padding:8px 6px;border-bottom:1px solid #262b36;font-size:13px}th{color:#8b93a1;font-weight:600}
.ok{color:#4ade80}.bad{color:#f87171}.muted{color:#6b7280}.del{background:transparent;border:none;color:#f87171;padding:2px 6px}
.actions{display:flex;gap:8px;align-items:center;margin-top:12px}#msg{color:#fbbf24}`;
const APP_JS = `const $=id=>document.getElementById(id);let token='';
async function api(path,opt={}){opt.headers=opt.headers||{};if(token)opt.headers.Authorization='Bearer '+token;const r=await fetch(path,opt);if(r.status===401){token=prompt('管理员令牌：')||'';return api(path,opt)}return r}
function el(tag,text,cls){const n=document.createElement(tag);if(cls)n.className=cls;n.textContent=text??'';return n}
async function load(){const r=await api('/api/status');if(!r.ok){$('msg').textContent='加载失败 '+r.status;return}const d=await r.json();const rows=$('rows');rows.textContent='';
for(const m of d.monitors){const tr=document.createElement('tr');const ok=m.state==='ok'&&m.last&&m.last.ok;
tr.appendChild(el('td',m.name||m.url));tr.appendChild(el('td',ok?'正常':'异常',ok?'ok':'bad'));
const tdLine=document.createElement('td');for(const x of (m.last?.results||[])){tdLine.appendChild(el('span',x.region+':'+(x.ok?'OK':'FAIL'),x.ok?'ok':'bad'));tdLine.appendChild(document.createTextNode(' '))}tr.appendChild(tdLine);
tr.appendChild(el('td',m.last?String(m.last.status):'-'));tr.appendChild(el('td',m.last?m.last.latencyMs+'ms':'-'));
tr.appendChild(el('td',(m.uptime*100).toFixed(1)+'%'));tr.appendChild(el('td',String(m.consecutiveFailures)));
const td=document.createElement('td');const b=el('button','删除');b.className='del';b.onclick=async()=>{await api('/api/monitors/'+encodeURIComponent(m.id),{method:'DELETE'});load()};td.appendChild(b);tr.appendChild(td);rows.appendChild(tr)}
const er=$('errors');er.textContent='';for(const e of d.recentErrors){const tr=document.createElement('tr');tr.appendChild(el('td',e.checkedAt));tr.appendChild(el('td',e.monitorName));tr.appendChild(el('td',e.region));tr.appendChild(el('td',e.error||('HTTP '+e.status),'bad'));er.appendChild(tr)}
if(!d.monitors.length){const tr=document.createElement('tr');const td=el('td','暂无监控项','muted');td.colSpan=8;tr.appendChild(td);rows.appendChild(tr)}}
$('addForm').onsubmit=async e=>{e.preventDefault();const raw=$('probes').value.trim();const probes=raw?raw.split(',').map(x=>x.trim()).filter(Boolean).map(id=>({id,type:'external',region:id})):[{id:'edge-main',type:'edge',region:'cf-edge'}];
const body={url:$('url').value.trim(),name:$('name').value.trim(),failureThreshold:Number($('threshold').value)||3,probes};
const r=await api('/api/monitors',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify(body)});const d=await r.json();$('msg').textContent=r.ok?'已添加':'添加失败: '+(d.error||r.status);if(r.ok){$('url').value='';$('name').value='';load()}};
$('refresh').onclick=load;$('checkNow').onclick=async()=>{await api('/api/check',{method:'POST'});load()};load();`;

// ---------- 入口 ----------
/** @param {any} env */
export function createWorker(env) {
  async function fetchHandler(request) {
    const url = new URL(request.url);
    const path = url.pathname;
    const method = request.method;

    if (path === '/' && method === 'GET') return html(dashboardHtml());
    if (path === '/app.css' && method === 'GET') {
      return new Response(APP_CSS, { headers: { 'content-type': 'text/css; charset=utf-8', ...SECURITY_HEADERS } });
    }
    if (path === '/app.js' && method === 'GET') {
      return new Response(APP_JS, { headers: { 'content-type': 'application/javascript; charset=utf-8', ...SECURITY_HEADERS } });
    }

    if (path === '/api/status' && method === 'GET') {
      const monitors = await listMonitors(env);
      const out = [], recentErrors = [];
      for (const m of monitors) {
        const history = await getJson(env.KV, `history:${m.id}`, []);
        const incident = await getJson(env.KV, `incident:${m.id}`, { state: 'ok', consecutiveFailures: 0 });
        const okCount = history.filter((h) => h.ok).length;
        out.push({
          id: m.id, name: m.name, url: m.url, enabled: m.enabled, probes: m.probes,
          state: incident.state, consecutiveFailures: incident.consecutiveFailures,
          last: history[0] || null, uptime: history.length ? okCount / history.length : 1, samples: history.length,
        });
        if (history[0] && !history[0].ok) {
          for (const r of history[0].results || []) {
            if (!r.ok) recentErrors.push({ checkedAt: history[0].checkedAt, monitorName: m.name || m.url, region: r.region, status: r.status, error: r.error });
          }
        }
      }
      return json({ monitors: out, recentErrors: recentErrors.slice(0, 30), serverTime: new Date().toISOString() });
    }

    if (path === '/api/monitors' && method === 'POST') {
      if (!isAdmin(request, env)) return json({ error: '未授权' }, 401);
      let body;
      try { body = await request.json(); } catch { return json({ error: 'JSON 格式错误' }, 400); }
      let clean;
      try { clean = await validateMonitorBody(body, env); } catch (e) { return json({ error: e.message }, 400); }
      const monitor = { id: crypto.randomUUID(), ...clean, createdAt: new Date().toISOString(), lastRunAt: 0 };
      await saveMonitor(env, monitor);
      return json({ ok: true, monitor }, 201);
    }

    let match = path.match(/^\/api\/monitors\/([^/]+)$/);
    if (match && (method === 'PUT' || method === 'DELETE')) {
      if (!isAdmin(request, env)) return json({ error: '未授权' }, 401);
      const id = match[1];
      const existing = await getJson(env.KV, `monitor:${id}`, null);
      if (!existing) return json({ error: '不存在' }, 404);
      if (method === 'DELETE') {
        const ids = await getJson(env.KV, 'monitor:index', []);
        await env.KV.put('monitor:index', JSON.stringify(ids.filter((x) => x !== id)));
        await env.KV.delete(`monitor:${id}`);
        await env.KV.delete(`history:${id}`);
        await env.KV.delete(`incident:${id}`);
        for (const p of existing.probes || []) await env.KV.delete(`probe:${id}:${p.id}`);
        return json({ ok: true });
      }
      let body;
      try { body = await request.json(); } catch { return json({ error: 'JSON 格式错误' }, 400); }
      let clean;
      try { clean = await validateMonitorBody({ ...existing, ...body }, env); } catch (e) { return json({ error: e.message }, 400); }
      const updated = { ...existing, ...clean };
      await saveMonitor(env, updated);
      return json({ ok: true, monitor: updated });
    }

    match = path.match(/^\/api\/monitors\/([^/]+)\/history$/);
    if (match && method === 'GET') {
      if (!isAdmin(request, env)) return json({ error: '未授权' }, 401);
      const history = await getJson(env.KV, `history:${match[1]}`, []);
      return json({ history: history.slice(0, 100) });
    }

    if (path === '/api/check' && method === 'POST') {
      if (!isAdmin(request, env)) return json({ error: '未授权' }, 401);
      return json({ ok: true, results: await runDueChecks(env, true) });
    }

    // 探针任务：仅返回分配给该探针的非敏感字段
    if (path === '/api/probes/tasks' && method === 'GET') {
      if (!isProbe(request, env)) return json({ error: '未授权' }, 401);
      const probeId = url.searchParams.get('probeId') || '';
      const monitors = await listMonitors(env);
      const tasks = monitors.filter((m) => m.enabled && (m.probes || []).some((p) => p.id === probeId && p.type === 'external'))
        .map((m) => ({
          id: m.id, url: m.url, method: m.method, expectedStatus: m.expectedStatus,
          timeoutMs: m.timeoutMs, intervalSec: m.intervalSec, probeId,
        }));
      return json({ tasks, serverTime: Date.now() });
    }

    // 探针回传：独立令牌，不能直接改配置
    if (path === '/api/ingest' && method === 'POST') {
      if (!isProbe(request, env)) return json({ error: '未授权' }, 401);
      let body;
      try { body = await request.json(); } catch { return json({ error: 'JSON 格式错误' }, 400); }
      const id = String(body.monitorId || '').slice(0, 80);
      const probeId = String(body.probeId || '').slice(0, 40);
      const monitor = await getJson(env.KV, `monitor:${id}`, null);
      if (!monitor || !(monitor.probes || []).some((p) => p.id === probeId && p.type === 'external')) {
        return json({ error: '未知监控项或探针' }, 404);
      }
      const report = {
        probeId,
        region: String(body.region || probeId).slice(0, 40),
        ok: body.ok === true,
        status: clampInt(body.status, 0, 599, 0),
        latencyMs: clampInt(body.latencyMs, 0, 300000, 0),
        error: typeof body.error === 'string' ? body.error.slice(0, 200) : null,
        checkedAt: new Date().toISOString(),
        receivedAt: Date.now(),
      };
      await env.KV.put(`probe:${id}:${probeId}`, JSON.stringify(report));
      // 仅当所有线路都有新鲜结果时才形成一个完整轮次，避免历史样本失真
      const results = [];
      const freshMs = Math.max(120, monitor.intervalSec * 3) * 1000;
      let allFresh = true;
      for (const p of monitor.probes || []) {
        if (p.id === probeId) { results.push(report); continue; }
        const r = await getJson(env.KV, `probe:${id}:${p.id}`, null);
        if (r && Date.now() - r.receivedAt <= freshMs) results.push(r);
        else allFresh = false;
      }
      if (allFresh) {
        const evaluated = await commitRound(monitor, results, env);
        return json({ ok: true, evaluated: true, ...evaluated });
      }
      return json({ ok: true, evaluated: false, pending: results.length });
    }

    return json({ error: '未找到' }, 404);
  }

  async function scheduledHandler() { await runDueChecks(env, false); }
  return { fetch: fetchHandler, scheduled: scheduledHandler };
}

export default {
  async fetch(request, env) { return createWorker(env).fetch(request); },
  async scheduled(controller, env) { await createWorker(env).scheduled(controller); },
};
