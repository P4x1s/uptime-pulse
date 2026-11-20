/**
 * UptimePulse - 完整版 Worker（只读版）
 *
 * 监控目标统一由后台变量 MONITOR_TARGETS 提供（Cloudflare Dashboard 变量/Secret）。
 * 服务端读取变量生成监控列表；前端只读展示；不提供任何修改监控配置的接口或入口。
 * 保留：多线路聚合、国内探针回传、邮件 + Webhook 双通道、历史与异常查询。
 * 安全原语复用 src/demo.mjs，避免两套实现产生分歧。
 */
import {
  assertPublicTarget, safeEqual, hmacSign, probeOnce, getJson,
  getMonitors, clampInt, dashboardHtml, APP_CSS, APP_JS,
} from './demo.mjs';

const SECURITY_HEADERS = {
  'X-Content-Type-Options': 'nosniff',
  'Referrer-Policy': 'no-referrer',
  'X-Frame-Options': 'DENY',
  'Content-Security-Policy': "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; connect-src 'self'; img-src 'self' data:; object-src 'none'; base-uri 'none'; frame-ancestors 'none'",
};
const MAX_HISTORY = 500;

function json(data, status = 200, extra = {}) {
  return new Response(JSON.stringify(data), {
    status, headers: { 'content-type': 'application/json; charset=utf-8', ...SECURITY_HEADERS, ...extra },
  });
}
function text(body, status = 200, contentType = 'text/html; charset=utf-8') {
  return new Response(body, { status, headers: { 'content-type': contentType, ...SECURITY_HEADERS } });
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
  history.unshift({ checkedAt: new Date().toISOString(), results, ...aggregated, incidentState: state.state });
  if (history.length > MAX_HISTORY) history.length = MAX_HISTORY;
  await env.KV.put(`history:${monitor.id}`, JSON.stringify(history));
  await env.KV.put(`lastrun:${monitor.id}`, Date.now());
  return { aggregated, state };
}

/** 到期监控项：edge 线路即时探测；external 线路读取最近上报 */
async function runDueChecks(env, force = false) {
  const monitors = await getMonitors(env);
  const now = Date.now();
  const output = [];
  for (const m of monitors) {
    if (!m.enabled) continue;
    const intervalMs = Math.max(60, m.intervalSec || 60) * 1000;
    const lastRun = Number(await getJson(env.KV, `lastrun:${m.id}`, 0)) || 0;
    if (!force && now - lastRun < intervalMs) continue;
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
          for (const r of history[0].results || []) {
            if (!r.ok) recentErrors.push({ checkedAt: history[0].checkedAt, monitorName: m.name || m.url, region: r.region, status: r.status, error: r.error });
          }
        }
      }
      return json({ monitors: out, recentErrors: recentErrors.slice(0, 30), serverTime: new Date().toISOString() });
    }

    // 只读模式：任何修改监控配置的接口一律禁用（含历史接口，避免暴露内部数据）
    if (path === '/api/monitors' || path.startsWith('/api/monitors/') || path === '/api/check'
      || /^\/api\/monitors\/[^/]+\/history$/.test(path)) {
      return json({ error: '只读模式：监控目标由服务端后台变量管理，不支持修改' }, 405);
    }

    // 探针任务：仅返回分配给该探针的非敏感字段
    if (path === '/api/probes/tasks' && method === 'GET') {
      if (!isProbe(request, env)) return json({ error: '未授权' }, 401);
      const probeId = url.searchParams.get('probeId') || '';
      const monitors = await getMonitors(env);
      const tasks = monitors.filter((m) => m.enabled && (m.probes || []).some((p) => p.id === probeId && p.type === 'external'))
        .map((m) => ({
          id: m.id, url: m.url, method: m.method, expectedStatus: m.expectedStatus,
          timeoutMs: m.timeoutMs, intervalSec: m.intervalSec, probeId,
        }));
      return json({ tasks, serverTime: Date.now() });
    }

    // 探针回传：独立令牌；只能回传当前后台变量中存在的监控项，不能改配置
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

export { runDueChecks };

export default {
  async fetch(request, env) { return createWorker(env).fetch(request); },
  async scheduled(controller, env) { await createWorker(env).scheduled(controller); },
};
