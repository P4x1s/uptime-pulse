/**
 * UptimePulse 国内自托管探针（无第三方依赖，Node >= 18）
 *
 * 用途：Cloudflare Workers 无法从中国大陆出口发起请求，因此国内线路由此探针
 *      部署在大陆 VPS / 云函数上，定时向 Worker 回传检测结果。
 *
 * 环境变量：
 *   WORKER_URL    必填，例如 https://uptime-pulse.<account>.workers.dev
 *   PROBE_TOKEN   必填，与 Worker 的 PROBE_TOKEN 变量一致（普通变量，不要选 Secret）
 *   PROBE_ID      必填，例如 cn-sh-1（需与监控项中的探针 ID 一致）
 *   PROBE_REGION  可选，展示用，默认同 PROBE_ID
 *   INTERVAL_SEC  可选，默认 60，最小 30
 *
 * 判定逻辑与 Worker 保持一致：多期望状态码 + 响应关键字正反匹配 + 瞬时故障重试。
 */
import { isPrivateIp, errorClass } from '../../src/demo.mjs';

const WORKER_URL = process.env.WORKER_URL || '';
const PROBE_TOKEN = process.env.PROBE_TOKEN || '';
const PROBE_ID = process.env.PROBE_ID || '';
const PROBE_REGION = process.env.PROBE_REGION || PROBE_ID;
const INTERVAL_SEC = Math.max(30, Number(process.env.INTERVAL_SEC) || 60);

if (!WORKER_URL || !PROBE_TOKEN || !PROBE_ID) {
  console.error('缺少必需环境变量：WORKER_URL / PROBE_TOKEN / PROBE_ID');
  process.exit(1);
}

const auth = { Authorization: `Bearer ${PROBE_TOKEN}` };

/** 探针侧基础防护：只访问公网 http(s) 目标（任务本身已由 Worker 校验，此处为纵深防御） */
function assertSafeUrl(raw) {
  const u = new URL(raw);
  if (u.protocol !== 'http:' && u.protocol !== 'https:') throw new Error('协议不允许');
  const host = u.hostname.toLowerCase().replace(/^\[|\]$/g, '');
  if (host === 'localhost' || host.endsWith('.local') || host.endsWith('.internal')) throw new Error('内网域名');
  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(host) || host.includes(':')) {
    if (isPrivateIp(host)) throw new Error('内网 IP');
  }
  return u;
}

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

async function fetchJson(url, init = {}) {
  const resp = await fetch(url, init);
  if (!resp.ok) throw new Error(`HTTP ${resp.status}: ${url}`);
  return resp.json();
}

/** 受大小限制读取响应文本（关键字校验用） */
async function readBodyCapped(resp, cap = 65536) {
  if (!resp || !resp.body) return '';
  const reader = resp.body.getReader ? resp.body.getReader() : null;
  if (!reader) return (await resp.text()).slice(0, cap);
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
  } catch { /* 保留已读内容 */ }
  try { await reader.cancel().catch(() => {}); } catch { /* noop */ }
  return out;
}

function expectedCodes(task) {
  if (Array.isArray(task.expectedCodes) && task.expectedCodes.length) return task.expectedCodes;
  return [task.expectedStatus || 200];
}

function retryable(cls) {
  return cls === 'timeout' || cls === 'dns' || cls === 'tls' || cls === 'network';
}

async function attempt(task, target) {
  const started = Date.now();
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), Math.min(30000, task.timeoutMs || 5000));
  const headers = { 'user-agent': `UptimePulseProbe/2.0 (${PROBE_ID})`, ...(task.headers || {}) };
  const init = { method: task.method === 'HEAD' ? 'HEAD' : 'GET', redirect: 'manual', signal: controller.signal, headers };
  if (task.body && init.method !== 'GET' && init.method !== 'HEAD') init.body = task.body;
  let resp;
  try {
    resp = await fetch(target.toString(), init);
  } finally { clearTimeout(timer); }
  const status = resp.status;
  const needBody = !!(task.responseKeyword || task.responseForbiddenKeyword);
  if (needBody) {
    const body = await readBodyCapped(resp);
    const codes = expectedCodes(task);
    let error = null;
    if (!codes.includes(status)) error = `HTTP ${status}`;
    else if (task.responseKeyword && !body.includes(task.responseKeyword)) error = 'keyword-missing';
    else if (task.responseForbiddenKeyword && body.includes(task.responseForbiddenKeyword)) error = 'keyword-forbidden';
    return { status, error, latencyMs: Date.now() - started };
  }
  if (resp.body) await resp.body.cancel().catch(() => {});
  const codes = expectedCodes(task);
  return { status, error: codes.includes(status) ? null : `HTTP ${status}`, latencyMs: Date.now() - started };
}

async function probeOne(task) {
  const started = Date.now();
  let last = { status: 0, error: 'unknown' }, used = 0;
  try {
    const target = assertSafeUrl(task.url);
    const maxAttempts = 1 + Math.max(0, Math.min(3, Number(task.retries) || 0));
    for (let i = 1; i <= maxAttempts; i++) {
      try {
        last = await attempt(task, target);
      } catch (e) {
        last = { status: 0, error: e && e.name === 'AbortError' ? 'timeout' : String((e && e.message) || e).slice(0, 200) };
      }
      used = i;
      if (!last.error || !retryable(errorClass(last.error)) || i >= maxAttempts) break;
      await sleep(Math.min(400, 120 * (2 ** (i - 1))));
    }
  } catch (e) {
    last = { status: 0, error: String((e && e.message) || e).slice(0, 200) };
    used = 1;
  }
  return {
    monitorId: task.id, probeId: PROBE_ID, region: PROBE_REGION,
    ok: !last.error, status: last.status, latencyMs: Date.now() - started,
    error: last.error, errorClass: last.error ? errorClass(last.error) : 'ok', attempts: used,
  };
}

async function round() {
  const base = WORKER_URL.replace(/\/$/, '');
  const { tasks } = await fetchJson(`${base}/api/probes/tasks?probeId=${encodeURIComponent(PROBE_ID)}`, { headers: auth });
  if (!tasks.length) { console.log(`[${new Date().toISOString()}] 无分配任务`); return; }
  const reports = await Promise.all(tasks.map(probeOne));
  for (const report of reports) {
    await fetchJson(`${base}/api/ingest`, {
      method: 'POST',
      headers: { ...auth, 'content-type': 'application/json' },
      body: JSON.stringify(report),
    });
  }
  console.log(`[${new Date().toISOString()}] 已上报 ${reports.length} 条：${reports.map((r) => `${r.monitorId}=${r.ok ? 'OK' : r.error || r.status}`).join(', ')}`);
}

async function main() {
  console.log(`UptimePulse 探针 ${PROBE_ID} (${PROBE_REGION}) → ${WORKER_URL}，间隔 ${INTERVAL_SEC}s`);
  for (;;) {
    try { await round(); } catch (e) { console.error(`[${new Date().toISOString()}] 轮次失败：${e.message}`); }
    await new Promise((resolve) => setTimeout(resolve, INTERVAL_SEC * 1000));
  }
}

main();
