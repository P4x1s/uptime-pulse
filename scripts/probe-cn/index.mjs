/**
 * UptimePulse 国内自托管探针（无第三方依赖，Node >= 18）
 *
 * 用途：Cloudflare Workers 无法从中国大陆出口发起请求，因此国内线路由此探针
 *      部署在大陆 VPS / 云函数上，定时向 Worker 回传检测结果。
 *
 * 环境变量：
 *   WORKER_URL    必填，例如 https://uptime-pulse.<account>.workers.dev
 *   PROBE_TOKEN   必填，与 Worker 的 PROBE_TOKEN secret 一致
 *   PROBE_ID      必填，例如 cn-sh-1（需与监控项中的探针 ID 一致）
 *   PROBE_REGION  可选，展示用，默认同 PROBE_ID
 *   INTERVAL_SEC  可选，默认 60，最小 30
 */
import { isPrivateIp } from '../../src/demo.mjs';

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

async function fetchJson(url, init = {}) {
  const resp = await fetch(url, init);
  if (!resp.ok) throw new Error(`HTTP ${resp.status}: ${url}`);
  return resp.json();
}

async function probeOne(task) {
  const started = Date.now();
  let status = 0, ok = false, error = null;
  try {
    const target = assertSafeUrl(task.url);
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), Math.min(30000, task.timeoutMs || 5000));
    let resp;
    try {
      resp = await fetch(target.toString(), {
        method: task.method === 'HEAD' ? 'HEAD' : 'GET',
        redirect: 'manual',
        signal: controller.signal,
        headers: { 'user-agent': `UptimePulseProbe/1.0 (${PROBE_ID})` },
      });
    } finally { clearTimeout(timer); }
    status = resp.status;
    ok = status === (task.expectedStatus || 200);
    if (resp.body) await resp.body.cancel().catch(() => {});
  } catch (e) {
    error = e && e.name === 'AbortError' ? 'timeout' : String((e && e.message) || e).slice(0, 200);
  }
  return {
    monitorId: task.id, probeId: PROBE_ID, region: PROBE_REGION,
    ok, status, latencyMs: Date.now() - started, error,
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
