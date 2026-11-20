/**
 * 完整版功能测试：配置 API 鉴权、探针权限隔离、多线路聚合、邮件与 Webhook 告警。
 */
import test from 'node:test';
import assert from 'node:assert/strict';
import { createWorker } from '../src/index.mjs';

class MockKV {
  constructor() { this.store = new Map(); }
  async get(key, type) {
    const value = this.store.get(key);
    if (value === undefined) return null;
    return type === 'json' ? JSON.parse(value) : value;
  }
  async put(key, value) { this.store.set(key, typeof value === 'string' ? value : JSON.stringify(value)); }
  async delete(key) { this.store.delete(key); }
}

function makeCtx() {
  const KV = new MockKV();
  const webhooks = [], emails = [];
  let targetStatus = 200;
  let emailFails = false;
  const fetchImpl = async (url, init = {}) => {
    const u = String(url);
    if (u.includes('alert.example.com')) {
      webhooks.push({ url: u, body: JSON.parse(init.body), sig: init.headers?.['x-uptimepulse-signature'] });
      return new Response('', { status: 200 });
    }
    if (u.includes('api.resend.com')) {
      if (emailFails) return new Response('{"error":"boom"}', { status: 500 });
      emails.push({ body: JSON.parse(init.body), auth: init.headers?.authorization });
      return new Response('', { status: 200 });
    }
    return new Response('', { status: targetStatus });
  };
  const env = {
    KV, ADMIN_TOKEN: 'admin-secret', PROBE_TOKEN: 'probe-secret',
    WEBHOOK_URL: 'https://alert.example.com/global', ALERT_SIGNING_SECRET: 'sign-secret',
    RESEND_API_KEY: 're_test_key', EMAIL_FROM: 'UptimePulse <alerts@example.com>',
    PROBE_REGION: 'cf-test',
    resolveDns: async () => ['93.184.216.34'],
    fetchImpl,
  };
  const worker = createWorker(env);
  const req = (path, options = {}) => worker.fetch(new Request(`http://localhost${path}`, options));
  return {
    env, KV, webhooks, emails, req,
    setTargetStatus: (s) => { targetStatus = s; },
    setEmailFails: (v) => { emailFails = v; },
  };
}

const adminHeaders = { authorization: 'Bearer admin-secret', 'content-type': 'application/json' };
const probeHeaders = { authorization: 'Bearer probe-secret', 'content-type': 'application/json' };

async function createMonitor(ctx, overrides = {}) {
  const body = {
    url: 'https://target.example.com', name: '电商首页', failureThreshold: 1,
    probes: [{ id: 'edge-main', type: 'edge', region: 'cf-test' }], ...overrides,
  };
  const r = await ctx.req('/api/monitors', { method: 'POST', headers: adminHeaders, body: JSON.stringify(body) });
  if (r.status !== 201) throw new Error(`创建失败: ${r.status} ${await r.text()}`);
  return (await r.json()).monitor;
}

test('配置 API：未授权被拒 / SSRF 目标被拒 / 授权创建成功', async () => {
  const ctx = makeCtx();
  const body = JSON.stringify({ url: 'https://target.example.com' });
  assert.equal((await ctx.req('/api/monitors', { method: 'POST', headers: { 'content-type': 'application/json' }, body })).status, 401);
  const bad = await ctx.req('/api/monitors', {
    method: 'POST', headers: adminHeaders,
    body: JSON.stringify({ url: 'http://169.254.169.254/latest/meta-data' }),
  });
  assert.equal(bad.status, 400);
  const m = await createMonitor(ctx);
  assert.equal(m.url, 'https://target.example.com');
  assert.equal(m.failureThreshold, 1);
  assert.equal(m.probes[0].type, 'edge');
});

test('探针隔离：任务接口只返回非敏感字段，探针令牌不能改配置', async () => {
  const ctx = makeCtx();
  await createMonitor(ctx, {
    probes: [{ id: 'cn-1', type: 'external', region: 'cn-sh' }],
    emailTo: 'owner@example.com', webhookUrl: 'https://alert.example.com/per-monitor',
  });
  const tasksResp = await ctx.req('/api/probes/tasks?probeId=cn-1', { headers: { authorization: 'Bearer probe-secret' } });
  assert.equal(tasksResp.status, 200);
  const { tasks } = await tasksResp.json();
  assert.equal(tasks.length, 1);
  assert.deepEqual(Object.keys(tasks[0]).sort(), ['expectedStatus', 'id', 'intervalSec', 'method', 'probeId', 'timeoutMs', 'url']);

  const forbidden = await ctx.req('/api/monitors', {
    method: 'POST', headers: probeHeaders, body: JSON.stringify({ url: 'https://target.example.com' }),
  });
  assert.equal(forbidden.status, 401);
  const forbiddenIngest = await ctx.req('/api/ingest', {
    method: 'POST', headers: adminHeaders,
    body: JSON.stringify({ monitorId: 'x', probeId: 'cn-1', ok: true }),
  });
  assert.equal(forbiddenIngest.status, 401);

  const status = await (await ctx.req('/api/status')).json();
  assert.ok(!JSON.stringify(status).includes('owner@example.com'), '状态接口不应泄漏告警邮箱');
  assert.ok(!JSON.stringify(status).includes('sign-secret'), '状态接口不应泄漏签名密钥');
});

test('告警：故障触发 Webhook + 邮件，恢复发送通知，邮件失败不影响 Webhook', async () => {
  const ctx = makeCtx();
  await createMonitor(ctx, { emailTo: 'owner@example.com', webhookUrl: 'https://alert.example.com/per-monitor' });
  ctx.setTargetStatus(200);
  await ctx.req('/api/check', { method: 'POST', headers: adminHeaders });
  assert.equal(ctx.webhooks.length, 0);

  ctx.setTargetStatus(503);
  await ctx.req('/api/check', { method: 'POST', headers: adminHeaders });
  assert.ok(ctx.webhooks.length >= 1, '故障应触发 Webhook（全局+单项）');
  assert.equal(ctx.emails.length, 1, '故障应触发邮件');
  assert.equal(ctx.emails[0].auth, 'Bearer re_test_key');
  assert.ok(ctx.emails[0].body.subject.includes('故障'));
  assert.ok(ctx.webhooks.every((w) => w.sig && w.sig.startsWith('sha256=')), 'Webhook 应带 HMAC 签名');

  const before = ctx.webhooks.length;
  ctx.setEmailFails(true);
  ctx.setTargetStatus(500);
  await ctx.req('/api/check', { method: 'POST', headers: adminHeaders });
  assert.ok(ctx.webhooks.length > before, '邮件失败时 Webhook 仍应送达');

  ctx.setEmailFails(false);
  ctx.setTargetStatus(200);
  await ctx.req('/api/check', { method: 'POST', headers: adminHeaders });
  const recovered = ctx.webhooks.filter((w) => w.body.type === 'recovered');
  assert.ok(recovered.length >= 1, '恢复应发送通知');
});

test('多线路聚合：all 模式下任一线路失败即判为故障', async () => {
  const ctx = makeCtx();
  const m = await createMonitor(ctx, {
    aggregate: 'all', threshold: 1,
    probes: [
      { id: 'edge-main', type: 'edge', region: 'cf-test' },
      { id: 'cn-1', type: 'external', region: 'cn-sh' },
    ],
  });
  await ctx.req('/api/ingest', {
    method: 'POST', headers: probeHeaders,
    body: JSON.stringify({ monitorId: m.id, probeId: 'cn-1', region: 'cn-sh', ok: false, status: 500, latencyMs: 120, error: 'HTTP 500' }),
  });
  ctx.setTargetStatus(200);
  await ctx.req('/api/check', { method: 'POST', headers: adminHeaders });
  const status = await (await ctx.req('/api/status')).json();
  assert.equal(status.monitors[0].state, 'firing', 'all 模式下 cn 线路失败应判故障');
  assert.equal(status.recentErrors.length, 1);
  assert.equal(status.recentErrors[0].region, 'cn-sh');
});

test('更新接口：PUT 修改阈值生效，且不能绕过 URL 校验', async () => {
  const ctx = makeCtx();
  const m = await createMonitor(ctx);
  const ok = await ctx.req(`/api/monitors/${m.id}`, {
    method: 'PUT', headers: adminHeaders, body: JSON.stringify({ failureThreshold: 7 }),
  });
  assert.equal(ok.status, 200);
  assert.equal((await ok.json()).monitor.failureThreshold, 7);
  const bad = await ctx.req(`/api/monitors/${m.id}`, {
    method: 'PUT', headers: adminHeaders, body: JSON.stringify({ url: 'http://127.0.0.1' }),
  });
  assert.equal(bad.status, 400);
});
