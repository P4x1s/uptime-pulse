/**
 * 完整版功能测试（只读版）：后台变量驱动配置、写接口禁用、探针权限隔离、
 * 多线路聚合、邮件与 Webhook 告警、变量更新同步生效。
 */
import test from 'node:test';
import assert from 'node:assert/strict';
import { createWorker, runDueChecks } from '../src/index.mjs';

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
  const webhooks = [], emails = [], outbound = [];
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
    outbound.push({ url: u, init });
    return new Response('', { status: targetStatus });
  };
  const env = {
    KV, ADMIN_TOKEN: 'admin-secret', PROBE_TOKEN: 'probe-secret',
    WEBHOOK_URL: 'https://alert.example.com/global', ALERT_SIGNING_SECRET: 'sign-secret',
    RESEND_API_KEY: 're_test_key', EMAIL_FROM: 'UptimePulse <alerts@example.com>',
    PROBE_REGION: 'cf-test', MONITORS: [],
    resolveDns: async () => ['93.184.216.34'],
    fetchImpl,
  };
  const worker = createWorker(env);
  const req = (path, options = {}) => worker.fetch(new Request(`http://localhost${path}`, options));
  return {
    env, KV, webhooks, emails, outbound, req,
    check: () => runDueChecks(env, true),
    setTargets: (targets) => { env.MONITORS = targets; },
    setTargetStatus: (s) => { targetStatus = s; },
    setEmailFails: (v) => { emailFails = v; },
  };
}

function target(overrides = {}) {
  return {
    id: 'm1', name: '电商首页', url: 'https://target.example.com', failureThreshold: 1,
    probes: [{ id: 'edge-main', type: 'edge', region: 'cf-test' }], ...overrides,
  };
}

test('配置只读：写接口全部禁用，列表由代码配置生成', async () => {
  const ctx = makeCtx();
  const adminHeaders = { authorization: 'Bearer admin-secret', 'content-type': 'application/json' };
  assert.equal((await ctx.req('/api/monitors', { method: 'POST', headers: adminHeaders, body: '{"url":"https://x.example.com"}' })).status, 405);
  assert.equal((await ctx.req('/api/monitors/m1', { method: 'PUT', headers: adminHeaders, body: '{}' })).status, 405);
  assert.equal((await ctx.req('/api/monitors/m1', { method: 'DELETE', headers: adminHeaders })).status, 405);
  assert.equal((await ctx.req('/api/check', { method: 'POST', headers: adminHeaders })).status, 405);
  assert.equal((await ctx.req('/api/monitors/m1/history', { headers: adminHeaders })).status, 405);

  ctx.setTargets([target()]);
  const status = await (await ctx.req('/api/status')).json();
  assert.equal(status.monitors.length, 1);
  assert.equal(status.monitors[0].url, 'https://target.example.com');
  assert.equal(status.monitors[0].name, '电商首页');
});

test('配置变更后展示与检测同步生效', async () => {
  const ctx = makeCtx();
  ctx.setTargets([target({ id: 'a', name: 'A', url: 'https://a.example.com' })]);
  let s = await (await ctx.req('/api/status')).json();
  assert.deepEqual(s.monitors.map((m) => m.name), ['A']);

  ctx.setTargets([
    target({ id: 'a', name: 'A', url: 'https://a.example.com' }),
    target({ id: 'b', name: 'B', url: 'https://b.example.com' }),
  ]);
  s = await (await ctx.req('/api/status')).json();
  assert.deepEqual(s.monitors.map((m) => m.name), ['A', 'B']);

  await ctx.check();
  s = await (await ctx.req('/api/status')).json();
  assert.ok(s.monitors.every((m) => m.samples >= 1), '新增目标应立即被发现并检测');

  ctx.setTargets([]);
  s = await (await ctx.req('/api/status')).json();
  assert.equal(s.monitors.length, 0, '从配置移除的目标应立即从展示消失');
});

test('探针隔离：任务接口只返回非敏感字段，令牌权限分离', async () => {
  const ctx = makeCtx();
  ctx.setTargets([target({
    probes: [{ id: 'cn-1', type: 'external', region: 'cn-sh' }],
    emailTo: 'owner@example.com', webhookUrl: 'https://alert.example.com/per-monitor',
  })]);
  const tasksResp = await ctx.req('/api/probes/tasks?probeId=cn-1', { headers: { authorization: 'Bearer probe-secret' } });
  assert.equal(tasksResp.status, 200);
  const { tasks } = await tasksResp.json();
  assert.equal(tasks.length, 1);
  assert.deepEqual(Object.keys(tasks[0]).sort(), ['expectedStatus', 'id', 'intervalSec', 'method', 'probeId', 'timeoutMs', 'url']);

  const forbidden = await ctx.req('/api/monitors', {
    method: 'POST', headers: { authorization: 'Bearer probe-secret', 'content-type': 'application/json' }, body: '{}',
  });
  assert.equal(forbidden.status, 405);
  const forbiddenIngest = await ctx.req('/api/ingest', {
    method: 'POST', headers: { authorization: 'Bearer admin-secret', 'content-type': 'application/json' },
    body: JSON.stringify({ monitorId: 'm1', probeId: 'cn-1', ok: true }),
  });
  assert.equal(forbiddenIngest.status, 401);

  const status = await (await ctx.req('/api/status')).json();
  assert.ok(!JSON.stringify(status).includes('owner@example.com'), '状态接口不应泄漏告警邮箱');
  assert.ok(!JSON.stringify(status).includes('sign-secret'), '状态接口不应泄漏签名密钥');
});

test('探针回传：只接受当前后台变量中的监控项', async () => {
  const ctx = makeCtx();
  ctx.setTargets([target({ probes: [{ id: 'cn-1', type: 'external', region: 'cn-sh' }] })]);
  const probeH = { authorization: 'Bearer probe-secret', 'content-type': 'application/json' };
  const ok = await ctx.req('/api/ingest', {
    method: 'POST', headers: probeH,
    body: JSON.stringify({ monitorId: 'm1', probeId: 'cn-1', ok: true, status: 200, latencyMs: 12 }),
  });
  assert.equal(ok.status, 200);
  const unknown = await ctx.req('/api/ingest', {
    method: 'POST', headers: probeH, body: JSON.stringify({ monitorId: 'ghost', probeId: 'cn-1', ok: true }),
  });
  assert.equal(unknown.status, 404);
  ctx.setTargets([target({ id: 'm2', probes: [{ id: 'cn-1', type: 'external', region: 'cn-sh' }] })]);
  const stale = await ctx.req('/api/ingest', {
    method: 'POST', headers: probeH, body: JSON.stringify({ monitorId: 'm1', probeId: 'cn-1', ok: true }),
  });
  assert.equal(stale.status, 404, '变量移除的旧 ID 不得再接收回传');
});

test('告警：故障触发 Webhook + 邮件，恢复通知，邮件失败不影响 Webhook', async () => {
  const ctx = makeCtx();
  ctx.setTargets([target({ emailTo: 'owner@example.com', webhookUrl: 'https://alert.example.com/per-monitor' })]);
  ctx.setTargetStatus(200);
  await ctx.check();
  assert.equal(ctx.webhooks.length, 0);

  ctx.setTargetStatus(503);
  await ctx.check();
  assert.ok(ctx.webhooks.length >= 1, '故障应触发 Webhook（全局+单项）');
  assert.equal(ctx.emails.length, 1, '故障应触发邮件');
  assert.equal(ctx.emails[0].auth, 'Bearer re_test_key');
  assert.ok(ctx.emails[0].body.subject.includes('故障'));
  assert.ok(ctx.webhooks.every((w) => w.sig && w.sig.startsWith('sha256=')), 'Webhook 应带 HMAC 签名');

  const before = ctx.webhooks.length;
  ctx.setEmailFails(true);
  ctx.setTargetStatus(500);
  await ctx.check();
  assert.ok(ctx.webhooks.length > before, '邮件失败时 Webhook 仍应送达');

  ctx.setEmailFails(false);
  ctx.setTargetStatus(200);
  await ctx.check();
  const recovered = ctx.webhooks.filter((w) => w.body.type === 'recovered');
  assert.ok(recovered.length >= 1, '恢复应发送通知');
});

test('多线路聚合：all 模式下任一线路失败即判为故障', async () => {
  const ctx = makeCtx();
  ctx.setTargets([target({
    id: 'm-multi', aggregate: 'all',
    probes: [
      { id: 'edge-main', type: 'edge', region: 'cf-test' },
      { id: 'cn-1', type: 'external', region: 'cn-sh' },
    ],
  })]);
  const probeH = { authorization: 'Bearer probe-secret', 'content-type': 'application/json' };
  await ctx.req('/api/ingest', {
    method: 'POST', headers: probeH,
    body: JSON.stringify({ monitorId: 'm-multi', probeId: 'cn-1', region: 'cn-sh', ok: false, status: 500, latencyMs: 120, error: 'HTTP 500' }),
  });
  ctx.setTargetStatus(200);
  await ctx.check();
  const status = await (await ctx.req('/api/status')).json();
  assert.equal(status.monitors[0].state, 'firing', 'all 模式下 cn 线路失败应判故障');
  assert.equal(status.recentErrors.length, 1);
  assert.equal(status.recentErrors[0].region, 'cn-sh');
});
