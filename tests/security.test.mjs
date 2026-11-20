/**
 * UptimePulse 安全测试套件
 * 覆盖：SSRF / 鉴权绕过 / XSS 与 CSP / 告警去重逻辑 / 输入校验 / 敏感信息泄漏
 * 所有测试离线运行，外部依赖通过 env 注入。
 */
import test from 'node:test';
import assert from 'node:assert/strict';
import { createWorker } from '../src/index.mjs';
import { assertPublicTarget } from '../src/demo.mjs';

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
  let responder = () => ({ status: 200 });
  const fetchImpl = async (url, init = {}) => {
    const u = String(url);
    if (u.includes('api.resend.com')) {
      emails.push({ body: JSON.parse(init.body), auth: init.headers?.authorization });
      return new Response('', { status: 200 });
    }
    if (u.includes('alert.example.com')) {
      webhooks.push({ url: u, body: JSON.parse(init.body), headers: init.headers });
      return new Response('', { status: 200 });
    }
    outbound.push({ url: u, init });
    const r = responder();
    if (r.throw) throw r.throw;
    return new Response('', { status: r.status || 200, headers: r.headers || {} });
  };
  const env = {
    KV, ADMIN_TOKEN: 'Secr3t-Admin-Token', PROBE_TOKEN: 'Secr3t-Probe-Token',
    WEBHOOK_URL: 'https://alert.example.com/hook', ALERT_SIGNING_SECRET: 'Secr3t-Signing-Key',
    RESEND_API_KEY: 're_Secr3tKey', EMAIL_FROM: 'alerts@example.com',
    PROBE_REGION: 'cf-test',
    resolveDns: async (host) => (host === 'private.example.com' ? ['192.168.1.10'] : ['93.184.216.34']),
    fetchImpl,
  };
  const worker = createWorker(env);
  const req = (path, options = {}) => worker.fetch(new Request(`http://localhost${path}`, options));
  return {
    env, KV, req, webhooks, emails, outbound,
    setResponder: (fn) => { responder = fn; },
  };
}

const admin = { authorization: 'Bearer Secr3t-Admin-Token', 'content-type': 'application/json' };
const probe = { authorization: 'Bearer Secr3t-Probe-Token', 'content-type': 'application/json' };

async function create(ctx, overrides = {}) {
  const body = {
    url: 'https://target.example.com', name: '测试目标', failureThreshold: 1,
    alertCooldownSec: 300, probes: [{ id: 'edge-main', type: 'edge', region: 'cf-test' }],
    ...overrides,
  };
  const r = await ctx.req('/api/monitors', { method: 'POST', headers: admin, body: JSON.stringify(body) });
  if (r.status !== 201) throw new Error(`创建失败 ${r.status}: ${await r.text()}`);
  return (await r.json()).monitor;
}

// ---------------- SSRF ----------------
test('SSRF: 混淆 IP / 元数据 / 内网域名 / 特殊协议在配置接口被拒绝', async () => {
  const ctx = makeCtx();
  const attacks = [
    'http://127.0.0.1', 'http://0177.0.0.1/', 'http://127.1/',
    'http://0x7f.1/', 'http://2130706433/', 'http://[::1]/',
    'http://[::ffff:7f00:1]/', 'http://[::ffff:127.0.0.1]/',
    'http://169.254.169.254/latest/meta-data/iam/security-credentials/',
    'http://10.0.0.1/', 'http://192.168.1.1/', 'http://100.64.0.1/',
    'http://localhost:8080/', 'http://app.local/', 'http://x.internal/',
    'https://private.example.com/',
    'file:///etc/passwd', 'javascript:alert(1)', 'ftp://example.com/',
    'https://user:pass@example.com/',
  ];
  for (const url of attacks) {
    const r = await ctx.req('/api/monitors', {
      method: 'POST', headers: admin, body: JSON.stringify({ url }),
    });
    assert.equal(r.status, 400, `应拒绝: ${url}`);
  }
  // 超长 URL
  const long = 'https://example.com/' + 'a'.repeat(3000);
  const r2 = await ctx.req('/api/monitors', {
    method: 'POST', headers: admin, body: JSON.stringify({ url: long }),
  });
  assert.equal(r2.status, 400);
});

test('SSRF: 监控目标不允许跟随重定向（阻断跳转内网）', async () => {
  const ctx = makeCtx();
  await create(ctx);
  ctx.setResponder(() => ({ status: 302, headers: { location: 'http://127.0.0.1/admin' } }));
  await ctx.req('/api/check', { method: 'POST', headers: admin });
  const probeCall = ctx.outbound.find((c) => c.url.includes('target.example.com'));
  assert.ok(probeCall, '应发起探测');
  assert.equal(probeCall.init.redirect, 'manual', '必须禁止自动跟随重定向');
  assert.equal(probeCall.url, 'https://target.example.com/', '不应请求重定向目标');
});

test('SSRF: Webhook 目标同样被校验，无法通过监控项配置绕过', async () => {
  const ctx = makeCtx();
  for (const hook of ['http://127.0.0.1:8080/hook', 'http://[::1]/hook', 'file:///etc/passwd']) {
    const r = await ctx.req('/api/monitors', {
      method: 'POST', headers: admin,
      body: JSON.stringify({ url: 'https://target.example.com', webhookUrl: hook }),
    });
    assert.equal(r.status, 400, `应拒绝 Webhook: ${hook}`);
  }
});

// ---------------- 鉴权 ----------------
test('鉴权: 缺失/错误/空/前缀错误的令牌均无法写配置', async () => {
  const ctx = makeCtx();
  const body = JSON.stringify({ url: 'https://target.example.com' });
  const cases = [
    {},
    { authorization: '' },
    { authorization: 'Bearer ' },
    { authorization: 'Bearer wrong-token' },
    { authorization: 'bearer Secr3t-Admin-Token' },
    { authorization: 'Basic Secr3t-Admin-Token' },
    // 令牌中间夹空格必须拒绝（首尾 OWS 由 HTTP 栈规范化，不算绕过）
    { authorization: 'Bearer Secr3t Admin Token' },
  ];
  for (const headers of cases) {
    const r = await ctx.req('/api/monitors', { method: 'POST', headers: { ...headers, 'content-type': 'application/json' }, body });
    assert.equal(r.status, 401, `应拒绝: ${JSON.stringify(headers)}`);
  }
  // 探针令牌不能执行管理员操作
  const probeAttempt = await ctx.req('/api/monitors', { method: 'POST', headers: probe, body });
  assert.equal(probeAttempt.status, 401);
  // 管理员令牌不能执行探针操作
  const adminAttempt = await ctx.req('/api/ingest', {
    method: 'POST', headers: admin, body: JSON.stringify({ monitorId: 'x', probeId: 'y', ok: true }),
  });
  assert.equal(adminAttempt.status, 401);
});

test('鉴权: 未授权不能读取历史或触发检测', async () => {
  const ctx = makeCtx();
  assert.equal((await ctx.req('/api/monitors/x/history')).status, 401);
  assert.equal((await ctx.req('/api/check', { method: 'POST' })).status, 401);
  assert.equal((await ctx.req('/api/probes/tasks?probeId=edge-main')).status, 401);
});

// ---------------- XSS / CSP ----------------
test('XSS: 用户输入不进入 HTML，前端使用 textContent 且 CSP 严格', async () => {
  const ctx = makeCtx();
  const payload = '<img src=x onerror="alert(1)"></script><script>alert(2)</script>';
  await create(ctx, { name: payload });

  const pageResp = await ctx.req('/');
  const page = await pageResp.text();
  assert.ok(!page.includes('onerror='), '首页 HTML 不应包含用户输入');
  const csp = pageResp.headers.get('content-security-policy') || '';
  const scriptDirective = csp.split(';').map((s) => s.trim()).find((s) => s.startsWith('script-src')) || '';
  assert.ok(scriptDirective.includes("'self'"), 'script-src 应限制为 self');
  assert.ok(!scriptDirective.includes('unsafe-inline'), 'script-src 不应允许内联脚本');

  const js = await (await ctx.req('/app.js')).text();
  assert.ok(!js.includes('innerHTML'), '前端不得使用 innerHTML 渲染用户数据');
  assert.ok(js.includes('textContent'), '前端应使用 textContent');

  const status = await (await ctx.req('/api/status')).json();
  assert.equal(status.monitors[0].name, payload, 'JSON 中保留原值，由前端安全渲染');
  const type = (await ctx.req('/api/status')).headers.get('content-type');
  assert.ok(type.includes('application/json'), 'API 必须返回 JSON 而非 HTML');
});

// ---------------- 告警逻辑 ----------------
test('逻辑: 错误文案变化不改变签名，冷却期内不重复告警', async () => {
  const ctx = makeCtx();
  await create(ctx, { failureThreshold: 1, alertCooldownSec: 300 });
  ctx.setResponder(() => ({ throw: Object.assign(new Error('network boom A'), { name: 'Error' }) }));
  await ctx.req('/api/check', { method: 'POST', headers: admin });
  assert.equal(ctx.webhooks.length, 1);

  ctx.setResponder(() => ({ throw: Object.assign(new Error('network totally different message B'), { name: 'Error' }) }));
  await ctx.req('/api/check', { method: 'POST', headers: admin });
  assert.equal(ctx.webhooks.length, 1, '同类别错误在冷却期内应去重');

  ctx.setResponder(() => ({ throw: Object.assign(new Error('aborted'), { name: 'AbortError' }) }));
  await ctx.req('/api/check', { method: 'POST', headers: admin });
  assert.equal(ctx.webhooks.length, 2, '错误类别变化（timeout）应允许新通知');
});

test('逻辑: 恢复后再次故障生成新的 incidentId', async () => {
  const ctx = makeCtx();
  const m = await create(ctx, { failureThreshold: 1, alertCooldownSec: 0 });
  ctx.setResponder(() => ({ status: 500 }));
  await ctx.req('/api/check', { method: 'POST', headers: admin });
  const first = (await ctx.KV.get(`incident:${m.id}`, 'json')).incidentId;
  ctx.setResponder(() => ({ status: 200 }));
  await ctx.req('/api/check', { method: 'POST', headers: admin });
  ctx.setResponder(() => ({ status: 500 }));
  await ctx.req('/api/check', { method: 'POST', headers: admin });
  const second = (await ctx.KV.get(`incident:${m.id}`, 'json')).incidentId;
  assert.ok(first && second && first !== second, '新事件必须有新的 incidentId');
  assert.ok(ctx.webhooks.some((w) => w.body.type === 'recovered'));
});

test('逻辑: 冷却窗口与阈值边界被正确钳制，不能绕过', async () => {
  const ctx = makeCtx();
  const m = await create(ctx, { failureThreshold: 999, alertCooldownSec: -50 });
  assert.equal(m.failureThreshold, 20, '阈值上限 20');
  assert.equal(m.alertCooldownSec, 0, '冷却不能为负');
  const m2 = await create(ctx, { failureThreshold: 0, url: 'https://other.example.com' });
  assert.equal(m2.failureThreshold, 1, '阈值下限 1');
});

// ---------------- 输入校验 ----------------
test('输入: 超长字段被截断，探针 ID 被清洗，非法邮箱被拒绝', async () => {
  const ctx = makeCtx();
  const m = await create(ctx, {
    name: 'x'.repeat(500),
    emailTo: 'owner@example.com',
    probes: Array.from({ length: 20 }, (_, i) => ({ id: `<bad id ${i}>`, type: 'external', region: 'r' })),
  });
  assert.equal(m.name.length, 80);
  assert.equal(m.probes.length, 10, '探针数量上限 10');
  assert.ok(m.probes.every((p) => /^[a-zA-Z0-9_-]+$/.test(p.id)), '探针 ID 应被清洗为安全字符');

  const bad = await ctx.req('/api/monitors', {
    method: 'POST', headers: admin,
    body: JSON.stringify({ url: 'https://target.example.com', emailTo: 'not-an-email' }),
  });
  assert.equal(bad.status, 400);
});

// ---------------- 信息泄漏 ----------------
test('信息泄漏: 响应体与响应头不包含任何密钥', async () => {
  const ctx = makeCtx();
  await create(ctx, { emailTo: 'owner@example.com' });
  ctx.setResponder(() => ({ status: 500 }));
  await ctx.req('/api/check', { method: 'POST', headers: admin });
  const responses = [
    await ctx.req('/'), await ctx.req('/api/status'), await ctx.req('/app.js'), await ctx.req('/app.css'),
  ];
  for (const r of responses) {
    const body = await r.text();
    const headers = JSON.stringify(Object.fromEntries(r.headers));
    for (const secret of ['Secr3t-Admin-Token', 'Secr3t-Probe-Token', 'Secr3t-Signing-Key', 're_Secr3tKey']) {
      assert.ok(!body.includes(secret), `响应体泄漏 ${secret}`);
      assert.ok(!headers.includes(secret), `响应头泄漏 ${secret}`);
    }
  }
  const status = await (await ctx.req('/api/status')).json();
  assert.ok(!JSON.stringify(status).includes('owner@example.com'), '状态接口不应暴露告警邮箱');
});

test('逻辑: 删除监控项同时清理探针上报数据', async () => {
  const ctx = makeCtx();
  const m = await create(ctx, {
    probes: [{ id: 'cn-1', type: 'external', region: 'cn-sh' }],
  });
  await ctx.req('/api/ingest', {
    method: 'POST', headers: probe,
    body: JSON.stringify({ monitorId: m.id, probeId: 'cn-1', ok: true, status: 200, latencyMs: 10 }),
  });
  assert.ok(await ctx.KV.get(`probe:${m.id}:cn-1`, 'json'));
  await ctx.req(`/api/monitors/${m.id}`, { method: 'DELETE', headers: admin });
  assert.equal(await ctx.KV.get(`probe:${m.id}:cn-1`, 'json'), null);
  assert.equal(await ctx.KV.get(`history:${m.id}`, 'json'), null);
});
