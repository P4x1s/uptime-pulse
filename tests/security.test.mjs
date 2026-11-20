/**
 * UptimePulse 安全测试套件（只读版）
 * 覆盖：SSRF / 鉴权与写接口禁用 / XSS 与 CSP / 告警去重逻辑 /
 *       后台变量输入校验 / 变量更新同步 / 敏感信息泄漏。
 * 所有测试离线运行，外部依赖通过 env 注入。
 */
import test from 'node:test';
import assert from 'node:assert/strict';
import { createWorker, runDueChecks } from '../src/index.mjs';
import { assertPublicTarget, parseTargets } from '../src/demo.mjs';

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
    PROBE_REGION: 'cf-test', MONITORS: [],
    resolveDns: async (host) => (host === 'private.example.com' ? ['192.168.1.10'] : ['93.184.216.34']),
    fetchImpl,
  };
  const worker = createWorker(env);
  const req = (path, options = {}) => worker.fetch(new Request(`http://localhost${path}`, options));
  return {
    env, KV, req, webhooks, emails, outbound,
    check: () => runDueChecks(env, true),
    setTargets: (targets) => { env.MONITORS = targets; },
    setResponder: (fn) => { responder = fn; },
  };
}

function target(overrides = {}) {
  return {
    id: 'm1', name: '测试目标', url: 'https://target.example.com', failureThreshold: 1,
    alertCooldownSec: 300, probes: [{ id: 'edge-main', type: 'edge', region: 'cf-test' }],
    ...overrides,
  };
}

// ---------------- SSRF（检测阶段仍强制校验，后台变量不是绕过理由） ----------------
test('SSRF: 后台变量中的混淆 IP / 元数据 / 内网域名目标在检测时被拒绝', async () => {
  const attacks = [
    'http://127.0.0.1', 'http://0177.0.0.1/', 'http://127.1/',
    'http://0x7f.1/', 'http://2130706433/', 'http://[::1]/',
    'http://[::ffff:7f00:1]/', 'http://[::ffff:127.0.0.1]/',
    'http://169.254.169.254/latest/meta-data/iam/security-credentials/',
    'http://10.0.0.1/', 'http://192.168.1.1/', 'http://100.64.0.1/',
    'http://localhost:8080/', 'http://app.local/', 'http://x.internal/',
    'https://private.example.com/', 'file:///etc/passwd', 'javascript:alert(1)',
    'https://user:pass@example.com/',
  ];
  for (const url of attacks) {
    const ctx = makeCtx();
    ctx.setTargets([target({ url })]);
    await ctx.check();
    assert.equal(ctx.outbound.length, 0, `不得向恶意目标发起请求: ${url}`);
  }
});

test('SSRF: 监控目标不允许跟随重定向（阻断跳转内网）', async () => {
  const ctx = makeCtx();
  ctx.setTargets([target()]);
  ctx.setResponder(() => ({ status: 302, headers: { location: 'http://127.0.0.1/admin' } }));
  await ctx.check();
  const probeCall = ctx.outbound.find((c) => c.url.includes('target.example.com'));
  assert.ok(probeCall, '应发起探测');
  assert.equal(probeCall.init.redirect, 'manual', '必须禁止自动跟随重定向');
  assert.equal(probeCall.url, 'https://target.example.com/', '不应请求重定向目标');
});

test('SSRF: Webhook 目标同样被校验，后台变量不能绕过', async () => {
  const ctx = makeCtx();
  ctx.env.WEBHOOK_URL = '';
  ctx.setTargets([target({ webhookUrl: 'http://127.0.0.1:8080/hook' })]);
  ctx.setResponder(() => ({ status: 500 }));
  await ctx.check();
  assert.equal(ctx.webhooks.length, 0, '内网 Webhook 不得被投递');
  assert.ok(!ctx.outbound.some((c) => c.url.includes('127.0.0.1')));
  await assert.rejects(() => assertPublicTarget('file:///etc/passwd', ctx.env.resolveDns));
});

// ---------------- 鉴权与写接口禁用 ----------------
test('只读: 所有配置写接口一律禁用，任何令牌都无法改配置', async () => {
  const ctx = makeCtx();
  const body = '{"url":"https://target.example.com"}';
  const cases = [
    {}, { authorization: '' }, { authorization: 'Bearer ' },
    { authorization: 'Bearer Secr3t-Admin-Token' },
    { authorization: 'Bearer Secr3t-Probe-Token' },
    { authorization: 'bearer Secr3t-Admin-Token' },
    { authorization: 'Bearer Secr3t Admin Token' },
  ];
  for (const headers of cases) {
    for (const [method, path] of [
      ['POST', '/api/monitors'], ['PUT', '/api/monitors/m1'],
      ['DELETE', '/api/monitors/m1'], ['POST', '/api/check'],
    ]) {
      const r = await ctx.req(path, { method, headers: { ...headers, 'content-type': 'application/json' }, body });
      assert.equal(r.status, 405, `${method} ${path} 应禁用: ${JSON.stringify(headers)}`);
    }
  }
});

test('鉴权: 探针接口仍需令牌，管理员令牌不能回传探针数据', async () => {
  const ctx = makeCtx();
  ctx.setTargets([target()]);
  assert.equal((await ctx.req('/api/probes/tasks?probeId=edge-main')).status, 401);
  assert.equal((await ctx.req('/api/probes/tasks?probeId=edge-main', { headers: { authorization: 'Bearer wrong' } })).status, 401);
  assert.equal((await ctx.req('/api/probes/tasks?probeId=edge-main', { headers: { authorization: 'Bearer Secr3t-Probe-Token' } })).status, 200);
  assert.equal((await ctx.req('/api/ingest', {
    method: 'POST', headers: { authorization: 'Bearer Secr3t-Admin-Token', 'content-type': 'application/json' },
    body: JSON.stringify({ monitorId: 'm1', probeId: 'x', ok: true }),
  })).status, 401);
});

// ---------------- 只读前端 ----------------
test('只读前端: 无新增/编辑/删除/立即检测入口，CSP 严格且无内联脚本', async () => {
  const ctx = makeCtx();
  ctx.setTargets([target()]);
  const pageResp = await ctx.req('/');
  const page = await pageResp.text();
  for (const forbidden of ['addForm', '立即检测', '管理员令牌', '删除']) {
    assert.ok(!page.includes(forbidden), `首页不应出现: ${forbidden}`);
  }
  assert.ok(page.includes('只读'), '应明确标注只读');
  const csp = pageResp.headers.get('content-security-policy') || '';
  const scriptDirective = csp.split(';').map((s) => s.trim()).find((s) => s.startsWith('script-src')) || '';
  assert.ok(scriptDirective.includes("'self'"), 'script-src 应限制为 self');
  assert.ok(!scriptDirective.includes('unsafe-inline'), 'script-src 不应允许内联脚本');

  const js = await (await ctx.req('/app.js')).text();
  assert.ok(!js.includes('innerHTML'), '前端不得使用 innerHTML');
  assert.ok(!js.includes('/api/monitors'), '前端不应引用已移除的配置接口');
  assert.ok(!js.includes('prompt('), '前端不应弹出令牌输入');
  assert.ok(js.includes('textContent'), '前端应使用 textContent');
});

test('XSS: 后台变量中的名称不进入 HTML，前端使用 textContent', async () => {
  const ctx = makeCtx();
  const payload = '<img src=x onerror="alert(1)"></script><script>alert(2)</script>';
  ctx.setTargets([target({ name: payload })]);
  const page = await (await ctx.req('/')).text();
  assert.ok(!page.includes('onerror='), '首页 HTML 不应包含配置数据');
  const status = await (await ctx.req('/api/status')).json();
  assert.equal(status.monitors[0].name, payload, 'JSON 中保留原值，由前端安全渲染');
  const type = (await ctx.req('/api/status')).headers.get('content-type');
  assert.ok(type.includes('application/json'), 'API 必须返回 JSON 而非 HTML');
});

// ---------------- 告警逻辑 ----------------
test('逻辑: 错误文案变化不改变签名，冷却期内不重复告警', async () => {
  const ctx = makeCtx();
  ctx.setTargets([target({ failureThreshold: 1, alertCooldownSec: 300 })]);
  ctx.setResponder(() => ({ throw: Object.assign(new Error('network boom A'), { name: 'Error' }) }));
  await ctx.check();
  assert.equal(ctx.webhooks.length, 1);

  ctx.setResponder(() => ({ throw: Object.assign(new Error('network totally different message B'), { name: 'Error' }) }));
  await ctx.check();
  assert.equal(ctx.webhooks.length, 1, '同类别错误在冷却期内应去重');

  ctx.setResponder(() => ({ throw: Object.assign(new Error('aborted'), { name: 'AbortError' }) }));
  await ctx.check();
  assert.equal(ctx.webhooks.length, 2, '错误类别变化（timeout）应允许新通知');
});

test('逻辑: 恢复后再次故障生成新的 incidentId', async () => {
  const ctx = makeCtx();
  ctx.setTargets([target({ failureThreshold: 1, alertCooldownSec: 0 })]);
  ctx.setResponder(() => ({ status: 500 }));
  await ctx.check();
  const first = (await ctx.KV.get('incident:m1', 'json')).incidentId;
  ctx.setResponder(() => ({ status: 200 }));
  await ctx.check();
  ctx.setResponder(() => ({ status: 500 }));
  await ctx.check();
  const second = (await ctx.KV.get('incident:m1', 'json')).incidentId;
  assert.ok(first && second && first !== second, '新事件必须有新的 incidentId');
  assert.ok(ctx.webhooks.some((w) => w.body.type === 'recovered'));
});

// ---------------- 后台变量输入校验 ----------------
test('输入: 后台变量字段被钳制，非法目标/邮箱被清洗或过滤', async () => {
  const parsed = parseTargets(JSON.stringify([
    target({
      name: 'x'.repeat(500),
      emailTo: 'owner@example.com',
      probes: Array.from({ length: 20 }, (_, i) => ({ id: `<bad id ${i}>`, type: 'external', region: 'r' })),
    }),
    target({ id: 'm2', url: 'https://other.example.com', emailTo: 'not-an-email' }),
    { url: 'not-a-url' },
    { url: 'file:///etc/passwd' },
  ]));
  assert.equal(parsed.length, 2, '非法 URL 条目应被过滤');
  assert.equal(parsed[0].name.length, 80);
  assert.equal(parsed[0].probes.length, 10, '探针数量上限 10');
  assert.ok(parsed[0].probes.every((p) => /^[a-zA-Z0-9_-]+$/.test(p.id)), '探针 ID 应被清洗');
  assert.ok(parsed[0].emailTo === 'owner@example.com', '合法邮箱保留');
  assert.equal(parsed[1].emailTo, '', '非法邮箱被丢弃');
});

test('输入: 监控配置非法 JSON 或空值时安全降级为空列表', async () => {
  const ctx = makeCtx();
  for (const raw of ['', 'not-json', '{}', 'null']) {
    ctx.env.MONITORS = raw;
    const s = await (await ctx.req('/api/status')).json();
    assert.equal(s.monitors.length, 0);
  }
});

// ---------------- 信息泄漏 ----------------
test('信息泄漏: 响应体与响应头不包含任何密钥', async () => {
  const ctx = makeCtx();
  ctx.setTargets([target({ emailTo: 'owner@example.com' })]);
  ctx.setResponder(() => ({ status: 500 }));
  await ctx.check();
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

// ---------------- 本轮安全审计回归：SSRF / 告警可靠性 / 数据健壮性 ----------------
test('SSRF: 拒绝 IPv6 隧道（6to4/Teredo/NAT64）内嵌内网 IPv4', async () => {
  const dns = async () => ['93.184.216.34'];
  const { isPrivateIp } = await import('../src/demo.mjs');
  // 6to4 内嵌 127.0.0.1 / 10.0.0.1
  assert.equal(isPrivateIp('2002:7f00:1::'), true, '6to4 内嵌 127.0.0.1 必须判为内网');
  assert.equal(isPrivateIp('2002:a00:1::'), true, '6to4 内嵌 10.0.0.1 必须判为内网');
  // NAT64 内嵌 127.0.0.1
  assert.equal(isPrivateIp('64:ff9b::7f00:1'), true, 'NAT64 内嵌 127.0.0.1 必须判为内网');
  // Teredo 内嵌地址
  assert.equal(isPrivateIp('2001:0:53aa:64c:0:1234:7f00:1'), true, 'Teredo 内嵌地址必须判为内网');
  // IPv4-mapped 写法（十进制/十六进制）
  assert.equal(isPrivateIp('::ffff:127.0.0.1'), true);
  assert.equal(isPrivateIp('::ffff:7f00:1'), true);
  // 公网 IPv6 不应误判
  assert.equal(isPrivateIp('2001:4860:4860::8888'), false, '公网 IPv6 不得误判');
  for (const u of ['http://[2002:7f00:1::]/', 'http://[64:ff9b::7f00:1]/', 'http://[::ffff:127.0.0.1]/']) {
    await assert.rejects(() => assertPublicTarget(u, dns), null, `应拒绝 SSRF: ${u}`);
  }
});

test('SSRF: 拒绝整数/十六进制/八进制混淆 IP 写法', async () => {
  const dns = async () => ['93.184.216.34'];
  for (const u of ['http://0x7f000001/', 'http://0177.0.0.1/', 'http://2130706433/']) {
    await assert.rejects(() => assertPublicTarget(u, dns), null, `应拒绝混淆 IP: ${u}`);
  }
});

test('告警可靠性: Webhook HTTP 500 时不写冷却标记，下一轮立即重试', async () => {
  const ctx = makeCtx();
  ctx.setTargets([target({ failureThreshold: 1, alertCooldownSec: 300 })]);
  let fail = true;
  ctx.setResponder(() => ({ status: 503 }));
  const origFetch = ctx.env.fetchImpl;
  let attempts = 0;
  ctx.env.fetchImpl = async (url, init = {}) => {
    if (String(url).includes('alert.example.com')) {
      attempts += 1;
      if (fail) return new Response('', { status: 500 }); // 接收端故障
      ctx.webhooks.push({ url: String(url), body: JSON.parse(init.body) });
      return new Response('', { status: 200 });
    }
    return origFetch(url, init);
  };
  await ctx.check();
  assert.equal(attempts, 1, '首次故障应尝试投递');
  let st = await ctx.KV.get('incident:m1', 'json');
  assert.equal(st.lastAlertAt, 0, '投递失败不应写入冷却标记');
  assert.equal(st.lastSignature, null, '投递失败不应写入签名');
  // 目标保持故障，Webhook 恢复可用 -> 下一轮应立即重试
  fail = false;
  await ctx.check();
  assert.equal(attempts, 2, '投递失败后下一轮应立即重试，不得被冷却吞掉');
  assert.equal(ctx.webhooks.length, 1, '重试成功应被记录');
  st = await ctx.KV.get('incident:m1', 'json');
  assert.ok(st.lastAlertAt > 0, '成功投递后应写入冷却标记');
});

test('健壮性: 被污染的 KV 数组/对象不会使状态接口或检测轮次崩溃', async () => {
  const ctx = makeCtx();
  ctx.setTargets([target()]);
  // 故意写入非法类型
  await ctx.KV.put('history:m1', '"not-an-array"');
  await ctx.KV.put('events:m1', '123');
  await ctx.KV.put('incident:m1', '"corrupted"');
  const status = await (await ctx.req('/api/status')).json();
  assert.equal(status.monitors.length, 1, '状态接口应正常返回而非 500');
  await ctx.check();
  const history = await ctx.KV.get('history:m1', 'json');
  assert.ok(Array.isArray(history), '检测轮次应把污染数据修复为数组');
});
