/**
 * 代码内集中配置 + 截图风格 UI 的专项测试（零第三方依赖）
 */
import test from 'node:test';
import assert from 'node:assert/strict';
import { createWorker, runDueChecks } from '../src/index.mjs';
import { dashboardHtml, APP_CSS, APP_JS } from '../src/demo.mjs';
import { MONITORS, resolveAlertConfig, buildWebhookBody } from '../src/config.mjs';

class MockKV {
  constructor() { this.store = new Map(); }
  async get(key, type) {
    const v = this.store.get(key);
    return v === undefined ? null : (type === 'json' ? JSON.parse(v) : v);
  }
  async put(key, value) { this.store.set(key, typeof value === 'string' ? value : JSON.stringify(value)); }
}

function makeEnv(overrides = {}) {
  const KV = new MockKV();
  const outbound = [], webhooks = [], emails = [];
  const fetchImpl = async (url, init = {}) => {
    const u = String(url);
    if (u.includes('api.resend.com')) { emails.push({ body: JSON.parse(init.body), auth: init.headers?.authorization }); return new Response('', { status: 200 }); }
    if (u.includes('alert.example.com')) { webhooks.push({ url: u, body: JSON.parse(init.body) }); return new Response('', { status: 200 }); }
    outbound.push(u);
    return new Response('', { status: 200 });
  };
  const env = {
    KV, PROBE_TOKEN: 'probe-secret', PROBE_REGION: 'cf-test',
    resolveDns: async () => ['93.184.216.34'], fetchImpl, ...overrides,
  };
  return { env, KV, outbound, webhooks, emails, worker: createWorker(env) };
}

function target(overrides = {}) {
  return {
    id: 'm1', name: '服务 A', url: 'https://a.example.com', type: 'service', group: 'Public',
    failureThreshold: 1, probes: [{ id: 'edge-main', type: 'edge', region: 'cf-edge' }], ...overrides,
  };
}

// ---------- 代码内集中配置 ----------
test('默认监控列表来自 src/config.mjs，支持网站与服务、名称、地址、类型、启用与检测参数', () => {
  assert.ok(MONITORS.length >= 3, '配置中应内置多个示例目标');
  for (const m of MONITORS) {
    assert.ok(m.id && m.name && m.url, '每项必须有 id/name/url');
    assert.ok(['website', 'api', 'service'].includes(m.type), 'type 应为 website/api/service');
    assert.equal(typeof m.enabled, 'boolean');
    assert.ok(m.timeoutMs >= 1000 && m.intervalSec >= 60 && m.failureThreshold >= 1);
  }
  assert.ok(MONITORS.some((m) => m.type === 'service'), '应包含服务类型');
});

test('每个目标独立检测：不同地址分别发起探测并写入各自历史', async () => {
  const ctx = makeEnv(); // 不注入 MONITORS → 使用代码内配置
  await runDueChecks(ctx.env, true);
  const enabled = MONITORS.filter((m) => m.enabled !== false);
  assert.equal(ctx.outbound.length, enabled.length, '每个启用目标各探测一次');
  for (const m of enabled) {
    assert.ok(ctx.outbound.some((u) => u.startsWith(new URL(m.url).origin)), `${m.name} 应被独立探测`);
    assert.notEqual(await ctx.KV.get(`history:${m.id}`), null, `${m.name} 应有独立历史`);
  }
});

test('配置中禁用某项后不再检测也不在状态页展示', async () => {
  const ctx = makeEnv({ MONITORS: [target(), target({ id: 'm2', name: '服务 B', url: 'https://b.example.com', enabled: false })] });
  await runDueChecks(ctx.env, true);
  assert.equal(ctx.outbound.length, 1, '只检测启用的目标');
  const resp = await ctx.worker.fetch(new Request('http://localhost/api/status'));
  const data = await resp.json();
  assert.deepEqual(data.monitors.map((m) => m.id), ['m1']);
});

test('多目标故障互不影响：仅异常项触发告警', async () => {
  const ctx = makeEnv({
    MONITORS: [target(), target({ id: 'm2', name: '服务 B', url: 'https://b.example.com' })],
    WEBHOOK_URL: 'https://alert.example.com/hook', resolveDns: async () => ['93.184.216.34'],
  });
  let badHost = false;
  ctx.env.fetchImpl = async (url, init = {}) => {
    const u = String(url);
    if (u.includes('alert.example.com')) { ctx.webhooks.push({ url: u, body: JSON.parse(init.body) }); return new Response('', { status: 200 }); }
    if (u.includes('b.example.com')) return new Response('', { status: 503 });
    return new Response('', { status: 200 });
  };
  await runDueChecks(ctx.env, true);
  assert.equal(ctx.webhooks.length, 1);
  assert.equal(ctx.webhooks[0].body.monitor.id, 'm2');
  const data = await (await ctx.worker.fetch(new Request('http://localhost/api/status'))).json();
  assert.deepEqual(data.monitors.map((m) => m.state), ['ok', 'firing']);
  assert.equal(badHost, false);
});

// ---------- 告警配置化 ----------
test('告警地址与开关来自环境变量，不写死；显式关闭生效', async () => {
  const env = {
    WEBHOOK_URL: 'https://legacy.example.com/old',
    ALERT_WEBHOOK_URL: 'https://alert.example.com/new', ALERT_EMAIL_TO: 'ops@example.com',
    RESEND_API_KEY: 're_key', EMAIL_FROM: 'alerts@example.com',
  };
  let cfg = resolveAlertConfig(env);
  assert.equal(cfg.webhook.url, 'https://alert.example.com/new');
  assert.equal(cfg.email.to, 'ops@example.com');
  assert.equal(cfg.webhook.enabled, true);
  assert.equal(cfg.email.enabled, true);

  cfg = resolveAlertConfig({ ...env, ALERT_WEBHOOK_ENABLED: 'false', ALERT_EMAIL_ENABLED: '0' });
  assert.equal(cfg.webhook.enabled, false, '开关可显式关闭 Webhook');
  assert.equal(cfg.email.enabled, false, '开关可显式关闭邮件');

  const ctx = makeEnv({ ...env, ALERT_WEBHOOK_ENABLED: 'false', MONITORS: [target()] });
  ctx.env.fetchImpl = async (url, init = {}) => {
    if (String(url).includes('alert.example.com')) { ctx.webhooks.push({ url: String(url) }); return new Response('', { status: 200 }); }
    return new Response('', { status: 503 });
  };
  await runDueChecks(ctx.env, true);
  assert.equal(ctx.webhooks.length, 0, '关闭后不应投递 Webhook');
});

// ---------- 状态数据（供 UI 绘图） ----------
test('状态接口返回绘图所需的 history/type/group，且历史按时间倒序保留耗时', async () => {
  const ctx = makeEnv({ MONITORS: [target()] });
  await runDueChecks(ctx.env, true);
  await runDueChecks(ctx.env, true);
  const data = await (await ctx.worker.fetch(new Request('http://localhost/api/status'))).json();
  const m = data.monitors[0];
  assert.equal(m.type, 'service');
  assert.equal(m.group, 'Public');
  assert.equal(m.history.length, 2);
  assert.ok(m.history.every((p) => typeof p.latencyMs === 'number' && !Number.isNaN(Date.parse(p.checkedAt)) && typeof p.ok === 'boolean'));
  assert.equal(m.samples, 2);
  assert.equal(m.uptime, 1);
});

// ---------- 截图风格 UI ----------
test('UI 静态特征：浅色主题、顶部徽章与系统正常、分组卡片、状态条、响应时间曲线、只读', () => {
  const page = dashboardHtml();
  for (const s of ['系统一切正常', '最后更新于', 'id="heroIcon"', 'id="groups"', '只读状态面板']) {
    assert.ok(page.includes(s), `页面缺少 ${s}`);
  }
  assert.ok(APP_CSS.includes('background:#fff'), '应为浅色背景');
  assert.ok(APP_CSS.includes('#22c55e'), '应有绿色状态条');
  assert.ok(APP_CSS.includes('.spark'), '应有折线图样式');
  assert.ok(!APP_CSS.includes('#0f1115'), '不应残留深色主题');
  for (const s of ['响应时间(ms)', '在线', '总可用率', 'createElementNS', 'polyline', 'addEventListener', 'textContent']) {
    assert.ok(APP_JS.includes(s), `前端脚本缺少 ${s}`);
  }
  assert.ok(!APP_JS.includes('innerHTML'), '禁止 innerHTML');
});

// 零依赖 DOM shim：真正执行 APP_JS，验证渲染不报错且结构符合截图
test('UI 渲染：单分组多监控项渲染为状态条与折线图，顶部显示系统一切正常', async () => {
  class Node {
    constructor(tag) {
      this.tagName = tag; this.children = []; this._text = ''; this.attrs = {}; this.style = {};
      this.className = ''; this.listeners = {};
      const self = this;
      this.classList = {
        add(c) { if (!self.className.split(' ').includes(c)) self.className = (self.className + ' ' + c).trim(); },
        remove(c) { self.className = self.className.split(' ').filter((x) => x && x !== c).join(' '); },
        contains(c) { return self.className.split(' ').includes(c); },
        toggle(c) { if (self.classList.contains(c)) { self.classList.remove(c); return false; } self.classList.add(c); return true; },
      };
    }
    set textContent(v) { this._text = String(v); this.children = []; }
    get textContent() { return this._text + this.children.map((c) => c.textContent).join(''); }
    appendChild(n) { this.children.push(n); return n; }
    setAttribute(k, v) { this.attrs[k] = String(v); if (k === 'class') this.className = String(v); }
    getAttribute(k) { return this.attrs[k]; }
    addEventListener(ev, fn) { (this.listeners[ev] ||= []).push(fn); }
  }
  const ids = ['heroIcon', 'icoOk', 'icoBad', 'heroTitle', 'updatedAt', 'age', 'groups', 'msg'];
  const store = Object.fromEntries(ids.map((id) => [id, new Node('div')]));
  const document = {
    getElementById: (id) => store[id] || null,
    createElement: (tag) => new Node(tag),
    createElementNS: (_ns, tag) => new Node(tag),
  };
  const payload = {
    serverTime: new Date().toISOString(),
    monitors: [
      { id: 'a', name: 'My Personal Website', url: 'https://example.com', type: 'website', group: 'Public', state: 'ok', uptime: 1, history: Array.from({ length: 20 }, (_, i) => ({ checkedAt: new Date(Date.now() - (20 - i) * 60000).toISOString(), ok: true, latencyMs: 20 + i, status: 200 })) },
      { id: 'b', name: 'Blog Comment', url: 'https://github.com', type: 'service', group: 'Public', state: 'ok', uptime: 0.9995, history: Array.from({ length: 20 }, (_, i) => ({ checkedAt: new Date(Date.now() - (20 - i) * 60000).toISOString(), ok: i !== 7, latencyMs: 700 + i, status: i === 7 ? 500 : 200 })) },
    ],
  };
  const fetchMock = async () => ({ ok: true, json: async () => payload });
  new Function('document', 'fetch', 'setInterval', APP_JS)(document, fetchMock, () => 0);
  await new Promise((r) => setTimeout(r, 10));

  assert.equal(store.heroTitle.textContent, '系统一切正常');
  assert.equal(store.groups.children.length, 1, '应渲染一个 Public 分组');
  const card = store.groups.children[0];
  const body = card.children.find((c) => c.className === 'group-body');
  assert.ok(body, '分组应有可折叠内容');
  assert.equal(body.children.length, 2, '分组内应有两个监控项');
  const first = body.children[0];
  assert.ok(JSON.stringify(first).includes('My Personal Website'), '应显示监控名称');
  assert.ok(JSON.stringify(first).includes('总可用率: 100.0%'));
  assert.ok(JSON.stringify(first).includes('bars'), '应渲染历史状态条');
  assert.ok(JSON.stringify(first).includes('spark'), '应渲染响应时间折线图');
});

// ---------- 立即推送（本次：宕机/无法联通即推送） ----------
test('ALERT_FAILURE_THRESHOLD=1 时首次失败即推送，覆盖监控项自身阈值', async () => {
  const ctx = makeEnv({
    MONITORS: [target({ failureThreshold: 3 })], // 监控项自身阈值 3，应被变量覆盖
    ALERT_WEBHOOK_URL: 'https://alert.example.com/hook',
    ALERT_FAILURE_THRESHOLD: '1',
  });
  ctx.env.fetchImpl = async (url, init = {}) => {
    if (String(url).includes('alert.example.com')) {
      ctx.webhooks.push({ url: String(url), body: JSON.parse(init.body) });
      return new Response('', { status: 200 });
    }
    return new Response('', { status: 503 }); // 目标故障
  };
  await runDueChecks(ctx.env, true); // 仅一次检测
  assert.equal(ctx.webhooks.length, 1, '变量阈值为 1 时首次失败即应推送，无需等 3 次');
  assert.equal(ctx.webhooks[0].body.type, 'firing');
  const state = await ctx.KV.get('incident:m1', 'json');
  assert.equal(state.state, 'firing');
});

test('未设置 ALERT_FAILURE_THRESHOLD 时沿用监控项阈值，保持原行为', async () => {
  const ctx = makeEnv({
    MONITORS: [target({ failureThreshold: 3 })],
    ALERT_WEBHOOK_URL: 'https://alert.example.com/hook',
  });
  ctx.env.fetchImpl = async (url, init = {}) => {
    if (String(url).includes('alert.example.com')) {
      ctx.webhooks.push({ url: String(url), body: JSON.parse(init.body) });
      return new Response('', { status: 200 });
    }
    return new Response('', { status: 503 });
  };
  await runDueChecks(ctx.env, true); // 第 1 次失败
  assert.equal(ctx.webhooks.length, 0, '未设变量时不应首次就推送');
});

test('Webhook 地址原样保留查询参数（ntfy 预设文案不被破坏）', async () => {
  const ntfy = 'https://ntfy.example.com/test-token.send?text=【服务监测】&desp=监测服务出现故障！';
  const ctx = makeEnv({
    MONITORS: [target({ failureThreshold: 1 })],
    ALERT_WEBHOOK_URL: ntfy,
    ALERT_FAILURE_THRESHOLD: '1',
    resolveDns: async () => ['93.184.216.34'],
  });
  let delivered = null;
  ctx.env.fetchImpl = async (url, init = {}) => {
    if (String(url).includes('ntfy.example.com')) {
      delivered = { url: String(url), method: init.method, body: init.body };
      return new Response('', { status: 200 });
    }
    return new Response('', { status: 503 }); // 目标故障
  };
  await runDueChecks(ctx.env, true);
  assert.ok(delivered, '应向 ntfy 地址投递告警');
  assert.ok(delivered.url.includes('text=') && delivered.url.includes('desp='), '预设查询参数应保留');
  assert.ok(decodeURIComponent(delivered.url).includes('【服务监测】'), '预设文案应原样保留（URL 编码后等价）');
  assert.equal(delivered.method, 'POST');
});

test('Server酱 .send 端点自动改用 title/desp body，预设文案与故障详情都送达', async () => {
  const url = 'https://ntfy.example.com/test-token.send?text=【服务监测】&desp=监测服务出现故障！';
  const ctx = makeEnv({
    MONITORS: [target({ failureThreshold: 1 })],
    ALERT_WEBHOOK_URL: url,
    ALERT_FAILURE_THRESHOLD: '1',
    resolveDns: async () => ['93.184.216.34'],
  });
  let delivered = null;
  ctx.env.fetchImpl = async (u, init = {}) => {
    if (String(u).includes('ntfy.example.com')) {
      delivered = { url: String(u), body: JSON.parse(init.body) };
      return new Response('', { status: 200 });
    }
    return new Response('', { status: 503 });
  };
  await runDueChecks(ctx.env, true);
  assert.ok(delivered, '应投递告警');
  assert.equal(delivered.body.title, '【服务监测】', '预设标题应从 query 提取到 body');
  assert.ok(delivered.body.desp.startsWith('监测服务出现故障！'), '预设正文应保留');
  assert.ok(delivered.body.desp.includes('服务 A'), '正文应附故障详情');
  assert.ok(delivered.body.desp.includes('故障 firing'));
  assert.equal(delivered.body.type, undefined, 'Server酱端点不应发送完整 JSON payload');
});

test('buildWebhookBody 兼容标准端点与恢复通知', () => {
  const payload = {
    type: 'recovered', monitor: { id: 'm1', name: '服务 A', url: 'https://a.example.com' },
    result: { ok: true, status: 200, latencyMs: 12 }, state: { state: 'ok' }, timestamp: '2026-01-01T00:00:00.000Z',
  };
  assert.deepEqual(buildWebhookBody('https://alert.example.com/hook', payload).body, payload, '标准端点保持完整 payload');
  const serverchan = buildWebhookBody('https://ntfy.example.com/token.send?text=【服务监测】', payload);
  assert.equal(serverchan.style, 'serverchan');
  assert.equal(serverchan.body.title, '【服务监测】 已恢复');
  assert.ok(serverchan.body.desp.includes('恢复 recovered'));
});
