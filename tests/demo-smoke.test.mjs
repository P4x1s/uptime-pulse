/**
 * Demo 核心链路测试（只读版）：SSRF / 检测判定 / 失败阈值 / 告警去重 / 恢复通知 / 可用率。
 * 监控目标由后台变量提供，全部依赖通过 env 注入，不依赖外网。
 */
import test from 'node:test';
import assert from 'node:assert/strict';
import {
  assertPublicTarget, isPrivateIp, safeEqual, runCheck, createWorker, hmacSign,
} from '../src/demo.mjs';

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

function makeEnv(overrides = {}) {
  const KV = new MockKV();
  const alerts = [];
  const calls = [];
  let responder = () => ({ status: 200 });
  const fetchImpl = async (url, init = {}) => {
    calls.push({ url, init });
    if (String(url).includes('alert.example.com')) {
      alerts.push({ url, headers: init.headers || {}, body: init.body });
      return new Response('', { status: 200 });
    }
    const result = responder();
    if (result.timeout) throw Object.assign(new Error('aborted'), { name: 'AbortError' });
    return new Response('', { status: result.status });
  };
  const resolveDns = async (host) => (host === 'dns-private.example.com' ? ['10.0.0.5'] : ['93.184.216.34']);
  const env = {
    KV, ADMIN_TOKEN: 'test-token', PROBE_REGION: 'test-line', MONITOR_TARGETS: '',
    WEBHOOK_URL: 'https://alert.example.com/hook', ALERT_SIGNING_SECRET: 'test-secret',
    resolveDns, fetchImpl,
  };
  return {
    env, KV, alerts, calls,
    setResponder: (fn) => { responder = fn; },
    setTargets: (targets) => { env.MONITOR_TARGETS = JSON.stringify(targets); },
    ...overrides,
  };
}

function makeMonitor(overrides = {}) {
  return {
    id: 'm1', name: '示例站', url: 'https://target.example.com', method: 'GET',
    expectedStatus: 200, timeoutMs: 1000, intervalSec: 60, failureThreshold: 3,
    alertCooldownSec: 300, webhookUrl: '', enabled: true,
    createdAt: new Date().toISOString(), lastRunAt: 0, ...overrides,
  };
}

test('SSRF: 私网 IP / localhost / 内网域名 / DNS 指向内网均被拒绝', async () => {
  const { env } = makeEnv();
  const bad = [
    'http://127.0.0.1', 'http://10.1.2.3', 'http://169.254.169.254/latest/meta-data',
    'http://[::1]/', 'http://[::ffff:7f00:1]/', 'http://[::ffff:127.0.0.1]/',
    'http://2130706433/', 'http://0x7f000001/',
    'http://localhost/x', 'http://foo.local', 'https://dns-private.example.com',
    'file:///etc/passwd', 'ftp://example.com',
  ];
  for (const url of bad) {
    await assert.rejects(() => assertPublicTarget(url, env.resolveDns), null, `应拒绝: ${url}`);
  }
  const good = await assertPublicTarget('https://example.com/path', env.resolveDns);
  assert.equal(good.hostname, 'example.com');
  assert.equal(isPrivateIp('100.64.0.1'), true);
  assert.equal(isPrivateIp('8.8.8.8'), false);
  assert.equal(safeEqual('abc', 'abc'), true);
  assert.equal(safeEqual('abc', 'abd'), false);
});

test('检测: 200 判正常，500 判异常，超时记录 timeout', async () => {
  const ctx = makeEnv();
  const m = makeMonitor();
  ctx.setResponder(() => ({ status: 200 }));
  let r = await runCheck(ctx.env, m);
  assert.equal(r.record.ok, true);
  assert.equal(r.record.status, 200);

  ctx.setResponder(() => ({ status: 500 }));
  r = await runCheck(ctx.env, m);
  assert.equal(r.record.ok, false);
  assert.equal(r.record.status, 500);

  ctx.setResponder(() => ({ timeout: true }));
  r = await runCheck(ctx.env, m);
  assert.equal(r.record.ok, false);
  assert.equal(r.record.error, 'timeout');
});

test('告警状态机: 阈值触发 / 同签名去重 / 恢复通知 / 签名可验证', async () => {
  const ctx = makeEnv();
  const m = makeMonitor();

  ctx.setResponder(() => ({ status: 200 }));
  for (let i = 0; i < 3; i++) await runCheck(ctx.env, m);
  assert.equal(ctx.alerts.length, 0, '正常时不应告警');

  ctx.setResponder(() => ({ status: 500 }));
  await runCheck(ctx.env, m); // 1
  await runCheck(ctx.env, m); // 2
  assert.equal(ctx.alerts.length, 0, '未达阈值不应告警');
  await runCheck(ctx.env, m); // 3 -> firing
  assert.equal(ctx.alerts.length, 1, '达到阈值应告警一次');
  const firing = JSON.parse(ctx.alerts[0].body);
  assert.equal(firing.type, 'firing');
  assert.ok(firing.state.incidentId, '应生成 incidentId');
  assert.equal(ctx.alerts[0].headers['x-uptimepulse-signature'],
    `sha256=${await hmacSign(ctx.alerts[0].body, 'test-secret')}`, 'HMAC 签名应可验证');

  await runCheck(ctx.env, m);
  await runCheck(ctx.env, m);
  assert.equal(ctx.alerts.length, 1, '同一事件同签名不应重复告警');

  ctx.setResponder(() => ({ status: 200 }));
  await runCheck(ctx.env, m);
  assert.equal(ctx.alerts.length, 2, '恢复应发送通知');
  assert.equal(JSON.parse(ctx.alerts[1].body).type, 'recovered');
  const state = await ctx.KV.get('incident:m1', 'json');
  assert.equal(state.state, 'ok');
  assert.equal(state.consecutiveFailures, 0);
});

test('可用率与异常记录: 状态接口按后台变量目标的历史计算', async () => {
  const ctx = makeEnv();
  const m = makeMonitor();
  ctx.setTargets([m]);
  ctx.setResponder(() => ({ status: 200 }));
  await runCheck(ctx.env, m);
  ctx.setResponder(() => ({ status: 500 }));
  await runCheck(ctx.env, makeMonitor({ failureThreshold: 99 }));
  const worker = createWorker(ctx.env);
  const resp = await worker.fetch(new Request('http://localhost/api/status'));
  const data = await resp.json();
  assert.equal(data.monitors.length, 1);
  assert.equal(data.monitors[0].samples, 2);
  assert.ok(Math.abs(data.monitors[0].uptime - 0.5) < 1e-9);
  assert.equal(data.recentErrors.length, 1);
  assert.equal(data.recentErrors[0].region, 'test-line');
});
