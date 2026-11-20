/**
 * 本地开发服务器：把 Node HTTP 请求转换为 Web Request，调用 Worker 入口。
 * 仅用于本地验证，不参与生产部署。所有外部依赖（DNS / fetch）显式注入，不放宽任何安全策略。
 */
import http from 'node:http';
import dns from 'node:dns/promises';
import path from 'node:path';
import { pathToFileURL } from 'node:url';

const workerArg = process.argv.find((a) => a.startsWith('--worker='));
const workerPath = workerArg ? workerArg.slice('--worker='.length) : 'src/demo.mjs';
const port = Number(process.env.PORT || 8787);

class MockKV {
  constructor() { this.store = new Map(); }
  async get(key, type) {
    const value = this.store.get(key);
    if (value === undefined) return null;
    return type === 'json' ? JSON.parse(value) : value;
  }
  async put(key, value) { this.store.set(key, typeof value === 'string' ? value : JSON.stringify(value)); }
  async delete(key) { this.store.delete(key); }
  async list() { return { keys: Array.from(this.store.keys()).map((name) => ({ name })) }; }
}

const resolveDns = async (host) => {
  try {
    const records = await dns.lookup(host, { all: true });
    return records.map((r) => r.address);
  } catch { return []; }
};

const moduleUrl = pathToFileURL(path.resolve(workerPath)).href;
const { createWorker } = await import(moduleUrl);

const env = {
  KV: new MockKV(),
  ADMIN_TOKEN: process.env.ADMIN_TOKEN || 'demo-admin-token',
  PROBE_REGION: process.env.PROBE_REGION || 'local-node',
  WEBHOOK_URL: process.env.WEBHOOK_URL || '',
  ALERT_SIGNING_SECRET: process.env.ALERT_SIGNING_SECRET || 'demo-signing-secret',
  RESEND_API_KEY: process.env.RESEND_API_KEY || '',
  EMAIL_FROM: process.env.EMAIL_FROM || '',
  PROBE_TOKEN: process.env.PROBE_TOKEN || 'demo-probe-token',
  // 默认使用 src/config.mjs 的 MONITORS；本地可用 MONITORS_JSON 覆盖以便调试
  MONITORS: process.env.MONITORS_JSON ? JSON.parse(process.env.MONITORS_JSON) : undefined,
  ALERT_WEBHOOK_ENABLED: process.env.ALERT_WEBHOOK_ENABLED || '',
  ALERT_WEBHOOK_URL: process.env.ALERT_WEBHOOK_URL || process.env.WEBHOOK_URL || '',
  ALERT_EMAIL_ENABLED: process.env.ALERT_EMAIL_ENABLED || '',
  ALERT_EMAIL_TO: process.env.ALERT_EMAIL_TO || process.env.EMAIL_TO || '',
  resolveDns,
  fetchImpl: (...args) => fetch(...args),
};

const worker = createWorker(env);

const server = http.createServer(async (req, res) => {
  try {
    const url = `http://${req.headers.host || 'localhost'}${req.url}`;
    const chunks = [];
    for await (const chunk of req) chunks.push(chunk);
    const rawBody = Buffer.concat(chunks);
    const headers = new Headers();
    for (const [key, value] of Object.entries(req.headers)) {
      if (Array.isArray(value)) value.forEach((v) => headers.append(key, v));
      else if (value !== undefined) headers.set(key, value);
    }
    const init = { method: req.method, headers };
    if (!['GET', 'HEAD'].includes(req.method) && rawBody.length) {
      init.body = rawBody;
      init.duplex = 'half';
    }
    const request = new Request(url, init);
    const response = await worker.fetch(request);
    const outHeaders = {};
    for (const [key, value] of response.headers) outHeaders[key] = value;
    res.writeHead(response.status, outHeaders);
    res.end(Buffer.from(await response.arrayBuffer()));
  } catch (error) {
    res.writeHead(500, { 'content-type': 'application/json' });
    res.end(JSON.stringify({ error: String(error && error.message || error) }));
  }
});

server.listen(port, () => {
  console.log(`UptimePulse dev server (${workerPath}) → http://localhost:${port}`);
  console.log(`只读模式：监控目标来自 src/config.mjs 的 MONITORS${env.MONITORS ? '（本地 MONITORS_JSON 覆盖）' : ''}`);
});
