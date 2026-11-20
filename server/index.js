import http from 'node:http';
import { readFile } from 'node:fs/promises';
import { extname, join, normalize } from 'node:path';
import { fileURLToPath } from 'node:url';
import { createDb, seed } from './db.js';
import * as svc from './services.js';

const __dirname = fileURLToPath(new URL('.', import.meta.url));
const PUBLIC_DIR = join(__dirname, '..', 'public');
const PORT = Number(process.env.PORT || 3000);
const DB_PATH = process.env.DB_PATH || ':memory:';

const db = createDb(DB_PATH);
seed(db);

const MIME = {
  '.html': 'text/html; charset=utf-8',
  '.js': 'text/javascript; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.json': 'application/json; charset=utf-8',
  '.svg': 'image/svg+xml',
};

function send(res, status, body, headers = {}) {
  const isObj = typeof body === 'object' && body !== null && !Buffer.isBuffer(body);
  const payload = isObj ? JSON.stringify(body) : body;
  res.writeHead(status, {
    'Content-Type': isObj ? 'application/json; charset=utf-8' : (headers['Content-Type'] || 'text/plain; charset=utf-8'),
    ...headers,
  });
  res.end(payload);
}

async function readBody(req) {
  const chunks = [];
  for await (const c of req) chunks.push(c);
  if (!chunks.length) return {};
  try {
    return JSON.parse(Buffer.concat(chunks).toString('utf8'));
  } catch {
    throw new svc.ApiError(400, '请求体不是合法 JSON');
  }
}

const actorOf = (req) => Number(req.headers['x-actor-id'] || 1);

const routes = [
  ['GET', '/api/bootstrap', (req, res) => send(res, 200, svc.bootstrap(db))],
  ['GET', '/api/authz-tree', (req, res, q) => {
    const user = svc.getUser(db, Number(q.get('user_id')));
    send(res, 200, svc.authzTree(db, user));
  }],
  ['GET', '/api/grants', (req, res, q) => {
    send(res, 200, svc.listGrants(db, q.get('user_id') ? Number(q.get('user_id')) : null));
  }],
  ['POST', '/api/grants', async (req, res) => {
    const body = await readBody(req);
    send(res, 201, svc.createGrant(db, actorOf(req), body));
  }],
  ['POST', '/api/grants/:id/revoke', async (req, res, q, m) => {
    const body = await readBody(req);
    send(res, 200, svc.revokeGrant(db, actorOf(req), m.id, body.reason));
  }],
  ['POST', '/api/query', async (req, res) => {
    const b = await readBody(req);
    send(res, 200, svc.runQuery(db, Number(b.user_id), Number(b.metric_id), Number(b.org_id), String(b.period || '2026-10')));
  }],
  ['POST', '/api/exports', async (req, res) => {
    const b = await readBody(req);
    send(res, 201, svc.enqueueExport(db, Number(b.user_id), Number(b.metric_id), Number(b.org_id), String(b.period || '2026-10')));
  }],
  ['GET', '/api/tasks', (req, res, q) => {
    send(res, 200, svc.listTasks(db, q.get('user_id') ? Number(q.get('user_id')) : null));
  }],
  ['GET', '/api/tasks/:id/download', (req, res, q, m) => {
    const { payload, task } = svc.downloadExport(db, actorOf(req), m.id);
    send(res, 200, JSON.stringify(payload, null, 2), {
      'Content-Type': 'application/json; charset=utf-8',
      'Content-Disposition': `attachment; filename="export-task-${task.id}.json"`,
    });
  }],
  ['GET', '/api/snapshots', (req, res, q) => {
    send(res, 200, svc.listSnapshots(db, q.get('user_id') ? Number(q.get('user_id')) : null));
  }],
  ['GET', '/api/cache', (req, res, q) => {
    send(res, 200, svc.listCache(db, Number(q.get('user_id') || 0)));
  }],
  ['GET', '/api/audit', (req, res) => send(res, 200, svc.listAudit(db, 300))],
];

function matchRoute(method, pathname) {
  for (const [m, pattern, handler] of routes) {
    if (m !== method) continue;
    const pp = pattern.split('/');
    const ap = pathname.split('/');
    if (pp.length !== ap.length) continue;
    const params = {};
    let ok = true;
    for (let i = 0; i < pp.length; i++) {
      if (pp[i].startsWith(':')) params[pp[i].slice(1)] = decodeURIComponent(ap[i]);
      else if (pp[i] !== ap[i]) { ok = false; break; }
    }
    if (ok) return { handler, params };
  }
  return null;
}

async function serveStatic(req, res, pathname) {
  const rel = pathname === '/' ? 'index.html' : pathname.slice(1);
  const file = normalize(join(PUBLIC_DIR, rel));
  if (!file.startsWith(PUBLIC_DIR)) return send(res, 403, 'Forbidden');
  try {
    const data = await readFile(file);
    send(res, 200, data, { 'Content-Type': MIME[extname(file)] || 'application/octet-stream' });
  } catch {
    send(res, 404, 'Not Found');
  }
}

const server = http.createServer(async (req, res) => {
  const url = new URL(req.url, `http://${req.headers.host || 'localhost'}`);
  try {
    if (url.pathname.startsWith('/api/')) {
      const matched = matchRoute(req.method, url.pathname);
      if (!matched) return send(res, 404, { error: '接口不存在' });
      return await matched.handler(req, res, url.searchParams, matched.params);
    }
    return await serveStatic(req, res, url.pathname);
  } catch (e) {
    const status = e.status || 500;
    if (status >= 500) console.error(e);
    send(res, status, { error: e.message || '服务器错误', ...(e.rules ? { rules: e.rules } : {}), ...(e.invalidReason ? { invalidReason: e.invalidReason } : {}) });
  }
});

// 任务工作器：每 2s 处理一个排队任务（让"排队→取消/完成"在页面上可观察）
const worker = setInterval(() => {
  try { svc.processNextTask(db); } catch (e) { console.error('worker error', e); }
}, 2000);
// 临时授权到期扫描器：每 1s 触发一次失效传播
const sweeper = setInterval(() => {
  try { svc.sweepExpiredGrants(db); } catch (e) { console.error('sweeper error', e); }
}, 1000);

server.listen(PORT, () => {
  console.log(`多组织指标查询应用已启动: http://localhost:${PORT}  (db: ${DB_PATH})`);
});

function shutdown() {
  clearInterval(worker);
  clearInterval(sweeper);
  server.close(() => process.exit(0));
  setTimeout(() => process.exit(0), 500).unref();
}
process.on('SIGINT', shutdown);
process.on('SIGTERM', shutdown);
