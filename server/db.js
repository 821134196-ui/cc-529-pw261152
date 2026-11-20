import { DatabaseSync } from 'node:sqlite';

export const SENSITIVITY_LABELS = { 1: '公开', 2: '内部', 3: '机密', 4: '绝密' };

const SCHEMA = `
CREATE TABLE IF NOT EXISTS orgs (
  id INTEGER PRIMARY KEY,
  name TEXT NOT NULL,
  parent_id INTEGER REFERENCES orgs(id)
);
CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY,
  name TEXT NOT NULL,
  org_id INTEGER NOT NULL REFERENCES orgs(id),
  clearance INTEGER NOT NULL DEFAULT 1,
  is_admin INTEGER NOT NULL DEFAULT 0,
  perm_epoch INTEGER NOT NULL DEFAULT 1
);
CREATE TABLE IF NOT EXISTS metrics (
  id INTEGER PRIMARY KEY,
  code TEXT NOT NULL UNIQUE,
  name TEXT NOT NULL,
  sensitivity INTEGER NOT NULL,
  unit TEXT NOT NULL DEFAULT ''
);
CREATE TABLE IF NOT EXISTS metric_facts (
  id INTEGER PRIMARY KEY,
  metric_id INTEGER NOT NULL REFERENCES metrics(id),
  org_id INTEGER NOT NULL REFERENCES orgs(id),
  period TEXT NOT NULL,
  dim TEXT NOT NULL DEFAULT '',
  value REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS grants (
  id INTEGER PRIMARY KEY,
  user_id INTEGER NOT NULL REFERENCES users(id),
  org_id INTEGER NOT NULL REFERENCES orgs(id),
  include_desc INTEGER NOT NULL DEFAULT 1,
  kind TEXT NOT NULL CHECK(kind IN ('exception','temporary','revoke')),
  expires_at INTEGER,
  created_by INTEGER NOT NULL REFERENCES users(id),
  created_at INTEGER NOT NULL,
  revoked_at INTEGER,
  revoke_reason TEXT,
  swept_at INTEGER
);
CREATE INDEX IF NOT EXISTS idx_grants_user ON grants(user_id);
CREATE TABLE IF NOT EXISTS query_cache (
  cache_key TEXT PRIMARY KEY,
  user_id INTEGER NOT NULL,
  epoch INTEGER NOT NULL,
  payload TEXT NOT NULL,
  created_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS snapshots (
  id INTEGER PRIMARY KEY,
  user_id INTEGER NOT NULL,
  metric_id INTEGER NOT NULL,
  org_id INTEGER NOT NULL,
  period TEXT NOT NULL,
  kind TEXT NOT NULL DEFAULT 'query' CHECK(kind IN ('query','export')),
  hit_rules TEXT NOT NULL,
  result TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'valid' CHECK(status IN ('valid','invalidated')),
  invalid_reason TEXT,
  created_at INTEGER NOT NULL,
  invalidated_at INTEGER
);
CREATE INDEX IF NOT EXISTS idx_snapshots_user ON snapshots(user_id, status);
CREATE TABLE IF NOT EXISTS tasks (
  id INTEGER PRIMARY KEY,
  kind TEXT NOT NULL CHECK(kind IN ('export','query')),
  user_id INTEGER NOT NULL,
  metric_id INTEGER NOT NULL,
  org_id INTEGER NOT NULL,
  period TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'queued' CHECK(status IN ('queued','running','done','failed','cancelled')),
  cancel_reason TEXT,
  snapshot_id INTEGER,
  created_at INTEGER NOT NULL,
  started_at INTEGER,
  finished_at INTEGER
);
CREATE INDEX IF NOT EXISTS idx_tasks_status ON tasks(status);
CREATE TABLE IF NOT EXISTS audit (
  id INTEGER PRIMARY KEY,
  ts INTEGER NOT NULL,
  actor TEXT NOT NULL,
  action TEXT NOT NULL,
  detail TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_audit_ts ON audit(ts);
`;

export function createDb(path = ':memory:') {
  const db = new DatabaseSync(path);
  db.exec('PRAGMA journal_mode = WAL;');
  db.exec('PRAGMA foreign_keys = ON;');
  db.exec('PRAGMA busy_timeout = 3000;');
  db.exec(SCHEMA);
  return db;
}

/** 事务助手：同步函数原子执行，支持嵌套（嵌套时并入外层事务）。 */
const txDepth = new WeakMap();
export function tx(db, fn) {
  const depth = txDepth.get(db) || 0;
  if (depth > 0) return fn();
  db.exec('BEGIN IMMEDIATE');
  txDepth.set(db, 1);
  try {
    const r = fn();
    db.exec('COMMIT');
    return r;
  } catch (e) {
    try { db.exec('ROLLBACK'); } catch { /* already rolled back */ }
    throw e;
  } finally {
    txDepth.set(db, 0);
  }
}

export function seed(db) {
  const now = Date.now();
  tx(db, () => {
    const insOrg = db.prepare('INSERT INTO orgs (id, name, parent_id) VALUES (?, ?, ?)');
    insOrg.run(1, '集团总部', null);
    insOrg.run(2, '华东大区', 1);
    insOrg.run(3, '华北大区', 1);
    insOrg.run(4, '上海分公司', 2);
    insOrg.run(5, '杭州分公司', 2);
    insOrg.run(6, '北京分公司', 3);
    insOrg.run(7, '天津分公司', 3);

    const insUser = db.prepare('INSERT INTO users (id, name, org_id, clearance, is_admin) VALUES (?, ?, ?, ?, ?)');
    insUser.run(1, 'admin', 1, 4, 1);
    insUser.run(2, 'alice', 2, 3, 0);
    insUser.run(3, 'bob', 4, 2, 0);
    insUser.run(4, 'carol', 6, 1, 0);

    const insMetric = db.prepare('INSERT INTO metrics (id, code, name, sensitivity, unit) VALUES (?, ?, ?, ?, ?)');
    insMetric.run(1, 'revenue', '营收', 1, '万元');
    insMetric.run(2, 'orders', '订单量', 2, '单');
    insMetric.run(3, 'salary_cost', '人力成本', 3, '万元');
    insMetric.run(4, 'profit_margin', '利润率', 4, '%');

    const insFact = db.prepare('INSERT INTO metric_facts (metric_id, org_id, period, dim, value) VALUES (?, ?, ?, ?, ?)');
    const leafOrgs = [4, 5, 6, 7];
    const periods = ['2026-09', '2026-10'];
    const dims = ['产品线A', '产品线B', '产品线C'];
    for (const m of [1, 2, 3, 4]) {
      for (const o of leafOrgs) {
        periods.forEach((p, pi) => {
          dims.forEach((d, di) => {
            const value = Math.round(((m * 7 + o * 13 + di * 3 + pi * 11) % 50 + 10) * 100) / 100;
            insFact.run(m, o, p, d, value);
          });
        });
      }
    }
    db.prepare('INSERT INTO audit (ts, actor, action, detail) VALUES (?, ?, ?, ?)')
      .run(now, 'system', 'seed', JSON.stringify({ orgs: 7, users: 4, metrics: 4 }));
  });
}
