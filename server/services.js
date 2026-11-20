import { tx, SENSITIVITY_LABELS } from './db.js';
import { effectiveAccess, descendantsOf, authzTree } from './authz.js';

export class ApiError extends Error {
  constructor(status, message, extra = {}) {
    super(message);
    this.status = status;
    Object.assign(this, extra);
  }
}

export const getUser = (db, id) => {
  const u = db.prepare('SELECT * FROM users WHERE id = ?').get(id);
  if (!u) throw new ApiError(404, `用户 #${id} 不存在`);
  return u;
};
export const getMetric = (db, id) => {
  const m = db.prepare('SELECT * FROM metrics WHERE id = ?').get(id);
  if (!m) throw new ApiError(404, `指标 #${id} 不存在`);
  return m;
};
export const getOrg = (db, id) => {
  const o = db.prepare('SELECT * FROM orgs WHERE id = ?').get(id);
  if (!o) throw new ApiError(404, `组织 #${id} 不存在`);
  return o;
};

export function audit(db, actor, action, detail, now = Date.now()) {
  db.prepare('INSERT INTO audit (ts, actor, action, detail) VALUES (?, ?, ?, ?)')
    .run(now, actor, action, JSON.stringify(detail));
}

/**
 * 权限变更传播（必须在事务内调用）：
 *   1. perm_epoch +1 —— 旧纪元缓存键即刻不可达
 *   2. 物理清除该用户缓存
 *   3. 排队中的任务重新校验，失去权限的一律取消
 *   4. 历史快照按快照规则重新评估：范围仍被覆盖 → 保留；否则 → 失效
 */
function applyPermissionChangeTx(db, userId, reason, now) {
  const user = getUser(db, userId);
  db.prepare('UPDATE users SET perm_epoch = perm_epoch + 1 WHERE id = ?').run(userId);

  const del = db.prepare('DELETE FROM query_cache WHERE user_id = ?').run(userId);
  audit(db, user.name, 'cache.invalidate', { userId, removed: del.changes, reason }, now);

  const queued = db.prepare(
    "SELECT * FROM tasks WHERE user_id = ? AND status = 'queued'"
  ).all(userId);
  for (const t of queued) {
    const acc = effectiveAccess(db, user, t.org_id, now);
    if (!acc.allowed) {
      db.prepare("UPDATE tasks SET status = 'cancelled', cancel_reason = ?, finished_at = ? WHERE id = ?")
        .run(`权限变更：${reason}`, now, t.id);
      audit(db, user.name, 'task.cancel', { taskId: t.id, kind: t.kind, reason: `权限变更：${reason}` }, now);
    }
  }

  const snaps = db.prepare(
    "SELECT * FROM snapshots WHERE user_id = ? AND status = 'valid'"
  ).all(userId);
  for (const s of snaps) {
    const acc = effectiveAccess(db, user, s.org_id, now);
    if (!acc.allowed) {
      db.prepare("UPDATE snapshots SET status = 'invalidated', invalid_reason = ?, invalidated_at = ? WHERE id = ?")
        .run(`权限变更：${reason}`, now, s.id);
      audit(db, user.name, 'snapshot.invalidate', { snapshotId: s.id, orgId: s.org_id, reason }, now);
    }
  }
}

/** 创建授权（例外/临时/撤销）。越权保护：非管理员只能就自己有权访问的组织授权。 */
export function createGrant(db, actorId, input, now = Date.now()) {
  return tx(db, () => {
    const actor = getUser(db, actorId);
    const target = getUser(db, Number(input.user_id));
    const org = getOrg(db, Number(input.org_id));
    const kind = input.kind;
    if (!['exception', 'temporary', 'revoke'].includes(kind)) {
      throw new ApiError(400, `非法授权类型: ${kind}`);
    }
    const access = effectiveAccess(db, actor, org.id, now);
    if (!actor.is_admin && !access.allowed) {
      audit(db, actor.name, 'grant.deny', { targetUser: target.id, orgId: org.id, kind, reason: '越权授权' }, now);
      throw new ApiError(403, `越权拒绝：你对组织「${org.name}」无访问权，不能对其授权`, { rules: access.rules });
    }
    let expiresAt = null;
    if (kind === 'temporary') {
      const ttl = Number(input.ttl_seconds);
      if (!Number.isFinite(ttl) || ttl <= 0 || ttl > 86400 * 30) {
        throw new ApiError(400, '临时授权必须提供 ttl_seconds（0 < ttl ≤ 30 天）');
      }
      expiresAt = now + Math.round(ttl * 1000);
    }
    const includeDesc = input.include_desc === false ? 0 : 1;
    const r = db.prepare(
      'INSERT INTO grants (user_id, org_id, include_desc, kind, expires_at, created_by, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)'
    ).run(target.id, org.id, includeDesc, kind, expiresAt, actor.id, now);
    const grantId = Number(r.lastInsertRowid);
    audit(db, actor.name, 'grant.create', {
      grantId, userId: target.id, orgId: org.id, kind, expiresAt, includeDesc,
    }, now);
    applyPermissionChangeTx(db, target.id, `新增${kindLabel(kind)}授权 #${grantId}`, now);
    return { grantId };
  });
}

/** 撤销已有授权。越权保护：仅管理员或授权的创建者可撤销。 */
export function revokeGrant(db, actorId, grantId, reason = '', now = Date.now()) {
  return tx(db, () => {
    const actor = getUser(db, actorId);
    const g = db.prepare('SELECT * FROM grants WHERE id = ?').get(Number(grantId));
    if (!g) throw new ApiError(404, `授权 #${grantId} 不存在`);
    if (g.revoked_at) throw new ApiError(409, `授权 #${grantId} 已被撤销`);
    if (!actor.is_admin && g.created_by !== actor.id) {
      audit(db, actor.name, 'grant.revoke.deny', { grantId, reason: '越权撤销' }, now);
      throw new ApiError(403, '越权拒绝：仅管理员或授权创建者可撤销该授权');
    }
    db.prepare('UPDATE grants SET revoked_at = ?, revoke_reason = ? WHERE id = ?')
      .run(now, reason || `由 ${actor.name} 撤销`, g.id);
    audit(db, actor.name, 'grant.revoke', { grantId: g.id, userId: g.user_id, orgId: g.org_id, kind: g.kind }, now);
    applyPermissionChangeTx(db, g.user_id, `授权 #${g.id} 被撤销`, now);
    return { ok: true };
  });
}

/** 临时授权到期扫描：过期即触发完整的权限变更传播。 */
export function sweepExpiredGrants(db, now = Date.now()) {
  return tx(db, () => {
    const expired = db.prepare(
      "SELECT * FROM grants WHERE kind = 'temporary' AND revoked_at IS NULL AND swept_at IS NULL AND expires_at <= ?"
    ).all(now);
    for (const g of expired) {
      db.prepare('UPDATE grants SET swept_at = ? WHERE id = ?').run(now, g.id);
      audit(db, 'system', 'grant.expire', { grantId: g.id, userId: g.user_id, orgId: g.org_id }, now);
      applyPermissionChangeTx(db, g.user_id, `临时授权 #${g.id} 到期`, now);
    }
    return expired.length;
  });
}

function kindLabel(kind) {
  return { exception: '例外', temporary: '临时', revoke: '撤销' }[kind] || kind;
}

/**
 * 指标查询：授权校验 → 敏感级别明细限制 → 纪元缓存 → 快照落库。
 */
export function runQuery(db, userId, metricId, orgId, period, opts = {}) {
  const now = opts.now || Date.now();
  const snapshotKind = opts.snapshotKind || 'query';
  return tx(db, () => {
    const user = getUser(db, userId);
    const metric = getMetric(db, metricId);
    getOrg(db, orgId);
    const access = effectiveAccess(db, user, orgId, now);
    if (!access.allowed) {
      audit(db, user.name, 'query.deny', { metricId, orgId, period, rules: access.rules }, now);
      throw new ApiError(403, '无权访问该组织的指标数据', { rules: access.rules });
    }
    const detailAllowed = user.clearance >= metric.sensitivity;
    const rules = [...access.rules, {
      type: 'sensitivity',
      label: detailAllowed
        ? `敏感级别 L${metric.sensitivity}（${SENSITIVITY_LABELS[metric.sensitivity]}）≤ 用户密级 L${user.clearance} → 明细可见`
        : `敏感级别 L${metric.sensitivity}（${SENSITIVITY_LABELS[metric.sensitivity]}）> 用户密级 L${user.clearance} → 明细受限，仅返回汇总`,
    }];

    const epoch = getUser(db, userId).perm_epoch;
    const cacheKey = `${userId}:${metricId}:${orgId}:${period}:e${epoch}`;
    const hit = db.prepare('SELECT payload FROM query_cache WHERE cache_key = ? AND epoch = ?')
      .get(cacheKey, epoch);
    if (hit && snapshotKind === 'query') {
      audit(db, user.name, 'query.allow', { metricId, orgId, period, cache: 'hit', epoch }, now);
      return { ...JSON.parse(hit.payload), fromCache: true, hitRules: rules, epoch };
    }

    const subtree = descendantsOf(db, orgId);
    const placeholders = subtree.map(() => '?').join(',');
    const agg = db.prepare(
      `SELECT COALESCE(SUM(value), 0) AS total, COUNT(*) AS rows FROM metric_facts
       WHERE metric_id = ? AND period = ? AND org_id IN (${placeholders})`
    ).get(metricId, period, ...subtree);
    let details = [];
    if (detailAllowed) {
      details = db.prepare(
        `SELECT f.org_id AS orgId, o.name AS orgName, f.dim, f.value
         FROM metric_facts f JOIN orgs o ON o.id = f.org_id
         WHERE f.metric_id = ? AND f.period = ? AND f.org_id IN (${placeholders})
         ORDER BY f.org_id, f.dim`
      ).all(metricId, period, ...subtree);
    }
    const result = {
      metric: { id: metric.id, code: metric.code, name: metric.name, sensitivity: metric.sensitivity, unit: metric.unit },
      orgId, period,
      aggregate: Math.round(agg.total * 100) / 100,
      aggregateRows: agg.rows,
      detailRestricted: !detailAllowed,
      details,
    };
    db.prepare('INSERT OR REPLACE INTO query_cache (cache_key, user_id, epoch, payload, created_at) VALUES (?, ?, ?, ?, ?)')
      .run(cacheKey, userId, epoch, JSON.stringify(result), now);
    const snap = db.prepare(
      'INSERT INTO snapshots (user_id, metric_id, org_id, period, kind, hit_rules, result, status, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)'
    ).run(userId, metricId, orgId, period, snapshotKind, JSON.stringify(rules), JSON.stringify(result), 'valid', now);
    const snapshotId = Number(snap.lastInsertRowid);
    audit(db, user.name, 'query.allow', { metricId, orgId, period, cache: 'miss', epoch, snapshotId, snapshotKind }, now);
    return { ...result, fromCache: false, hitRules: rules, snapshotId, epoch };
  });
}

/** 导出任务入队：入队前做授权预检。 */
export function enqueueExport(db, userId, metricId, orgId, period, now = Date.now()) {
  return tx(db, () => {
    const user = getUser(db, userId);
    getMetric(db, metricId);
    getOrg(db, orgId);
    const access = effectiveAccess(db, user, orgId, now);
    if (!access.allowed) {
      audit(db, user.name, 'task.enqueue.deny', { kind: 'export', metricId, orgId }, now);
      throw new ApiError(403, '无权访问该组织，导出任务被拒绝', { rules: access.rules });
    }
    const r = db.prepare(
      "INSERT INTO tasks (kind, user_id, metric_id, org_id, period, status, created_at) VALUES ('export', ?, ?, ?, ?, 'queued', ?)"
    ).run(userId, metricId, orgId, period, now);
    const taskId = Number(r.lastInsertRowid);
    audit(db, user.name, 'task.enqueue', { taskId, kind: 'export', metricId, orgId, period }, now);
    return { taskId };
  });
}

/** 任务工作器：取出队首任务，执行前再次校验权限（覆盖入队后的权限变更）。 */
export function processNextTask(db, now = Date.now()) {
  return tx(db, () => {
    const t = db.prepare("SELECT * FROM tasks WHERE status = 'queued' ORDER BY id LIMIT 1").get();
    if (!t) return null;
    db.prepare("UPDATE tasks SET status = 'running', started_at = ? WHERE id = ?").run(now, t.id);
    const user = getUser(db, t.user_id);
    const access = effectiveAccess(db, user, t.org_id, now);
    if (!access.allowed) {
      db.prepare("UPDATE tasks SET status = 'cancelled', cancel_reason = ?, finished_at = ? WHERE id = ?")
        .run('执行时权限校验失败：授权已变更', now, t.id);
      audit(db, user.name, 'task.cancel', { taskId: t.id, reason: '执行时权限校验失败' }, now);
      return { taskId: t.id, status: 'cancelled' };
    }
    try {
      const res = runQuery(db, t.user_id, t.metric_id, t.org_id, t.period, { now, snapshotKind: 'export' });
      db.prepare("UPDATE tasks SET status = 'done', snapshot_id = ?, finished_at = ? WHERE id = ?")
        .run(res.snapshotId, now, t.id);
      audit(db, user.name, 'task.done', { taskId: t.id, kind: t.kind, snapshotId: res.snapshotId }, now);
      return { taskId: t.id, status: 'done', snapshotId: res.snapshotId };
    } catch (e) {
      db.prepare("UPDATE tasks SET status = 'failed', cancel_reason = ?, finished_at = ? WHERE id = ?")
        .run(String(e.message || e), now, t.id);
      audit(db, user.name, 'task.fail', { taskId: t.id, error: String(e.message || e) }, now);
      return { taskId: t.id, status: 'failed' };
    }
  });
}

/** 下载导出物：任务完成 + 快照有效 + 当前仍有权限，三者缺一不可。 */
export function downloadExport(db, actorId, taskId, now = Date.now()) {
  const actor = getUser(db, actorId);
  const t = db.prepare('SELECT * FROM tasks WHERE id = ?').get(Number(taskId));
  if (!t) throw new ApiError(404, `任务 #${taskId} 不存在`);
  if (!actor.is_admin && t.user_id !== actor.id) {
    throw new ApiError(403, '越权拒绝：不能下载他人的导出结果');
  }
  if (t.status !== 'done' || !t.snapshot_id) {
    throw new ApiError(409, `任务 #${taskId} 状态为 ${t.status}，不可下载`);
  }
  const s = db.prepare('SELECT * FROM snapshots WHERE id = ?').get(t.snapshot_id);
  if (!s || s.status !== 'valid') {
    throw new ApiError(410, `快照已失效：${s?.invalid_reason || '不存在'}`, { invalidReason: s?.invalid_reason });
  }
  const owner = getUser(db, t.user_id);
  const access = effectiveAccess(db, owner, t.org_id, now);
  if (!access.allowed) {
    throw new ApiError(403, '数据所属授权已变更，按快照规则该结果不可再获取', { rules: access.rules });
  }
  audit(db, actor.name, 'export.download', { taskId: t.id, snapshotId: s.id }, now);
  return { task: t, snapshot: s, payload: JSON.parse(s.result) };
}

/* ---------- 查询接口（页面数据） ---------- */

export function listGrants(db, userId) {
  const rows = db.prepare(`
    SELECT g.*, u.name AS userName, o.name AS orgName, c.name AS creatorName
    FROM grants g JOIN users u ON u.id = g.user_id JOIN orgs o ON o.id = g.org_id
    JOIN users c ON c.id = g.created_by
    ${userId ? 'WHERE g.user_id = ?' : ''} ORDER BY g.id DESC`
  ).all(...(userId ? [userId] : []));
  const now = Date.now();
  return rows.map((g) => ({
    ...g,
    active: !g.revoked_at && (g.kind !== 'temporary' || g.expires_at > now),
    expired: g.kind === 'temporary' && g.expires_at <= now,
  }));
}

export function listTasks(db, userId) {
  return db.prepare(`
    SELECT t.*, u.name AS userName, m.name AS metricName, o.name AS orgName
    FROM tasks t JOIN users u ON u.id = t.user_id
    JOIN metrics m ON m.id = t.metric_id JOIN orgs o ON o.id = t.org_id
    ${userId ? 'WHERE t.user_id = ?' : ''} ORDER BY t.id DESC LIMIT 100`
  ).all(...(userId ? [userId] : []));
}

export function listSnapshots(db, userId) {
  return db.prepare(`
    SELECT s.id, s.user_id AS userId, u.name AS userName, s.metric_id AS metricId, m.name AS metricName,
           s.org_id AS orgId, o.name AS orgName, s.period, s.kind, s.hit_rules AS hitRules,
           s.status, s.invalid_reason AS invalidReason, s.created_at AS createdAt, s.invalidated_at AS invalidatedAt
    FROM snapshots s JOIN users u ON u.id = s.user_id
    JOIN metrics m ON m.id = s.metric_id JOIN orgs o ON o.id = s.org_id
    ${userId ? 'WHERE s.user_id = ?' : ''} ORDER BY s.id DESC LIMIT 200`
  ).all(...(userId ? [userId] : []));
}

export function listAudit(db, limit = 200) {
  return db.prepare('SELECT * FROM audit ORDER BY id DESC LIMIT ?').all(limit);
}

export function listCache(db, userId) {
  return db.prepare(
    'SELECT cache_key AS cacheKey, user_id AS userId, epoch, created_at AS createdAt FROM query_cache WHERE user_id = ? ORDER BY created_at DESC'
  ).all(userId);
}

export function bootstrap(db) {
  return {
    users: db.prepare('SELECT id, name, org_id AS orgId, clearance, is_admin AS isAdmin, perm_epoch AS permEpoch FROM users ORDER BY id').all(),
    orgs: db.prepare('SELECT id, name, parent_id AS parentId FROM orgs ORDER BY id').all(),
    metrics: db.prepare('SELECT id, code, name, sensitivity, unit FROM metrics ORDER BY id').all(),
    periods: ['2026-09', '2026-10'],
    sensitivityLabels: SENSITIVITY_LABELS,
  };
}

export { authzTree };
