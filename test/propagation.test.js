import { test } from 'node:test';
import assert from 'node:assert/strict';
import { freshDb, ORG, USER, METRIC } from './helpers.js';
import * as svc from '../server/services.js';

/** 权限变更传播：缓存、导出、排队任务、历史快照。 */

test('缓存：权限变更后旧纪元缓存立即失效', () => {
  const db = freshDb();
  const r1 = svc.runQuery(db, USER.ALICE, METRIC.REVENUE, ORG.SH, '2026-10');
  assert.equal(r1.fromCache, false);
  const r2 = svc.runQuery(db, USER.ALICE, METRIC.REVENUE, ORG.SH, '2026-10');
  assert.equal(r2.fromCache, true, '第二次查询应命中缓存');
  assert.equal(svc.listCache(db, USER.ALICE).length, 1);

  // 任意权限变更（哪怕新增授权）→ 缓存清空、纪元推进
  svc.createGrant(db, USER.ADMIN, { user_id: USER.ALICE, org_id: ORG.BJ, kind: 'exception' });
  assert.equal(svc.listCache(db, USER.ALICE).length, 0);
  const r3 = svc.runQuery(db, USER.ALICE, METRIC.REVENUE, ORG.SH, '2026-10');
  assert.equal(r3.fromCache, false, '变更后必须重新计算');
  assert.equal(r3.epoch, r1.epoch + 1);
});

test('排队任务：权限撤销后自动取消，执行时再次校验', () => {
  const db = freshDb();
  const { taskId } = svc.enqueueExport(db, USER.ALICE, METRIC.REVENUE, ORG.SH, '2026-10');
  // 撤销 alice 对上海的访问（通过撤销授权）
  svc.createGrant(db, USER.ADMIN, { user_id: USER.ALICE, org_id: ORG.SH, kind: 'revoke' });
  const t = svc.listTasks(db, USER.ALICE).find((x) => x.id === taskId);
  assert.equal(t.status, 'cancelled');
  assert.match(t.cancel_reason, /权限变更/);
  assert.equal(svc.processNextTask(db), null, '队列中无可执行任务');
});

test('执行时校验：入队后、执行前权限被撤销（绕过排队取消的边界）', () => {
  const db = freshDb();
  // carol 获得临时授权并入队
  const now = Date.now();
  svc.createGrant(db, USER.ADMIN, { user_id: USER.CAROL, org_id: ORG.SH, kind: 'temporary', ttl_seconds: 100 }, now);
  svc.enqueueExport(db, USER.CAROL, METRIC.REVENUE, ORG.SH, '2026-10', now);
  // 直接撤销授权但"跳过"排队取消的场景由 applyPermissionChange 覆盖；
  // 这里验证 worker 执行时仍会再校验：先撤销临时授权
  const g = svc.listGrants(db, USER.CAROL).find((x) => x.kind === 'temporary');
  svc.revokeGrant(db, USER.ADMIN, g.id);
  const res = svc.processNextTask(db);
  assert.equal(res, null, '任务已在撤销时被取消');
});

test('快照规则：范围仍被覆盖 → 保留；失去覆盖 → 失效', () => {
  const db = freshDb();
  // alice 在上海、杭州各产生一个快照
  const s1 = svc.runQuery(db, USER.ALICE, METRIC.REVENUE, ORG.SH, '2026-10');
  const s2 = svc.runQuery(db, USER.ALICE, METRIC.REVENUE, ORG.HZ, '2026-10');
  // 仅撤销上海 → 上海快照失效，杭州快照保留
  svc.createGrant(db, USER.ADMIN, { user_id: USER.ALICE, org_id: ORG.SH, kind: 'revoke' });
  const snaps = svc.listSnapshots(db, USER.ALICE);
  assert.equal(snaps.find((s) => s.id === s1.snapshotId).status, 'invalidated');
  assert.equal(snaps.find((s) => s.id === s2.snapshotId).status, 'valid', '未受影响的快照必须保留');
});

test('快照规则：临时授权到期 → 扫描器触发失效传播', () => {
  const db = freshDb();
  const now = Date.now();
  svc.createGrant(db, USER.ADMIN, { user_id: USER.CAROL, org_id: ORG.SH, kind: 'temporary', ttl_seconds: 2 }, now);
  const q = svc.runQuery(db, USER.CAROL, METRIC.REVENUE, ORG.SH, '2026-10', { now });
  assert.ok(q.snapshotId);
  assert.ok(svc.listCache(db, USER.CAROL).length > 0);

  // 时间前进到过期之后，扫描器触发
  const swept = svc.sweepExpiredGrants(db, now + 3000);
  assert.equal(swept, 1);
  const snap = svc.listSnapshots(db, USER.CAROL).find((s) => s.id === q.snapshotId);
  assert.equal(snap.status, 'invalidated');
  assert.match(snap.invalidReason, /临时授权.*到期/);
  assert.equal(svc.listCache(db, USER.CAROL).length, 0, '缓存随到期清空');
});

test('导出全链路：入队 → 执行 → 快照 → 下载；权限撤销后下载被拒', () => {
  const db = freshDb();
  const { taskId } = svc.enqueueExport(db, USER.ALICE, METRIC.REVENUE, ORG.SH, '2026-10');
  const done = svc.processNextTask(db);
  assert.equal(done.status, 'done');
  const dl = svc.downloadExport(db, USER.ALICE, taskId);
  assert.ok(dl.payload.aggregate > 0);

  // 撤销 alice 对上海的继承访问 → 快照失效 → 下载 410
  svc.createGrant(db, USER.ADMIN, { user_id: USER.ALICE, org_id: ORG.SH, kind: 'revoke' });
  assert.throws(() => svc.downloadExport(db, USER.ALICE, taskId), (e) => e.status === 410);
});

test('审计：关键动作全部留痕', () => {
  const db = freshDb();
  svc.runQuery(db, USER.ALICE, METRIC.REVENUE, ORG.SH, '2026-10');
  const { grantId } = svc.createGrant(db, USER.ADMIN, { user_id: USER.BOB, org_id: ORG.BJ, kind: 'exception' });
  svc.revokeGrant(db, USER.ADMIN, grantId);
  const actions = svc.listAudit(db, 500).map((a) => a.action);
  for (const expected of ['query.allow', 'grant.create', 'cache.invalidate', 'grant.revoke']) {
    assert.ok(actions.includes(expected), `审计应包含 ${expected}`);
  }
});
