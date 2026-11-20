import { test } from 'node:test';
import assert from 'node:assert/strict';
import { freshDb, ORG, USER, METRIC } from './helpers.js';
import * as svc from '../server/services.js';

/**
 * 并发授权验证：Node 单线程 + 同步 SQLite 事务保证每个变更原子提交；
 * 这里用 Promise.all 制造交错，验证最终状态一致性不变量。
 */

test('并发创建 50 个授权：全部成功、纪元严格递增、缓存清空', async () => {
  const db = freshDb();
  // 先制造一些缓存
  svc.runQuery(db, USER.BOB, METRIC.REVENUE, ORG.SH, '2026-10');
  assert.ok(svc.listCache(db, USER.BOB).length > 0);

  const before = svc.getUser(db, USER.BOB).perm_epoch;
  const N = 50;
  const results = await Promise.all(
    Array.from({ length: N }, (_, i) =>
      Promise.resolve().then(() =>
        svc.createGrant(db, USER.ADMIN, {
          user_id: USER.BOB, org_id: i % 2 ? ORG.BJ : ORG.TJ, kind: 'exception',
        })))
  );
  assert.equal(new Set(results.map((r) => r.grantId)).size, N, '授权 ID 全部唯一');
  const after = svc.getUser(db, USER.BOB).perm_epoch;
  assert.equal(after, before + N, '每次授权恰好推进一个纪元');
  assert.equal(svc.listCache(db, USER.BOB).length, 0, '并发授权后缓存全部失效');
  const grants = svc.listGrants(db, USER.BOB).filter((g) => !g.revoked_at);
  assert.equal(grants.length, N);
});

test('并发授权与查询交错：任何成功查询都必须对应有效授权', async () => {
  const db = freshDb();
  // carol 默认无权访问上海。并发执行：授权、查询、撤销、再查询。
  const ops = [];
  const successes = [];
  for (let i = 0; i < 20; i++) {
    ops.push(Promise.resolve().then(() => {
      const { grantId } = svc.createGrant(db, USER.ADMIN, { user_id: USER.CAROL, org_id: ORG.SH, kind: 'exception' });
      return grantId;
    }).then((grantId) => {
      try {
        svc.runQuery(db, USER.CAROL, METRIC.REVENUE, ORG.SH, '2026-10');
        successes.push(grantId);
      } catch (e) {
        assert.equal(e.status, 403, '只允许 403，不允许其他错误');
      }
      return svc.revokeGrant(db, USER.ADMIN, grantId);
    }));
  }
  await Promise.all(ops);
  // 全部撤销后：查询必须被拒绝，且缓存为空
  assert.throws(() => svc.runQuery(db, USER.CAROL, METRIC.REVENUE, ORG.SH, '2026-10'), (e) => e.status === 403);
  assert.equal(svc.listCache(db, USER.CAROL).length, 0);
  // carol 在上海的有效快照必须全部失效
  const valid = svc.listSnapshots(db, USER.CAROL).filter((s) => s.status === 'valid' && s.orgId === ORG.SH);
  assert.equal(valid.length, 0, '撤销后不允许残留有效快照');
});

test('并发入队 + 撤销：排队任务全部取消，无一执行', async () => {
  const db = freshDb();
  const { grantId } = svc.createGrant(db, USER.ADMIN, { user_id: USER.CAROL, org_id: ORG.SH, kind: 'exception' });
  // 并发入队 10 个导出
  const enqueued = await Promise.all(
    Array.from({ length: 10 }, () =>
      Promise.resolve().then(() => svc.enqueueExport(db, USER.CAROL, METRIC.REVENUE, ORG.SH, '2026-10')))
  );
  assert.equal(enqueued.length, 10);
  // 立即撤销授权（在 worker 处理之前）
  await Promise.resolve().then(() => svc.revokeGrant(db, USER.ADMIN, grantId));
  const tasks = svc.listTasks(db, USER.CAROL);
  assert.equal(tasks.filter((t) => t.status === 'cancelled').length, 10, '排队任务应全部被权限变更取消');
  // worker 现在运行也不应有任何任务可执行
  assert.equal(svc.processNextTask(db), null);
  assert.equal(svc.listTasks(db, USER.CAROL).filter((t) => t.status === 'done').length, 0);
});

test('并发撤销同一授权：幂等，仅一次生效', async () => {
  const db = freshDb();
  const { grantId } = svc.createGrant(db, USER.ADMIN, { user_id: USER.BOB, org_id: ORG.BJ, kind: 'exception' });
  const epochBefore = svc.getUser(db, USER.BOB).perm_epoch;
  const outcomes = await Promise.all(
    Array.from({ length: 8 }, () =>
      Promise.resolve().then(() => {
        try { return svc.revokeGrant(db, USER.ADMIN, grantId); }
        catch (e) { return { conflict: e.status === 409 }; }
      }))
  );
  assert.equal(outcomes.filter((o) => o.ok).length, 1, '只有一次撤销成功');
  assert.equal(outcomes.filter((o) => o.conflict).length, 7, '其余返回 409 冲突');
  assert.equal(svc.getUser(db, USER.BOB).perm_epoch, epochBefore + 1, '纪元只推进一次');
});
