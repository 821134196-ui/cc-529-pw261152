import { test } from 'node:test';
import assert from 'node:assert/strict';
import { freshDb, ORG, USER, METRIC } from './helpers.js';
import { effectiveAccess } from '../server/authz.js';
import * as svc from '../server/services.js';

test('继承：用户可访问所属组织子树，不能访问兄弟子树', () => {
  const db = freshDb();
  const alice = svc.getUser(db, USER.ALICE); // 华东大区
  assert.equal(effectiveAccess(db, alice, ORG.SH).allowed, true);   // 上海（下级）
  assert.equal(effectiveAccess(db, alice, ORG.HZ).allowed, true);   // 杭州（下级）
  assert.equal(effectiveAccess(db, alice, ORG.BJ).allowed, false);  // 北京（另一子树）
  assert.equal(effectiveAccess(db, alice, ORG.HQ).allowed, false);  // 上级不可见
  const bob = svc.getUser(db, USER.BOB); // 上海分公司
  assert.equal(effectiveAccess(db, bob, ORG.SH).allowed, true);
  assert.equal(effectiveAccess(db, bob, ORG.EAST).allowed, false);  // 上级大区不可见
});

test('例外授权：授予子树外组织；撤销授权优先于一切', () => {
  const db = freshDb();
  // admin 给 bob（上海）授予北京的例外授权
  const { grantId } = svc.createGrant(db, USER.ADMIN, { user_id: USER.BOB, org_id: ORG.BJ, kind: 'exception' });
  const bob = svc.getUser(db, USER.BOB);
  const acc = effectiveAccess(db, bob, ORG.BJ);
  assert.equal(acc.allowed, true);
  assert.equal(acc.rules[0].type, 'exception');

  // 再叠加一条针对北京的撤销授权 → 立即拒绝（撤销优先）
  svc.createGrant(db, USER.ADMIN, { user_id: USER.BOB, org_id: ORG.BJ, kind: 'revoke' });
  const denied = effectiveAccess(db, svc.getUser(db, USER.BOB), ORG.BJ);
  assert.equal(denied.allowed, false);
  assert.equal(denied.rules[0].type, 'revoke');

  // 撤销"撤销授权"本身 → 例外授权重新生效
  const grants = svc.listGrants(db, USER.BOB);
  const revokeGrant = grants.find((g) => g.kind === 'revoke' && !g.revoked_at);
  svc.revokeGrant(db, USER.ADMIN, revokeGrant.id);
  assert.equal(effectiveAccess(db, svc.getUser(db, USER.BOB), ORG.BJ).allowed, true);
  void grantId;
});

test('临时授权：有效期内可用，过期即拒绝', () => {
  const db = freshDb();
  const now = Date.now();
  svc.createGrant(db, USER.ADMIN, { user_id: USER.CAROL, org_id: ORG.SH, kind: 'temporary', ttl_seconds: 5 }, now);
  const carol = svc.getUser(db, USER.CAROL);
  assert.equal(effectiveAccess(db, carol, ORG.SH, now + 1000).allowed, true);
  const expired = effectiveAccess(db, carol, ORG.SH, now + 6000);
  assert.equal(expired.allowed, false);
  assert.ok(expired.rules.some((r) => r.type === 'temporary-expired'));
});

test('敏感级别：低密级用户仅得汇总，明细受限', () => {
  const db = freshDb();
  // bob 密级 L2，查询 L3 人力成本 → 明细受限
  const r1 = svc.runQuery(db, USER.BOB, METRIC.SALARY, ORG.SH, '2026-10');
  assert.equal(r1.detailRestricted, true);
  assert.equal(r1.details.length, 0);
  assert.ok(r1.aggregate > 0);
  assert.ok(r1.hitRules.some((r) => r.type === 'sensitivity' && r.label.includes('明细受限')));
  // bob 查询 L2 订单量 → 明细可见
  const r2 = svc.runQuery(db, USER.BOB, METRIC.ORDERS, ORG.SH, '2026-10');
  assert.equal(r2.detailRestricted, false);
  assert.ok(r2.details.length > 0);
});

test('越权拒绝：查询无授权组织返回 403 及命中规则', () => {
  const db = freshDb();
  assert.throws(
    () => svc.runQuery(db, USER.CAROL, METRIC.REVENUE, ORG.SH, '2026-10'),
    (e) => e.status === 403 && Array.isArray(e.rules) && e.rules.at(-1).type === 'none'
  );
});

test('越权拒绝：非管理员不能就无权组织授权，不能撤销他人授权', () => {
  const db = freshDb();
  // carol（仅北京）试图给 bob 授予上海 → 403
  assert.throws(
    () => svc.createGrant(db, USER.CAROL, { user_id: USER.BOB, org_id: ORG.SH, kind: 'exception' }),
    (e) => e.status === 403
  );
  // alice（华东）就上海授权是允许的（她对上海有继承权）
  const { grantId } = svc.createGrant(db, USER.ALICE, { user_id: USER.BOB, org_id: ORG.HZ, kind: 'exception' });
  // carol 试图撤销 alice 创建的授权 → 403
  assert.throws(() => svc.revokeGrant(db, USER.CAROL, grantId), (e) => e.status === 403);
  // 创建者本人可撤销
  assert.doesNotThrow(() => svc.revokeGrant(db, USER.ALICE, grantId));
});

test('越权拒绝：不能下载他人导出，失效快照返回 410', () => {
  const db = freshDb();
  const { taskId } = svc.enqueueExport(db, USER.ALICE, METRIC.REVENUE, ORG.SH, '2026-10');
  svc.processNextTask(db);
  // carol 下载 alice 的导出 → 403
  assert.throws(() => svc.downloadExport(db, USER.CAROL, taskId), (e) => e.status === 403);
  // admin 给 alice 加一条针对上海的撤销授权 → 快照失效 → 410
  svc.createGrant(db, USER.ADMIN, { user_id: USER.ALICE, org_id: ORG.SH, kind: 'revoke' });
  assert.throws(() => svc.downloadExport(db, USER.ALICE, taskId), (e) => e.status === 410);
});
