/**
 * 授权引擎：计算用户对某组织的有效访问。
 * 规则优先级：
 *   1. 撤销授权（revoke）—— 否决一切，最高优先
 *   2. 继承（inherit）—— 用户所属组织的整棵子树
 *   3. 例外授权（exception）—— 显式授予的子树
 *   4. 临时授权（temporary）—— 带过期时间的显式授予
 *   5. 以上皆无 → 拒绝
 * 每次评估返回命中规则（hit rules），用于页面展示与快照记录。
 */

export function ancestorsOf(db, orgId) {
  const path = [];
  const seen = new Set();
  let cur = orgId;
  while (cur != null && !seen.has(cur)) {
    seen.add(cur);
    const row = db.prepare('SELECT id, parent_id FROM orgs WHERE id = ?').get(cur);
    if (!row) break;
    path.push(row.id);
    cur = row.parent_id;
  }
  return path; // [self, parent, ..., root]
}

export function descendantsOf(db, orgId) {
  return db.prepare(`
    WITH RECURSIVE sub(id) AS (
      SELECT ?
      UNION ALL
      SELECT o.id FROM orgs o JOIN sub s ON o.parent_id = s.id
    ) SELECT id FROM sub`).all(orgId).map((r) => r.id);
}

function orgName(db, id) {
  const r = db.prepare('SELECT name FROM orgs WHERE id = ?').get(id);
  return r ? r.name : `#${id}`;
}

function fmtTs(ms) {
  return new Date(ms).toLocaleString('zh-CN', { hour12: false });
}

/**
 * @returns {{allowed: boolean, rules: Array<{type:string, label:string, grantId?:number}>}}
 */
export function effectiveAccess(db, user, orgId, now = Date.now()) {
  const path = ancestorsOf(db, orgId);
  const grants = db.prepare(
    'SELECT * FROM grants WHERE user_id = ? AND revoked_at IS NULL'
  ).all(user.id);

  const covers = (g) => g.org_id === orgId || (g.include_desc === 1 && path.includes(g.org_id));

  // 1. 撤销授权优先（未过期的 revoke 一律否决）
  for (const g of grants) {
    if (g.kind !== 'revoke' || !covers(g)) continue;
    return {
      allowed: false,
      rules: [{
        type: 'revoke',
        grantId: g.id,
        label: `撤销授权 #${g.id}（组织「${orgName(db, g.org_id)}」${g.include_desc ? '及子树' : ''}）→ 拒绝`,
      }],
    };
  }

  // 2. 继承：目标组织在用户所属组织的子树内
  if (path.includes(user.org_id)) {
    return {
      allowed: true,
      rules: [{
        type: 'inherit',
        label: `继承：所属组织「${orgName(db, user.org_id)}」的子树覆盖「${orgName(db, orgId)}」`,
      }],
    };
  }

  // 3./4. 例外与临时授权
  const notes = [];
  for (const g of grants) {
    if (!covers(g)) continue;
    if (g.kind === 'exception') {
      return {
        allowed: true,
        rules: [{
          type: 'exception',
          grantId: g.id,
          label: `例外授权 #${g.id}（组织「${orgName(db, g.org_id)}」${g.include_desc ? '及子树' : ''}）`,
        }],
      };
    }
    if (g.kind === 'temporary') {
      if (g.expires_at > now) {
        return {
          allowed: true,
          rules: [{
            type: 'temporary',
            grantId: g.id,
            label: `临时授权 #${g.id}（组织「${orgName(db, g.org_id)}」，有效期至 ${fmtTs(g.expires_at)}）`,
          }],
        };
      }
      notes.push({
        type: 'temporary-expired',
        grantId: g.id,
        label: `临时授权 #${g.id} 已于 ${fmtTs(g.expires_at)} 过期，不再生效`,
      });
    }
  }

  // 5. 拒绝
  return {
    allowed: false,
    rules: [...notes, { type: 'none', label: '无任何授权覆盖该组织 → 拒绝' }],
  };
}

/** 授权树：对每个组织节点计算访问状态，供前端展示。 */
export function authzTree(db, user, now = Date.now()) {
  const orgs = db.prepare('SELECT * FROM orgs ORDER BY id').all();
  return orgs.map((o) => {
    const acc = effectiveAccess(db, user, o.id, now);
    const primary = acc.rules[0];
    return {
      orgId: o.id,
      name: o.name,
      parentId: o.parent_id,
      allowed: acc.allowed,
      status: !acc.allowed
        ? (primary.type === 'revoke' ? 'revoked' : 'none')
        : primary.type, // inherit | exception | temporary
      rules: acc.rules,
    };
  });
}
