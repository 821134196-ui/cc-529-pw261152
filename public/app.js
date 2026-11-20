/* 多组织指标查询平台前端 */
const state = {
  actor: 1,
  users: [],
  orgs: [],
  metrics: [],
  periods: [],
  sensitivityLabels: {},
  tab: 'tree',
  treeUser: 2,
  snapUser: '',
  cacheUser: 2,
};

const $ = (sel, root = document) => root.querySelector(sel);
const $$ = (sel, root = document) => [...root.querySelectorAll(sel)];

async function api(path, opts = {}) {
  const res = await fetch(path, {
    ...opts,
    headers: { 'Content-Type': 'application/json', 'x-actor-id': String(state.actor), ...(opts.headers || {}) },
  });
  const ct = res.headers.get('Content-Type') || '';
  const body = ct.includes('json') ? await res.json() : await res.text();
  if (!res.ok) {
    const err = new Error(body.error || `HTTP ${res.status}`);
    err.status = res.status;
    err.rules = body.rules;
    throw err;
  }
  return body;
}

const esc = (s) => String(s ?? '').replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
const fmtTs = (ms) => (ms ? new Date(ms).toLocaleString('zh-CN', { hour12: false }) : '—');
const userName = (id) => state.users.find((u) => u.id === id)?.name || `#${id}`;

/* ---------- 初始化 ---------- */
async function boot() {
  const b = await api('/api/bootstrap');
  Object.assign(state, {
    users: b.users, orgs: b.orgs, metrics: b.metrics,
    periods: b.periods, sensitivityLabels: b.sensitivityLabels,
  });
  fillSelects();
  bindTabs();
  bindForms();
  await Promise.all([renderTree(), renderGrants(), renderTasks(), renderSnapshots(), renderCache(), renderAudit()]);
  setInterval(() => { if (state.tab === 'tasks') renderTasks(); }, 2000);
  setInterval(() => { if (state.tab === 'audit') renderAudit(); }, 2000);
  setInterval(() => { if (state.tab === 'tree') renderTree(); }, 3000); // 临时授权倒计时
}

function fillSelects() {
  const userOpts = state.users.map((u) =>
    `<option value="${u.id}">${esc(u.name)}（密级L${u.clearance}${u.isAdmin ? '·管理员' : ''}）</option>`).join('');
  const orgOpts = state.orgs.map((o) => `<option value="${o.id}">${esc(o.name)}</option>`).join('');
  const metricOpts = state.metrics.map((m) =>
    `<option value="${m.id}">${esc(m.name)}（敏感L${m.sensitivity}·${esc(state.sensitivityLabels[m.sensitivity])}）</option>`).join('');
  const periodOpts = state.periods.map((p) => `<option value="${p}">${p}</option>`).join('');

  $('#actorSelect').innerHTML = userOpts;
  $('#actorSelect').value = String(state.actor);
  $('#actorSelect').onchange = (e) => { state.actor = Number(e.target.value); };

  $('#treeUserSelect').innerHTML = userOpts;
  $('#treeUserSelect').value = String(state.treeUser);
  $('#treeUserSelect').onchange = (e) => { state.treeUser = Number(e.target.value); renderTree(); };

  for (const form of [$('#grantForm'), $('#queryForm'), $('#exportForm')]) {
    $('[name=user_id]', form).innerHTML = userOpts;
    $('[name=org_id]', form).innerHTML = orgOpts;
    if ($('[name=metric_id]', form)) $('[name=metric_id]', form).innerHTML = metricOpts;
    if ($('[name=period]', form)) $('[name=period]', form).innerHTML = periodOpts;
  }
  $('#queryForm [name=user_id]').value = '2';
  $('#exportForm [name=user_id]').value = '2';

  $('#snapUserSelect').innerHTML = '<option value="">全部用户</option>' + userOpts;
  $('#snapUserSelect').onchange = (e) => { state.snapUser = e.target.value; renderSnapshots(); };
  $('#cacheUserSelect').innerHTML = userOpts;
  $('#cacheUserSelect').value = String(state.cacheUser);
  $('#cacheUserSelect').onchange = (e) => { state.cacheUser = Number(e.target.value); renderCache(); };
}

function bindTabs() {
  $$('.tab').forEach((btn) => {
    btn.onclick = () => {
      $$('.tab').forEach((b) => b.classList.toggle('active', b === btn));
      $$('.panel').forEach((p) => p.classList.toggle('active', p.id === `tab-${btn.dataset.tab}`));
      state.tab = btn.dataset.tab;
      if (state.tab === 'tasks') renderTasks();
      if (state.tab === 'audit') renderAudit();
      if (state.tab === 'snapshots') { renderSnapshots(); renderCache(); }
    };
  });
}

function bindForms() {
  $('#grantForm').onsubmit = async (e) => {
    e.preventDefault();
    const f = e.target;
    const body = {
      user_id: Number(f.user_id.value),
      org_id: Number(f.org_id.value),
      kind: f.kind.value,
      include_desc: f.include_desc.checked,
    };
    if (f.kind.value === 'temporary') body.ttl_seconds = Number(f.ttl_seconds.value || 0);
    try {
      const r = await api('/api/grants', { method: 'POST', body: JSON.stringify(body) });
      msg('#grantMsg', `授权 #${r.grantId} 创建成功，权限变更已传播（缓存/队列/快照）`, 'ok');
      await Promise.all([renderGrants(), renderTree(), renderSnapshots(), renderCache()]);
    } catch (err) {
      msg('#grantMsg', `${err.message}${rulesHtml(err.rules)}`, 'err');
    }
  };
  $('#reloadGrants').onclick = renderGrants;

  $('#queryForm').onsubmit = async (e) => {
    e.preventDefault();
    const f = e.target;
    const body = { user_id: +f.user_id.value, metric_id: +f.metric_id.value, org_id: +f.org_id.value, period: f.period.value };
    try {
      const r = await api('/api/query', { method: 'POST', body: JSON.stringify(body) });
      msg('#queryMsg', `查询成功 · ${r.fromCache ? '缓存命中' : '实时计算'} · 纪元 e${r.epoch} · 快照 #${r.snapshotId ?? '—'}`, 'ok');
      renderQueryResult(r);
      renderRules(r.hitRules);
      renderCache();
    } catch (err) {
      msg('#queryMsg', `查询被拒绝（${err.status}）：${err.message}`, 'err');
      $('#queryResult').innerHTML = '';
      renderRules(err.rules || []);
    }
  };

  $('#exportForm').onsubmit = async (e) => {
    e.preventDefault();
    const f = e.target;
    const body = { user_id: +f.user_id.value, metric_id: +f.metric_id.value, org_id: +f.org_id.value, period: f.period.value };
    try {
      const r = await api('/api/exports', { method: 'POST', body: JSON.stringify(body) });
      msg('#exportMsg', `导出任务 #${r.taskId} 已入队`, 'ok');
      renderTasks();
    } catch (err) {
      msg('#exportMsg', `入队被拒绝：${err.message}`, 'err');
    }
  };
}

function msg(sel, html, kind) {
  const el = $(sel);
  el.innerHTML = `<div class="msg ${kind}">${html}</div>`;
  setTimeout(() => { if (el.firstChild) el.innerHTML = ''; }, 8000);
}

/* ---------- 授权树 ---------- */
async function renderTree() {
  const nodes = await api(`/api/authz-tree?user_id=${state.treeUser}`);
  const byParent = new Map();
  for (const n of nodes) {
    const k = n.parentId ?? 0;
    if (!byParent.has(k)) byParent.set(k, []);
    byParent.get(k).push(n);
  }
  const badge = (n) => {
    const map = {
      inherit: ['b-inherit', '继承'], exception: ['b-exception', '例外授权'],
      temporary: ['b-temporary', '临时授权'], revoked: ['b-revoked', '已撤销'], none: ['b-none', '无权限'],
    };
    const [cls, text] = map[n.status] || map.none;
    const tip = n.rules.map((r) => r.label).join('\n');
    return `<span class="badge ${cls}" title="${esc(tip)}">${text}</span>`;
  };
  const renderNodes = (pid) => (byParent.get(pid) || [])
    .map((n) => `<li><span class="node">${esc(n.name)} ${badge(n)}</span>${
      byParent.has(n.orgId) ? `<ul>${renderNodes(n.orgId)}</ul>` : ''}</li>`)
    .join('');
  $('#authzTree').innerHTML = `<ul class="root">${renderNodes(0)}</ul>`;
}

async function renderGrants() {
  const grants = await api('/api/grants');
  const kindText = { exception: '例外', temporary: '临时', revoke: '撤销' };
  $('#grantsTable tbody').innerHTML = grants.map((g) => {
    const status = g.revoked_at ? '<span class="badge b-revoked">已撤销</span>'
      : g.expired ? '<span class="badge b-none">已过期</span>'
      : '<span class="badge b-inherit">生效中</span>';
    const extra = g.kind === 'temporary' ? `<br><small>至 ${fmtTs(g.expires_at)}</small>` : '';
    const canRevoke = !g.revoked_at && !g.expired
      ? `<button class="mini danger" data-revoke="${g.id}">撤销</button>` : '';
    return `<tr><td>${g.id}</td><td>${esc(g.userName)}</td><td>${esc(g.orgName)}${g.include_desc ? '（含子树）' : ''}</td>
      <td>${kindText[g.kind]}${extra}</td><td>${status}</td><td>${esc(g.creatorName)}</td><td>${canRevoke}</td></tr>`;
  }).join('');
  $$('#grantsTable [data-revoke]').forEach((btn) => {
    btn.onclick = async () => {
      try {
        await api(`/api/grants/${btn.dataset.revoke}/revoke`, { method: 'POST', body: JSON.stringify({}) });
        await Promise.all([renderGrants(), renderTree(), renderSnapshots(), renderCache(), renderTasks()]);
      } catch (err) {
        msg('#grantMsg', `撤销失败：${err.message}`, 'err');
      }
    };
  });
}

/* ---------- 查询结果 ---------- */
function renderQueryResult(r) {
  const m = r.metric;
  const details = r.detailRestricted
    ? `<div class="notice">明细受限：指标敏感级别 L${m.sensitivity}（${esc(state.sensitivityLabels[m.sensitivity])}）高于用户密级，仅返回汇总值。</div>`
    : `<table><thead><tr><th>组织</th><th>维度</th><th>值</th></tr></thead>
       <tbody>${r.details.map((d) => `<tr><td>${esc(d.orgName)}</td><td>${esc(d.dim)}</td><td>${d.value}</td></tr>`).join('')}</tbody></table>`;
  $('#queryResult').innerHTML = `
    <div class="stat-row">
      <div class="stat"><div class="stat-label">${esc(m.name)} · 汇总（含下级）</div>
        <div class="stat-value">${r.aggregate} <small>${esc(m.unit)}</small></div></div>
      <div class="stat"><div class="stat-label">明细行数</div><div class="stat-value">${r.detailRestricted ? '受限' : r.details.length}</div></div>
    </div>${details}`;
}

function renderRules(rules) {
  $('#hitRules').innerHTML = (rules || []).map((r) =>
    `<li class="rule r-${r.type}"><span class="rule-type">${esc(r.type)}</span>${esc(r.label)}</li>`).join('')
    || '<li class="hint">暂无</li>';
}
function rulesHtml(rules) {
  return (rules || []).map((r) => `<br><small>· ${esc(r.label)}</small>`).join('');
}

/* ---------- 任务 ---------- */
async function renderTasks() {
  const tasks = await api('/api/tasks');
  const statusBadge = {
    queued: ['b-temporary', '排队中'], running: ['b-exception', '执行中'], done: ['b-inherit', '完成'],
    failed: ['b-revoked', '失败'], cancelled: ['b-none', '已取消'],
  };
  $('#tasksTable tbody').innerHTML = tasks.map((t) => {
    const [cls, text] = statusBadge[t.status] || ['b-none', t.status];
    const tail = t.status === 'done'
      ? `<a href="/api/tasks/${t.id}/download" target="_blank">下载快照#${t.snapshot_id}</a>`
      : esc(t.cancel_reason || '—');
    return `<tr><td>${t.id}</td><td>${t.kind === 'export' ? '导出' : '查询'}</td><td>${esc(t.userName)}</td>
      <td>${esc(t.metricName)}</td><td>${esc(t.orgName)}</td>
      <td><span class="badge ${cls}">${text}</span></td><td>${tail}</td></tr>`;
  }).join('');
}

/* ---------- 快照 / 缓存 / 审计 ---------- */
async function renderSnapshots() {
  const q = state.snapUser ? `?user_id=${state.snapUser}` : '';
  const snaps = await api(`/api/snapshots${q}`);
  $('#snapshotsTable tbody').innerHTML = snaps.map((s) => {
    const rules = JSON.parse(s.hitRules || '[]').map((r) => r.label).join('\n');
    const badge = s.status === 'valid'
      ? '<span class="badge b-inherit">有效</span>'
      : '<span class="badge b-revoked">已失效</span>';
    return `<tr title="命中规则：\n${esc(rules)}"><td>${s.id}</td><td>${esc(s.userName)}</td>
      <td>${esc(s.metricName)}</td><td>${esc(s.orgName)}</td>
      <td>${s.kind === 'export' ? '导出' : '查询'}</td><td>${badge}</td>
      <td><small>${esc(s.invalidReason || '—')}</small></td></tr>`;
  }).join('');
}

async function renderCache() {
  const rows = await api(`/api/cache?user_id=${state.cacheUser}`);
  $('#cacheTable tbody').innerHTML = rows.map((c) =>
    `<tr><td><code>${esc(c.cacheKey)}</code></td><td>e${c.epoch}</td><td>${fmtTs(c.createdAt)}</td></tr>`).join('')
    || '<tr><td colspan="3" class="hint">无缓存（权限变更后已清空）</td></tr>';
}

async function renderAudit() {
  const rows = await api('/api/audit');
  $('#auditTable tbody').innerHTML = rows.map((a) =>
    `<tr><td>${a.id}</td><td>${fmtTs(a.ts)}</td><td>${esc(a.actor)}</td>
     <td><code>${esc(a.action)}</code></td><td><small>${esc(a.detail)}</small></td></tr>`).join('');
}

boot().catch((e) => { document.body.innerHTML = `<pre>初始化失败: ${esc(e.message)}</pre>`; });
