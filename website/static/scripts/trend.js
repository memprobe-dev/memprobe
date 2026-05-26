// ── Projects tab ──────────────────────────────────────────────────────────────
// (File still named trend.js for asset-version stability; drives the Projects view.)

let _projects = [];
let _projectTrendCache = {};   // project name -> array of builds
const _expandedProjects = new Set();

const _fmtBP = (b) => {
  if (b === null || b === undefined) return '-';
  if (b >= 1048576) return (b/1048576).toFixed(1) + ' MB';
  if (b >= 1024)    return (b/1024).toFixed(1) + ' KB';
  return b + ' B';
};
const _fmtRel = (iso) => {
  if (!iso) return 'never';
  const diff = Date.now() - new Date(iso).getTime();
  const m = Math.floor(diff / 60000);
  if (m < 1)  return 'just now';
  if (m < 60) return `${m}m ago`;
  const h = Math.floor(m / 60);
  if (h < 24) return `${h}h ago`;
  return `${Math.floor(h/24)}d ago`;
};

async function loadProjects() {
  try {
    const r = await fetch('/api/projects-full');
    _projects = r.ok ? await r.json() : [];
    if (!Array.isArray(_projects)) _projects = [];
  } catch (e) { _projects = []; }
  const counter = document.getElementById('proj-counter');
  if (counter) counter.textContent = `${_projects.length} / ${_MAX_PROJECTS}`;
  renderProjects();
}

function renderProjects() {
  const list = document.getElementById('projects-list');
  const empty = document.getElementById('projects-empty');
  if (!list) return;
  if (!_projects.length) {
    list.innerHTML = '';
    empty.style.display = '';
    return;
  }
  empty.style.display = 'none';
  list.innerHTML = _projects.map(p => _renderProjectCard(p)).join('');
  // Restore expanded chart panels
  for (const name of _expandedProjects) _loadProjectTrend(name);
}

function _budgetPct(used, budget) {
  if (!budget || !used) return null;
  return Math.round((used / budget) * 100);
}

function _renderProjectCard(p) {
  const flashPct = _budgetPct(p.latest_flash, p.flash_budget_bytes);
  const ramPct   = _budgetPct(p.latest_ram,   p.ram_budget_bytes);
  const overFlash = flashPct !== null && flashPct > 100;
  const overRam   = ramPct   !== null && ramPct   > 100;
  const expanded = _expandedProjects.has(p.project);
  const safeId = btoa(unescape(encodeURIComponent(p.project))).replace(/[^A-Za-z0-9]/g,'');

  return `
  <div class="card proj-card-detail" id="pcd-${safeId}" style="margin-bottom:14px">
    <div style="padding:18px 20px;display:flex;align-items:flex-start;gap:14px;flex-wrap:wrap">
      <div style="flex:1;min-width:240px">
        <div style="display:flex;align-items:center;gap:10px;margin-bottom:4px">
          <div style="font-size:16px;font-weight:700;color:var(--text)">${esc(p.project)}</div>
          <div style="font-size:11px;color:var(--text3)">${p.build_count} build${p.build_count !== 1 ? 's' : ''}</div>
        </div>
        ${p.description ? `<div style="font-size:12.5px;color:var(--text2);line-height:1.5;margin-bottom:6px">${esc(p.description)}</div>` : ''}
        <div style="font-size:11px;color:var(--text3);font-family:var(--mono)">
          Latest build ${_fmtRel(p.last_build)}
        </div>
      </div>

      <div style="display:flex;gap:14px;flex-wrap:wrap">
        ${_renderBudgetTile('Flash', p.latest_flash, p.flash_budget_bytes, flashPct, overFlash)}
        ${_renderBudgetTile('RAM',   p.latest_ram,   p.ram_budget_bytes,   ramPct,   overRam)}
      </div>

      <div style="display:flex;gap:8px;align-items:center;margin-left:auto">
        <button class="btn-sm" onclick='_toggleProjectExpand(${JSON.stringify(p.project)})'>${expanded ? 'Hide trend' : 'Show trend'}</button>
        <button class="btn-sm" onclick='_openProjectEditor(${JSON.stringify(p.project)})'>Edit</button>
        <button class="btn-sm" onclick='_confirmDeleteProject(${JSON.stringify(p.project)})' style="border-color:rgba(244,114,114,.4);color:#f47272">Delete</button>
      </div>
    </div>

    <div id="pe-${safeId}" style="display:none;border-top:1px solid var(--border);padding:18px 20px;background:var(--bg2)">
      ${_renderProjectEditor(p)}
    </div>

    <div id="pt-${safeId}" style="display:${expanded ? 'block' : 'none'};border-top:1px solid var(--border);padding:18px 20px">
      <div style="font-size:11px;font-weight:700;text-transform:uppercase;letter-spacing:.09em;color:var(--text3);margin-bottom:10px">Flash &amp; RAM over time</div>
      <div id="ptc-${safeId}" style="position:relative">
        <svg id="pts-${safeId}" width="100%" height="260"></svg>
        <div id="pte-${safeId}" style="display:none;color:var(--text3);text-align:center;padding:40px;font-size:13px">No builds for this project yet.</div>
      </div>
      <div style="margin-top:14px">
        <div style="font-size:11px;font-weight:700;text-transform:uppercase;letter-spacing:.09em;color:var(--text3);margin-bottom:8px">Recent builds</div>
        <div id="ptr-${safeId}" style="font-size:12px;color:var(--text3)">Loading...</div>
      </div>
    </div>
  </div>`;
}

function _renderBudgetTile(label, used, budget, pct, over) {
  const showBar = budget !== null && budget !== undefined && used !== null && used !== undefined;
  return `
    <div style="min-width:150px;background:var(--bg3);border:1px solid ${over ? 'rgba(244,114,114,.5)' : 'var(--border)'};border-radius:8px;padding:10px 14px">
      <div style="font-size:10px;font-weight:700;text-transform:uppercase;letter-spacing:.09em;color:var(--text3)">${label}</div>
      <div style="font-size:18px;font-weight:700;color:${over ? '#f47272' : 'var(--text)'};font-family:var(--mono);margin-top:3px">
        ${used !== null && used !== undefined ? _fmtBP(used) : '-'}
      </div>
      <div style="font-size:11px;color:var(--text3);margin-top:2px">
        ${budget ? `of ${_fmtBP(budget)} ${pct !== null ? `· ${pct}%` : ''}` : 'no budget set'}
      </div>
      ${showBar ? `
        <div style="margin-top:6px;height:4px;background:var(--bg2);border-radius:2px;overflow:hidden">
          <div style="height:100%;width:${Math.min(pct, 100)}%;background:${over ? '#f47272' : 'var(--accent)'};border-radius:2px"></div>
        </div>` : ''}
    </div>`;
}

function _renderProjectEditor(p) {
  const safeId = btoa(unescape(encodeURIComponent(p.project))).replace(/[^A-Za-z0-9]/g,'');
  const flashKB = p.flash_budget_bytes ? Math.round(p.flash_budget_bytes / 1024) : '';
  const ramKB   = p.ram_budget_bytes   ? Math.round(p.ram_budget_bytes   / 1024) : '';
  return `
    <div style="font-size:13px;font-weight:700;color:var(--text);margin-bottom:14px">Project settings</div>

    <label style="display:block;font-size:11px;font-weight:700;text-transform:uppercase;letter-spacing:.09em;color:var(--text3);margin-bottom:6px">Description</label>
    <textarea id="ped-${safeId}" placeholder="What is this project? (optional)" style="width:100%;min-height:60px;padding:10px 12px;background:var(--bg3);border:1px solid var(--border);border-radius:7px;color:var(--text);font-size:13px;font-family:inherit;resize:vertical">${esc(p.description || '')}</textarea>

    <div style="display:grid;grid-template-columns:1fr 1fr;gap:14px;margin-top:14px">
      <div>
        <label style="display:block;font-size:11px;font-weight:700;text-transform:uppercase;letter-spacing:.09em;color:var(--text3);margin-bottom:6px">Flash budget <span style="font-weight:400;text-transform:none;letter-spacing:0">(KB)</span></label>
        <input id="pef-${safeId}" type="number" min="0" placeholder="e.g. 512" value="${flashKB}" style="width:100%;padding:10px 12px;background:var(--bg3);border:1px solid var(--border);border-radius:7px;color:var(--text);font-size:13px;font-family:var(--mono)">
      </div>
      <div>
        <label style="display:block;font-size:11px;font-weight:700;text-transform:uppercase;letter-spacing:.09em;color:var(--text3);margin-bottom:6px">RAM budget <span style="font-weight:400;text-transform:none;letter-spacing:0">(KB)</span></label>
        <input id="per-${safeId}" type="number" min="0" placeholder="e.g. 256" value="${ramKB}" style="width:100%;padding:10px 12px;background:var(--bg3);border:1px solid var(--border);border-radius:7px;color:var(--text);font-size:13px;font-family:var(--mono)">
      </div>
    </div>

    <div style="display:flex;gap:8px;margin-top:16px">
      <button class="btn-primary" onclick='_saveProjectSettings(${JSON.stringify(p.project)})' style="padding:10px 18px;font-size:13px">Save changes</button>
      <button class="btn-sm" onclick='_closeProjectEditor(${JSON.stringify(p.project)})'>Cancel</button>
      <div id="pes-${safeId}" style="margin-left:auto;font-size:12px;color:var(--text3);align-self:center"></div>
    </div>
  `;
}

function _openProjectEditor(name) {
  const id = btoa(unescape(encodeURIComponent(name))).replace(/[^A-Za-z0-9]/g,'');
  const panel = document.getElementById(`pe-${id}`);
  if (panel) panel.style.display = panel.style.display === 'none' ? '' : 'none';
}
function _closeProjectEditor(name) {
  const id = btoa(unescape(encodeURIComponent(name))).replace(/[^A-Za-z0-9]/g,'');
  const panel = document.getElementById(`pe-${id}`);
  if (panel) panel.style.display = 'none';
}

async function _saveProjectSettings(name) {
  const id = btoa(unescape(encodeURIComponent(name))).replace(/[^A-Za-z0-9]/g,'');
  const status = document.getElementById(`pes-${id}`);
  const descEl = document.getElementById(`ped-${id}`);
  const flashEl = document.getElementById(`pef-${id}`);
  const ramEl   = document.getElementById(`per-${id}`);
  if (status) status.textContent = 'Saving...';

  const desc = (descEl?.value || '').trim();
  const fkb = parseFloat(flashEl?.value);
  const rkb = parseFloat(ramEl?.value);
  const body = {
    description: desc || null,
    flash_budget_bytes: isNaN(fkb) || fkb <= 0 ? null : Math.round(fkb * 1024),
    ram_budget_bytes:   isNaN(rkb) || rkb <= 0 ? null : Math.round(rkb * 1024),
  };

  try {
    const r = await fetch(`/api/project/${encodeURIComponent(name)}`, {
      method: 'PATCH',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body),
    });
    if (!r.ok) {
      const err = await r.json().catch(() => ({}));
      if (status) status.textContent = `Failed: ${err.error || r.statusText}`;
      return;
    }
    if (status) status.textContent = 'Saved.';
    await loadProjects();
  } catch (e) {
    if (status) status.textContent = `Error: ${e.message}`;
  }
}

function _confirmDeleteProject(name) {
  if (!confirm(`Delete project "${name}"?\n\nThis permanently deletes ALL builds in this project and its settings. This cannot be undone.\n\nShared links are preserved.`)) return;
  _doDeleteProject(name);
}
async function _doDeleteProject(name) {
  try {
    const r = await fetch(`/api/project/${encodeURIComponent(name)}`, { method: 'DELETE' });
    if (!r.ok) {
      const err = await r.json().catch(() => ({}));
      alert(`Could not delete: ${err.error || r.statusText}`);
      return;
    }
    _expandedProjects.delete(name);
    await loadProjects();
  } catch (e) {
    alert(`Error: ${e.message}`);
  }
}

function _toggleProjectExpand(name) {
  if (_expandedProjects.has(name)) {
    _expandedProjects.delete(name);
  } else {
    _expandedProjects.add(name);
  }
  renderProjects();
}

async function _loadProjectTrend(name) {
  const id = btoa(unescape(encodeURIComponent(name))).replace(/[^A-Za-z0-9]/g,'');
  let data = _projectTrendCache[name];
  if (!data) {
    try {
      const r = await fetch(`/api/history/trend?project=${encodeURIComponent(name)}`);
      data = r.ok ? await r.json() : [];
      if (!Array.isArray(data)) data = [];
      _projectTrendCache[name] = data;
    } catch (e) { data = []; }
  }
  const svg = document.getElementById(`pts-${id}`);
  const empty = document.getElementById(`pte-${id}`);
  if (!svg) return;
  if (!data.length) {
    svg.style.display = 'none';
    if (empty) empty.style.display = '';
  } else {
    svg.style.display = '';
    if (empty) empty.style.display = 'none';
    const proj = _projects.find(p => p.project === name) || {};
    _drawProjectChart(svg, data, proj.flash_budget_bytes, proj.ram_budget_bytes);
  }
  _renderProjectRecent(name, data);
}

function _drawProjectChart(svg, data, flashBudget, ramBudget) {
  svg.innerHTML = '';
  const W = svg.parentElement.clientWidth || 800;
  const H = 260;
  const PAD = { top: 16, right: 16, bottom: 40, left: 60 };
  const IW = W - PAD.left - PAD.right;
  const IH = H - PAD.top  - PAD.bottom;
  svg.setAttribute('viewBox', `0 0 ${W} ${H}`);
  svg.setAttribute('width', W);

  const flashVals = data.map(d => d.total_flash);
  const ramVals   = data.map(d => d.total_ram);
  const yMax = Math.max(...flashVals, ...ramVals, flashBudget || 0, ramBudget || 0) * 1.08 || 1;
  const xScale = i => PAD.left + (data.length < 2 ? IW/2 : i / (data.length - 1) * IW);
  const yScale = v => PAD.top + IH - (v / yMax) * IH;
  const ns = 'http://www.w3.org/2000/svg';
  const el = (tag, attrs) => {
    const e = document.createElementNS(ns, tag);
    Object.entries(attrs).forEach(([k,v]) => e.setAttribute(k, v));
    return e;
  };

  for (let i = 0; i <= 4; i++) {
    const v = yMax * (i / 4);
    const y = yScale(v);
    svg.appendChild(el('line', {x1: PAD.left, y1: y, x2: PAD.left+IW, y2: y,
      stroke: 'var(--border)', 'stroke-width': 1, 'stroke-dasharray': '3,3'}));
    const t = document.createElementNS(ns, 'text');
    t.setAttribute('x', PAD.left - 6); t.setAttribute('y', y + 3);
    t.setAttribute('text-anchor', 'end'); t.setAttribute('font-size', 10);
    t.setAttribute('fill', 'var(--text3)'); t.setAttribute('font-family', 'var(--mono)');
    t.textContent = _fmtBP(v);
    svg.appendChild(t);
  }

  function plot(vals, color) {
    if (vals.length < 2) {
      vals.forEach((v, i) => svg.appendChild(el('circle', {cx: xScale(i), cy: yScale(v), r: 4, fill: color})));
      return;
    }
    const pts = vals.map((v, i) => `${xScale(i)},${yScale(v)}`).join(' ');
    svg.appendChild(el('polyline', {
      points: pts, fill: 'none', stroke: color, 'stroke-width': 2,
      'stroke-linejoin': 'round', 'stroke-linecap': 'round',
    }));
    vals.forEach((v, i) => {
      svg.appendChild(el('circle', {
        cx: xScale(i), cy: yScale(v), r: 3,
        fill: color, stroke: 'var(--bg2)', 'stroke-width': 1.5,
      }));
    });
  }
  plot(flashVals, '#5b9cf6');
  plot(ramVals,   '#3dd68c');

  function budgetLine(b, color) {
    if (!b || b > yMax * 1.1) return;
    const y = yScale(b);
    svg.appendChild(el('line', {x1: PAD.left, y1: y, x2: PAD.left+IW, y2: y,
      stroke: color, 'stroke-width': 1.5, 'stroke-dasharray': '6,4', opacity: 0.7}));
  }
  budgetLine(flashBudget, '#5b9cf6');
  budgetLine(ramBudget,   '#3dd68c');
}

function _renderProjectRecent(name, data) {
  const id = btoa(unescape(encodeURIComponent(name))).replace(/[^A-Za-z0-9]/g,'');
  const box = document.getElementById(`ptr-${id}`);
  if (!box) return;
  if (!data.length) { box.innerHTML = '<span style="color:var(--text3)">No builds</span>'; return; }
  const rows = [...data].reverse().slice(0, 10);
  box.innerHTML = `
    <table style="width:100%;font-size:12px">
      <thead><tr style="color:var(--text3);text-align:left">
        <th style="padding:4px 8px;font-weight:600">When</th>
        <th style="padding:4px 8px;font-weight:600">Flash</th>
        <th style="padding:4px 8px;font-weight:600">RAM</th>
        <th style="padding:4px 8px;font-weight:600">Branch</th>
        <th style="padding:4px 8px;font-weight:600">Commit</th>
      </tr></thead>
      <tbody>${rows.map(d => `<tr style="border-top:1px solid var(--border)">
        <td style="padding:5px 8px;color:var(--text2);font-family:var(--mono)">${esc((d.timestamp||'').slice(0,19).replace('T',' '))}</td>
        <td style="padding:5px 8px;font-family:var(--mono);color:var(--text)">${_fmtBP(d.total_flash)}</td>
        <td style="padding:5px 8px;font-family:var(--mono);color:var(--text)">${_fmtBP(d.total_ram)}</td>
        <td style="padding:5px 8px;color:var(--text3);font-family:var(--mono)">${esc(d.git_branch||'-')}</td>
        <td style="padding:5px 8px;color:var(--text3);font-family:var(--mono)">${d.git_hash ? esc(d.git_hash.slice(0,7)) : '-'}</td>
      </tr>`).join('')}</tbody>
    </table>`;
}
