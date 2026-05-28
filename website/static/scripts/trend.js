// ── Projects tab ──────────────────────────────────────────────────────────────
// (File still named trend.js for asset-version stability; drives the Projects view.)

let _projects = [];
let _projectTrendCache = {};   // project name -> array of builds
const _expandedProjects = new Set();

const _fmtBP = (b) => {
  if (b === null || b === undefined) return '-';
  const abs = Math.abs(b);
  if (abs >= 1048576) return (b/1048576).toFixed(1) + ' MB';
  if (abs >= 1024)    return (b/1024).toFixed(1) + ' KB';
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

function showCreateProject() {
  const row = document.getElementById('create-project-row');
  if (row) { row.style.display = ''; document.getElementById('new-proj-name-input').focus(); }
}

function hideCreateProject() {
  const row = document.getElementById('create-project-row');
  if (row) row.style.display = 'none';
  const inp = document.getElementById('new-proj-name-input');
  if (inp) inp.value = '';
  const err = document.getElementById('create-proj-err');
  if (err) err.style.display = 'none';
}

async function createProject() {
  const inp = document.getElementById('new-proj-name-input');
  const err = document.getElementById('create-proj-err');
  const name = inp?.value.trim();
  if (!name) { if (err) { err.textContent = 'Enter a project name.'; err.style.display = ''; } return; }
  const encoded = encodeURIComponent(name);
  const res = await fetch(`/api/project/${encoded}`, { method: 'POST' });
  const data = await res.json();
  if (!res.ok) {
    if (err) { err.textContent = data.error || 'Could not create project.'; err.style.display = ''; }
    return;
  }
  hideCreateProject();
  await loadProjects();
  await loadProjectPicker();
}

async function loadProjects() {
  try {
    const r = await fetch('/api/projects-full');
    _projects = r.ok ? await r.json() : [];
    if (!Array.isArray(_projects)) _projects = [];
  } catch (e) { _projects = []; }
  const counter = document.getElementById('proj-counter');
  if (counter) counter.textContent = `${_projects.length} / ${_MAX_PROJECTS}`;
  _projectTrendCache = {};   // clear stale cache on every load
  _initExpandedProjects();
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
  // Load trend data for all projects (charts are always visible)
  for (const p of _projects) _loadProjectTrend(p.project);
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
    <div style="padding:18px 20px;display:flex;align-items:flex-start;gap:20px;flex-wrap:wrap">
      <div style="min-width:160px">
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
        ${_renderBudgetTile('Flash', p.latest_flash, p.flash_budget_bytes, flashPct, overFlash, p.flash_delta)}
        ${_renderBudgetTile('RAM',   p.latest_ram,   p.ram_budget_bytes,   ramPct,   overRam,   p.ram_delta)}
      </div>

      <div style="display:flex;gap:8px;align-items:center;margin-left:auto">
        <button class="btn-sm" onclick='_goToAddBuild(${JSON.stringify(p.project)})' style="border-color:rgba(91,156,246,.5);color:#5b9cf6">+ Add build</button>
        <button class="btn-sm" onclick='_openProjectEditor(${JSON.stringify(p.project)})'>Edit</button>
        <button class="btn-sm" onclick='_confirmDeleteProject(${JSON.stringify(p.project)})' style="border-color:rgba(244,114,114,.4);color:#f47272">Delete</button>
      </div>
    </div>

    <div id="pe-${safeId}" style="display:none;border-top:1px solid var(--border);padding:18px 20px;background:var(--bg2)">
      ${_renderProjectEditor(p)}
    </div>

    <div id="pt-${safeId}" style="border-top:1px solid var(--border);padding:18px 20px">
      <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:12px">
        <div style="font-size:11px;font-weight:700;text-transform:uppercase;letter-spacing:.09em;color:var(--text3)">Flash &amp; RAM over time</div>
        <div style="display:flex;align-items:center;gap:14px">
          <span style="display:inline-flex;align-items:center;gap:5px;font-size:11px;color:var(--text3)">
            <span style="display:inline-block;width:10px;height:3px;border-radius:2px;background:#5b9cf6"></span>Flash
          </span>
          <span style="display:inline-flex;align-items:center;gap:5px;font-size:11px;color:var(--text3)">
            <span style="display:inline-block;width:10px;height:3px;border-radius:2px;background:#3dd68c"></span>RAM
          </span>
        </div>
      </div>
      <div id="ptc-${safeId}" style="position:relative">
        <svg id="pts-${safeId}" width="100%" height="220"></svg>
        <div id="pte-${safeId}" style="display:none;color:var(--text3);text-align:center;padding:40px;font-size:13px">No builds yet. Analyze a file and save it to this project.</div>
      </div>
      <div style="margin-top:16px">
        <div style="font-size:11px;font-weight:700;text-transform:uppercase;letter-spacing:.09em;color:var(--text3);margin-bottom:8px">Recent builds</div>
        <div id="ptr-${safeId}" style="font-size:12px;color:var(--text3)">Loading...</div>
      </div>
    </div>
  </div>`;
}

function _renderBudgetTile(label, used, budget, pct, over, delta) {
  const showBar   = budget !== null && budget !== undefined && used !== null && used !== undefined;
  const showDelta = delta !== null && delta !== undefined && delta !== 0;
  const deltaColor = delta > 0 ? '#f47272' : '#3dd68c';
  const deltaSign  = delta > 0 ? '+' : '';
  return `
    <div style="min-width:150px;background:var(--bg3);border:1px solid ${over ? 'rgba(244,114,114,.5)' : 'var(--border)'};border-radius:8px;padding:10px 14px">
      <div style="font-size:10px;font-weight:700;text-transform:uppercase;letter-spacing:.09em;color:var(--text3)">${label}</div>
      <div style="display:flex;align-items:baseline;gap:7px;margin-top:3px">
        <div style="font-size:18px;font-weight:700;color:${over ? '#f47272' : 'var(--text)'};font-family:var(--mono)">
          ${used !== null && used !== undefined ? _fmtBP(used) : '-'}
        </div>
        ${showDelta ? `<div style="font-size:11px;font-weight:700;color:${deltaColor};font-family:var(--mono)">${deltaSign}${_fmtBP(delta)}</div>` : ''}
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

function _goToAddBuild(projectName) {
  // Switch to the Analyze tab and pre-select this project
  const navBtn = document.querySelector('.nav-btn[onclick*="analyze"]');
  if (navBtn) showTab('analyze', navBtn);
  // loadProjectPicker is called by showTab, but wait a tick for the picker to render
  setTimeout(() => selectProject(projectName), 80);
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

// Start all projects expanded by default
function _initExpandedProjects() {
  _projects.forEach(p => _expandedProjects.add(p.project));
}

async function _loadProjectTrend(name) {
  const id = btoa(unescape(encodeURIComponent(name))).replace(/[^A-Za-z0-9]/g,'');
  let data = _projectTrendCache[name];
  // only use cache if it has actual data — always re-fetch if previously empty
  if (!data || !data.length) {
    try {
      const r = await fetch(`/api/history/trend?project=${encodeURIComponent(name)}`);
      data = r.ok ? await r.json() : [];
      if (!Array.isArray(data)) data = [];
      if (data.length) _projectTrendCache[name] = data;  // only cache non-empty results
    } catch (e) { data = []; }
  }
  const svg = document.getElementById(`pts-${id}`);
  const empty = document.getElementById(`pte-${id}`);
  if (!svg) return;
  const activeData = data.filter(d => d.active !== false);
  if (!activeData.length) {
    svg.style.display = 'none';
    if (empty) empty.style.display = '';
  } else {
    svg.style.display = '';
    if (empty) empty.style.display = 'none';
    const proj = _projects.find(p => p.project === name) || {};
    _drawProjectChart(svg, activeData, proj.flash_budget_bytes, proj.ram_budget_bytes);
  }
  _renderProjectRecent(name, data);
}

function _drawProjectChart(svgEl, data, flashBudget, ramBudget) {
  svgEl.innerHTML = '';
  const W = svgEl.parentElement.clientWidth || 800;
  const H = 220;
  const PAD = { top: 20, right: 80, bottom: 44, left: 62 };
  const IW = W - PAD.left - PAD.right;
  const IH = H - PAD.top  - PAD.bottom;
  svgEl.setAttribute('viewBox', `0 0 ${W} ${H}`);
  svgEl.setAttribute('width', W);
  svgEl.setAttribute('height', H);

  const ns = 'http://www.w3.org/2000/svg';
  const el = (tag, attrs = {}, text) => {
    const e = document.createElementNS(ns, tag);
    Object.entries(attrs).forEach(([k, v]) => e.setAttribute(k, v));
    if (text !== undefined) e.textContent = text;
    return e;
  };

  const flashVals = data.map(d => d.total_flash || 0);
  const ramVals   = data.map(d => d.total_ram   || 0);
  const yMax = Math.max(...flashVals, ...ramVals, flashBudget || 0, ramBudget || 0) * 1.12 || 1;
  const xScale = i => PAD.left + (data.length < 2 ? IW / 2 : (i / (data.length - 1)) * IW);
  const yScale = v => PAD.top + IH - (v / yMax) * IH;

  // Defs: gradient fills
  const defs = el('defs');
  const makeGrad = (id, color) => {
    const g = el('linearGradient', {id, x1: '0', y1: '0', x2: '0', y2: '1'});
    g.appendChild(el('stop', {'offset': '0%',   'stop-color': color, 'stop-opacity': '0.22'}));
    g.appendChild(el('stop', {'offset': '100%', 'stop-color': color, 'stop-opacity': '0.01'}));
    return g;
  };
  defs.appendChild(makeGrad('gFlash', '#5b9cf6'));
  defs.appendChild(makeGrad('gRam',   '#3dd68c'));
  svgEl.appendChild(defs);

  // Grid lines + y-axis labels
  for (let i = 0; i <= 4; i++) {
    const v = yMax * (i / 4);
    const y = yScale(v);
    svgEl.appendChild(el('line', {
      x1: PAD.left, y1: y, x2: PAD.left + IW, y2: y,
      stroke: 'var(--border)', 'stroke-width': 1,
      'stroke-dasharray': i === 0 ? 'none' : '3,4',
    }));
    svgEl.appendChild(el('text', {
      x: PAD.left - 7, y: y + 3.5,
      'text-anchor': 'end', 'font-size': 9.5,
      fill: 'var(--text3)', 'font-family': 'var(--mono)',
    }, _fmtBP(v)));
  }

  // X-axis date labels (up to 6 evenly spaced)
  const maxLabels = Math.min(data.length, 6);
  const step = data.length <= 1 ? 1 : Math.ceil((data.length - 1) / (maxLabels - 1 || 1));
  for (let i = 0; i < data.length; i += step) {
    if (i > data.length - 1) break;
    const d = data[i];
    const label = d.timestamp ? d.timestamp.slice(5, 10) : '';  // MM-DD
    const x = xScale(i);
    svgEl.appendChild(el('text', {
      x, y: H - PAD.bottom + 14,
      'text-anchor': 'middle', 'font-size': 9,
      fill: 'var(--text3)', 'font-family': 'var(--mono)',
    }, label));
  }
  // Always label the last point
  if (data.length > 1) {
    const last = data[data.length - 1];
    const label = last.timestamp ? last.timestamp.slice(5, 10) : '';
    svgEl.appendChild(el('text', {
      x: xScale(data.length - 1), y: H - PAD.bottom + 14,
      'text-anchor': 'middle', 'font-size': 9,
      fill: 'var(--text3)', 'font-family': 'var(--mono)',
    }, label));
  }

  function plotSeries(vals, color, gradId) {
    if (!vals.length) return;
    if (vals.length === 1) {
      svgEl.appendChild(el('circle', {
        cx: xScale(0), cy: yScale(vals[0]), r: 4,
        fill: color, stroke: 'var(--bg2)', 'stroke-width': 2,
      }));
      return;
    }
    const pts = vals.map((v, i) => `${xScale(i)},${yScale(v)}`).join(' ');
    const bottom = PAD.top + IH;
    // Area fill
    const areaPath = `M${xScale(0)},${bottom} ` +
      vals.map((v, i) => `L${xScale(i)},${yScale(v)}`).join(' ') +
      ` L${xScale(vals.length - 1)},${bottom} Z`;
    svgEl.appendChild(el('path', {d: areaPath, fill: `url(#${gradId})`, stroke: 'none'}));
    // Line
    svgEl.appendChild(el('polyline', {
      points: pts, fill: 'none', stroke: color, 'stroke-width': 2,
      'stroke-linejoin': 'round', 'stroke-linecap': 'round',
    }));
    // Dots
    vals.forEach((v, i) => {
      svgEl.appendChild(el('circle', {
        cx: xScale(i), cy: yScale(v), r: 3.5,
        fill: color, stroke: 'var(--bg2)', 'stroke-width': 2,
        class: 'trend-dot',
      }));
    });
  }

  plotSeries(ramVals,   '#3dd68c', 'gRam');
  plotSeries(flashVals, '#5b9cf6', 'gFlash');

  // Budget lines with labels
  function budgetLine(b, color, label) {
    if (!b || b > yMax) return;
    const y = yScale(b);
    svgEl.appendChild(el('line', {
      x1: PAD.left, y1: y, x2: PAD.left + IW, y2: y,
      stroke: color, 'stroke-width': 1.5, 'stroke-dasharray': '6,4', opacity: '0.65',
    }));
    svgEl.appendChild(el('text', {
      x: PAD.left + IW + 5, y: y + 3.5,
      'font-size': 9, fill: color, 'font-family': 'var(--mono)', opacity: '0.85',
    }, label));
  }
  budgetLine(flashBudget, '#5b9cf6', 'F limit');
  budgetLine(ramBudget,   '#3dd68c', 'R limit');

  // Hover interaction: single overlay rect + nearest-point snap
  const tooltip = _getOrCreateTrendTooltip();
  const fmtDelta = v => v === null ? '' : (v >= 0 ? `+${_fmtBP(v)}` : `-${_fmtBP(Math.abs(v))}`);

  // Hover indicator: background band + solid line + dots on each series
  const hoverBand = el('rect', {
    x: PAD.left, y: PAD.top, width: 12, height: IH,
    fill: 'rgba(240,160,64,0.08)', rx: 2,
    display: 'none', 'pointer-events': 'none',
  });
  svgEl.appendChild(hoverBand);

  const crosshair = el('line', {
    x1: PAD.left, y1: PAD.top, x2: PAD.left, y2: PAD.top + IH,
    stroke: 'rgba(240,160,64,0.85)', 'stroke-width': 1.5,
    display: 'none', 'pointer-events': 'none',
  });
  svgEl.appendChild(crosshair);

  const dotFlash = el('circle', { r: 4.5, fill: '#5b9cf6', stroke: 'var(--bg)', 'stroke-width': 2, display: 'none', 'pointer-events': 'none' });
  const dotRam   = el('circle', { r: 4.5, fill: '#3dd68c', stroke: 'var(--bg)', 'stroke-width': 2, display: 'none', 'pointer-events': 'none' });
  svgEl.appendChild(dotFlash);
  svgEl.appendChild(dotRam);

  const overlay = el('rect', {
    x: PAD.left, y: PAD.top, width: IW, height: IH,
    fill: 'transparent', cursor: 'crosshair',
  });

  overlay.addEventListener('mousemove', ev => {
    const svgRect = svgEl.getBoundingClientRect();
    const mouseX = ev.clientX - svgRect.left;
    const frac = Math.max(0, Math.min(1, (mouseX - PAD.left) / IW));
    const i = Math.round(frac * (data.length - 1));
    const d = data[i];
    const cx = xScale(i);

    // band: centred on the line, 12px wide
    hoverBand.setAttribute('x', cx - 6);
    hoverBand.setAttribute('display', '');
    crosshair.setAttribute('x1', cx);
    crosshair.setAttribute('x2', cx);
    crosshair.setAttribute('display', '');

    // dots at the data values
    const flashY = PAD.top + IH - ((d.total_flash || 0) / yMax) * IH;
    const ramY   = PAD.top + IH - ((d.total_ram   || 0) / yMax) * IH;
    dotFlash.setAttribute('cx', cx); dotFlash.setAttribute('cy', flashY); dotFlash.setAttribute('display', '');
    dotRam.setAttribute('cx', cx);   dotRam.setAttribute('cy', ramY);     dotRam.setAttribute('display', '');

    const fDelta = i > 0 ? (d.total_flash || 0) - (data[i-1].total_flash || 0) : null;
    const rDelta = i > 0 ? (d.total_ram   || 0) - (data[i-1].total_ram   || 0) : null;
    const date     = (d.timestamp || '').slice(0, 16).replace('T', ' ');
    const filename = d.basename || d.source_file || '';

    tooltip.innerHTML =
      `<div style="font-size:11px;color:var(--text3);margin-bottom:2px;font-family:var(--mono)">${esc(filename)}</div>` +
      `<div style="font-size:10px;color:var(--text3);margin-bottom:6px">${date}</div>` +
      `<div style="display:flex;align-items:center;gap:8px;margin-bottom:3px">` +
        `<span style="display:inline-block;width:8px;height:8px;border-radius:2px;background:#5b9cf6;flex-shrink:0"></span>` +
        `<span style="color:var(--text);font-weight:600">${_fmtBP(d.total_flash)}</span>` +
        (fDelta !== null ? `<span style="font-size:10px;color:${fDelta > 0 ? '#f47272' : fDelta < 0 ? '#3dd68c' : 'var(--text3)'}">${fmtDelta(fDelta)}</span>` : '') +
        `<span style="font-size:10px;color:var(--text3)">flash</span>` +
      `</div>` +
      `<div style="display:flex;align-items:center;gap:8px">` +
        `<span style="display:inline-block;width:8px;height:8px;border-radius:2px;background:#3dd68c;flex-shrink:0"></span>` +
        `<span style="color:var(--text);font-weight:600">${_fmtBP(d.total_ram)}</span>` +
        (rDelta !== null ? `<span style="font-size:10px;color:${rDelta > 0 ? '#f47272' : rDelta < 0 ? '#3dd68c' : 'var(--text3)'}">${fmtDelta(rDelta)}</span>` : '') +
        `<span style="font-size:10px;color:var(--text3)">ram</span>` +
      `</div>`;

    tooltip.style.display = 'block';
    // keep tooltip on screen horizontally
    const tipW = 200;
    const leftPos = ev.clientX + 14 + tipW > window.innerWidth ? ev.clientX - tipW - 8 : ev.clientX + 14;
    tooltip.style.left = leftPos + 'px';
    tooltip.style.top  = (ev.clientY - 10) + 'px';
  });

  overlay.addEventListener('mouseleave', () => {
    tooltip.style.display = 'none';
    crosshair.setAttribute('display', 'none');
    hoverBand.setAttribute('display', 'none');
    dotFlash.setAttribute('display', 'none');
    dotRam.setAttribute('display', 'none');
  });

  svgEl.appendChild(overlay);
}

function _getOrCreateTrendTooltip() {
  let t = document.getElementById('_proj-trend-tooltip');
  if (!t) {
    t = document.createElement('div');
    t.id = '_proj-trend-tooltip';
    t.className = 'trend-tooltip';
    document.body.appendChild(t);
  }
  return t;
}

function _renderProjectRecent(name, data) {
  const id = btoa(unescape(encodeURIComponent(name))).replace(/[^A-Za-z0-9]/g,'');
  const box = document.getElementById(`ptr-${id}`);
  if (!box) return;
  if (!data.length) { box.innerHTML = '<span style="color:var(--text3)">No builds</span>'; return; }

  const thStyle = 'padding:4px 8px;font-weight:600;white-space:nowrap';
  const tdBase  = 'padding:5px 8px;vertical-align:middle';

  box.innerHTML = `
    <table style="width:100%;font-size:12px;border-collapse:collapse">
      <thead><tr style="color:var(--text3);text-align:left">
        <th style="${thStyle}">Order</th>
        <th style="${thStyle}">File</th>
        <th style="${thStyle}">Flash</th>
        <th style="${thStyle}">RAM</th>
        <th style="${thStyle}">Uploaded</th>
        <th style="${thStyle}">In chart</th>
      </tr></thead>
      <tbody id="ptr-tbody-${id}">
        ${data.map((d, i) => _buildRow(d, i, data.length, id)).join('')}
      </tbody>
    </table>`;
}

function _buildRow(d, i, total, id) {
  const active  = d.active !== false;
  const dimmed  = active ? '' : 'opacity:0.45;';
  const ts      = (d.timestamp || '').slice(0, 16).replace('T', ' ');
  const tdBase  = 'padding:5px 8px;vertical-align:middle';
  return `<tr data-build-id="${d.id}" style="border-top:1px solid var(--border);${dimmed}">
    <td style="${tdBase}">
      <div style="display:flex;gap:2px">
        <button onclick="_moveBuild('${id}',${d.id},'up')"
          class="build-order-btn"
          title="Move up" ${i === 0 ? 'disabled' : ''}>▲</button>
        <button onclick="_moveBuild('${id}',${d.id},'down')"
          class="build-order-btn"
          title="Move down" ${i === total - 1 ? 'disabled' : ''}>▼</button>
      </div>
    </td>
    <td style="${tdBase};font-family:var(--mono);color:var(--text2);max-width:220px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap" title="${esc(d.basename||d.source_file||'')}">${esc(d.basename||d.source_file||'')}</td>
    <td style="${tdBase};font-family:var(--mono);color:var(--text)">${_fmtBP(d.total_flash)}</td>
    <td style="${tdBase};font-family:var(--mono);color:var(--text)">${_fmtBP(d.total_ram)}</td>
    <td style="${tdBase};color:var(--text3)">
      <span class="build-ts-display" style="cursor:pointer;text-decoration:underline dotted;font-family:var(--mono);font-size:11px" onclick="_editTimestamp(this,${d.id},'${esc(d.timestamp||'')}')" title="Click to edit">${esc(ts)}</span>
    </td>
    <td style="${tdBase};text-align:center">
      <button onclick="_toggleBuildActive(${d.id},${active},'${id}')"
        style="background:${active ? 'rgba(61,214,140,.15)' : 'rgba(244,114,114,.1)'};border:1px solid ${active ? '#3dd68c' : '#f47272'};border-radius:5px;color:${active ? '#3dd68c' : '#f47272'};padding:2px 8px;font-size:11px;font-weight:600;cursor:pointer"
        title="${active ? 'Click to exclude from chart' : 'Click to include in chart'}">${active ? 'Yes' : 'No'}</button>
    </td>
  </tr>`;
}

async function _toggleBuildActive(buildId, currentlyActive, tableId) {
  const newActive = !currentlyActive;
  try {
    const r = await fetch(`/api/history/${buildId}/patch`, {
      method: 'PATCH',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ active: newActive }),
    });
    if (!r.ok) { alert('Failed to update build'); return; }
    // Invalidate cache and re-render
    const projName = _findProjectByTableId(tableId);
    if (projName) { delete _projectTrendCache[projName]; await _loadProjectTrend(projName); }
  } catch (e) { alert(`Error: ${e.message}`); }
}

async function _moveBuild(tableId, buildId, direction) {
  // Find current data array, swap sort_orders with neighbour
  const projName = _findProjectByTableId(tableId);
  if (!projName) return;
  const data = _projectTrendCache[projName];
  if (!data) return;
  const idx = data.findIndex(d => d.id === buildId);
  if (idx < 0) return;
  const swapIdx = direction === 'up' ? idx - 1 : idx + 1;
  if (swapIdx < 0 || swapIdx >= data.length) return;

  const a = data[idx];
  const b = data[swapIdx];
  const aOrder = a.sort_order ?? idx + 1;
  const bOrder = b.sort_order ?? swapIdx + 1;

  try {
    await Promise.all([
      fetch(`/api/history/${a.id}/patch`, { method: 'PATCH', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ sort_order: bOrder }) }),
      fetch(`/api/history/${b.id}/patch`, { method: 'PATCH', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ sort_order: aOrder }) }),
    ]);
    delete _projectTrendCache[projName];
    await _loadProjectTrend(projName);
  } catch (e) { alert(`Error: ${e.message}`); }
}

function _editTimestamp(spanEl, buildId, currentIso) {
  // Replace the span with a datetime-local input
  const local = currentIso ? currentIso.slice(0, 16) : '';
  const input = document.createElement('input');
  input.type = 'datetime-local';
  input.value = local;
  input.style.cssText = 'font-size:11px;font-family:var(--mono);background:var(--bg2);border:1px solid var(--accent);border-radius:4px;color:var(--text);padding:1px 4px';
  spanEl.replaceWith(input);
  input.focus();

  const commit = async () => {
    const newVal = input.value;
    if (!newVal || newVal === local) { input.replaceWith(spanEl); return; }
    // Convert datetime-local (no TZ) to ISO UTC by treating as local time
    const iso = new Date(newVal).toISOString();
    try {
      const r = await fetch(`/api/history/${buildId}/patch`, {
        method: 'PATCH',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ timestamp: iso }),
      });
      if (!r.ok) { alert('Failed to update timestamp'); input.replaceWith(spanEl); return; }
      // Refresh the whole panel
      const allRows = document.querySelectorAll(`[data-build-id]`);
      allRows.forEach(row => {
        if (parseInt(row.dataset.buildId) === buildId) {
          const cell = row.querySelector('.build-ts-display');
          if (cell) cell.textContent = newVal.replace('T', ' ');
        }
      });
      input.replaceWith(spanEl);
      spanEl.textContent = newVal.replace('T', ' ');
      // Invalidate cache
      for (const [projName, builds] of Object.entries(_projectTrendCache)) {
        if (builds.some(b => b.id === buildId)) {
          delete _projectTrendCache[projName];
          _loadProjectTrend(projName);
          break;
        }
      }
    } catch (e) { alert(`Error: ${e.message}`); input.replaceWith(spanEl); }
  };

  input.addEventListener('blur', commit);
  input.addEventListener('keydown', ev => { if (ev.key === 'Enter') input.blur(); if (ev.key === 'Escape') { input.replaceWith(spanEl); } });
}

function _findProjectByTableId(tableId) {
  for (const p of _projects) {
    const pid = btoa(unescape(encodeURIComponent(p.project))).replace(/[^A-Za-z0-9]/g,'');
    if (pid === tableId) return p.project;
  }
  return null;
}
