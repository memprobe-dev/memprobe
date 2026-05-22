// _selectedProject: string = project name, null = snapshot, undefined = nothing chosen yet
let _selectedProject = undefined;
let _projectSummaries = [];

async function loadProjectPicker() {
  try {
    const r = await fetch('/api/project-summaries');
    const j = r.ok ? await r.json() : [];
    _projectSummaries = Array.isArray(j) ? j : [];
  } catch(e) { _projectSummaries = []; }
  if (!document.getElementById('proj-grid')) return;
  renderProjectPicker();

  const saved = localStorage.getItem('memprobe-last-project');
  if (saved === '__snapshot__') {
    selectProject(null);
  } else if (saved && _projectSummaries.some(p => p.project === saved)) {
    selectProject(saved);
  } else if (_projectSummaries.length === 0) {
    // No projects yet - pre-select "new project" card to guide first-time user
  }
}

function renderProjectPicker() {
  const grid = document.getElementById('proj-grid');
  const _fmtDelta = (d) => {
    if (d === null || d === undefined) return '';
    if (d === 0) return '';
    const sign = d > 0 ? '+' : '';
    const cls  = d > 0 ? 'up' : 'down';
    return `<span class="proj-delta ${cls}">${sign}${_fmtB(Math.abs(d))}</span>`;
  };
  const _fmtRelTime = (iso) => {
    if (!iso) return '';
    const diff = Date.now() - new Date(iso).getTime();
    const m = Math.floor(diff / 60000);
    if (m < 1)   return 'just now';
    if (m < 60)  return `${m}m ago`;
    const h = Math.floor(m / 60);
    if (h < 24)  return `${h}h ago`;
    return `${Math.floor(h / 24)}d ago`;
  };
  const _fmtB = (b) => {
    if (b >= 1048576) return (b/1048576).toFixed(1)+' MB';
    if (b >= 1024)    return (b/1024).toFixed(1)+' KB';
    return b+' B';
  };

  let html = _projectSummaries.map(p => {
    const sel = _selectedProject === p.project;
    return `<div class="proj-card${sel ? ' selected' : ''}" onclick='selectProject(${JSON.stringify(p.project)})'>
      <div class="proj-card-check"><svg width="9" height="9" viewBox="0 0 12 12" fill="none"><polyline points="2,6 5,9 10,3" stroke="#fff" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/></svg></div>
      <div class="proj-card-name" title="${esc(p.project)}">${esc(p.project)}</div>
      <div class="proj-card-meta">${p.build_count} build${p.build_count !== 1 ? 's' : ''} &middot; ${_fmtRelTime(p.last_build)}</div>
      <div class="proj-card-flash">${_fmtB(p.total_flash)}${_fmtDelta(p.flash_delta)}</div>
    </div>`;
  }).join('');

  const newSel = _selectedProject === '__new__';
  html += `<div class="proj-card new-card${newSel ? ' selected' : ''}" id="proj-new-card" onclick="selectNewProject()">
    <div class="proj-card-check"><svg width="9" height="9" viewBox="0 0 12 12" fill="none"><polyline points="2,6 5,9 10,3" stroke="#fff" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/></svg></div>
    <svg xmlns="http://www.w3.org/2000/svg" width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"><line x1="12" y1="5" x2="12" y2="19"/><line x1="5" y1="12" x2="19" y2="12"/></svg>
    <input class="proj-new-input" id="proj-new-name" placeholder="New project name"
      onclick="event.stopPropagation()"
      oninput="onNewProjectName(this.value)"
      onkeydown="if(event.key==='Enter')document.getElementById('btn-a').click()">
  </div>`;

  grid.innerHTML = html;

  const snapBtn = document.getElementById('proj-snapshot-btn');
  if (_selectedProject === null) snapBtn.classList.add('selected');
  else snapBtn.classList.remove('selected');
}

function selectProject(name) {
  // name: string = existing project, null = snapshot, '__new__' handled separately
  _selectedProject = name;
  renderProjectPicker();
  updateProjectContext();
  saveBudgetForProject(name);
  loadBudgetForProject(name);
  updateAnalyzeBtn();
  if (name !== undefined) {
    localStorage.setItem('memprobe-last-project', name === null ? '__snapshot__' : name);
  }
}

function selectNewProject() {
  _selectedProject = '__new__';
  renderProjectPicker();
  updateProjectContext();
  setTimeout(() => document.getElementById('proj-new-name')?.focus(), 50);
  updateAnalyzeBtn();
}

function onNewProjectName(val) {
  updateProjectContext();
  updateAnalyzeBtn();
}

function clearProjectSelection() {
  _selectedProject = undefined;
  renderProjectPicker();
  updateProjectContext();
  updateAnalyzeBtn();
  localStorage.removeItem('memprobe-last-project');
}

function updateProjectContext() {
  const ctx = document.getElementById('proj-context');
  const ctxName = document.getElementById('proj-context-name');
  if (_selectedProject === null) {
    ctx.classList.add('show');
    ctxName.textContent = 'none';
  } else if (_selectedProject === '__new__') {
    const newName = document.getElementById('proj-new-name')?.value.trim();
    ctx.classList.add('show');
    ctxName.textContent = newName ? newName : 'new project';
  } else if (typeof _selectedProject === 'string') {
    ctx.classList.add('show');
    ctxName.textContent = _selectedProject;
  } else {
    ctx.classList.remove('show');
  }
}

function updateAnalyzeBtn() {
  const f = document.getElementById('fi-a').files[0];
  const btn = document.getElementById('btn-a');
  const label = document.getElementById('bt-a');
  const ready = !!f && _selectedProject !== undefined;
  btn.disabled = !ready;
  if (_selectedProject === '__new__') {
    const nm = document.getElementById('proj-new-name')?.value.trim();
    label.textContent = nm ? `Analyze + save to "${nm}"` : 'Enter project name above';
    btn.disabled = !f || !nm;
  } else if (_selectedProject === null) {
    label.textContent = 'Analyze (snapshot)';
  } else if (typeof _selectedProject === 'string') {
    label.textContent = `Analyze + save to "${_selectedProject}"`;
  } else {
    label.textContent = 'Analyze';
    btn.disabled = true;
  }
}
