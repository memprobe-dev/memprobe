async function loadHist() {
  const res = await fetch('/api/history');
  if (!res.ok) return;
  const builds = await res.json();
  const el = document.getElementById('hist-list');
  const counter = document.getElementById('hist-counter');
  if (counter) counter.textContent = `${builds.length} / ${_MAX_BUILDS}`;
  if (!builds.length) { el.innerHTML = '<div class="hist-empty">No builds yet.</div>'; return; }
  el.innerHTML = '<div class="hist-row">' + builds.map(b => {
    const meta = [b.timestamp?.slice(0,19).replace('T',' '), b.git_branch, b.git_hash?.slice(0,7)].filter(Boolean).join('  ');
    const hasData = !!b.analysis_json;
    return `<div class="hist-card" id="hcard-${b.id}">
      <div onclick="${hasData?`loadHistBuild(${b.id})`:'void 0'}" style="flex:1;cursor:${hasData?'pointer':'default'};display:flex;align-items:center;justify-content:space-between;gap:12px" title="${hasData?'Click to load analysis':'No analysis data stored for this build'}">
        <div>
          <div class="hc-name">${esc(b.basename)}${b.project ? ` <span style="font-size:10px;font-weight:600;padding:2px 7px;border-radius:10px;background:rgba(91,156,246,.15);color:var(--accent);margin-left:6px">${esc(b.project)}</span>` : ''}</div>
          <div class="hc-meta">${esc(meta)}${!hasData?' (no analysis data)':''}</div>
        </div>
        <div class="hc-stats">
          <div class="hc-stat"><div class="v">${fmtBH(b.total_flash)}</div><div class="l">Flash</div></div>
          <div class="hc-stat"><div class="v">${fmtBH(b.total_ram)}</div><div class="l">RAM</div></div>
          ${hasData ? '<div class="hc-stat" style="color:var(--accent);font-size:11px;align-self:center">View</div>' : ''}
        </div>
      </div>
      <button class="del-btn" onclick="deleteHistBuild(${b.id})" title="Delete this build"><svg xmlns="http://www.w3.org/2000/svg" width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round"><line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/></svg></button>
    </div>`;
  }).join('') + '</div>';
}

async function loadHistBuild(id) {
  try {
    const res = await fetch(`/api/history/${id}`);
    if (!res.ok) return;
    const data = await res.json();
    const btn = document.querySelector('.nav-btn');
    showTab('analyze', btn);
    renderResults(data, id);
  } catch(e) { console.error(e); }
}

async function clearHist() {
  if (!confirm('Clear all history?')) return;
  await fetch('/api/history', { method: 'DELETE' });
  loadHist();
}

async function deleteHistBuild(id) {
  await fetch(`/api/history/${id}/delete`, { method: 'DELETE' });
  const card = document.getElementById(`hcard-${id}`);
  if (card) card.remove();
  loadHist();
}
