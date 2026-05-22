// Share-page renderer. The server emits the analysis as a JSON island
// via Django's {{ analysis_data|json_script:"share-data" }} template tag.

const _SHARE_DATA = JSON.parse(document.getElementById('share-data').textContent);

const PAGE = 100;
let _shareSyms = [], _shareFiltered = [], _sharePage = 0;
let _shareDemangle = false;

function shareTab(id, btn) {
  document.querySelectorAll('.atab-panel').forEach(p => p.classList.remove('active'));
  document.querySelectorAll('.atab-btn').forEach(b => b.classList.remove('active'));
  document.getElementById('satab-' + id).classList.add('active');
  btn.classList.add('active');
}

function _init() {
  const d = _SHARE_DATA;

  // Theme init
  const t = localStorage.getItem('theme') || 'dark';
  document.documentElement.setAttribute('data-theme', t);
  const moon = document.getElementById('theme-icon-moon');
  const sun  = document.getElementById('theme-icon-sun');
  if (moon) moon.style.display = t === 'dark' ? 'block' : 'none';
  if (sun)  sun.style.display  = t === 'light' ? 'block' : 'none';

  document.getElementById('share-filename').textContent = d.filename || '';

  // KPIs
  document.getElementById('share-kpis').innerHTML = `
    <div class="kpi"><div class="kpi-label">Flash</div><div class="kpi-val">${fmtBH(d.total_flash)}</div><div class="kpi-sub"></div></div>
    <div class="kpi"><div class="kpi-label">RAM</div><div class="kpi-val">${fmtBH(d.total_ram)}</div><div class="kpi-sub"></div></div>
    <div class="kpi"><div class="kpi-label">Symbols</div><div class="kpi-val">${(d.symbol_count||0).toLocaleString()}</div><div class="kpi-sub"></div></div>
    <div class="kpi"><div class="kpi-label">Sections</div><div class="kpi-val">${(d.section_count||0).toLocaleString()}</div><div class="kpi-sub"></div></div>`;

  // Warnings
  const warns = d.warnings || [];
  if (warns.length) {
    document.getElementById('share-warnings').innerHTML = `<div class="card"><div class="card-hd"><span class="card-title">Warnings</span></div><div class="warn-list">${warns.map(w => `
      <div class="warn-item ${w.level}">
        <div class="wi-icon ${w.level}">${w.level==='warning'?'!':'i'}</div>
        <div class="wi-body">
          <div class="wi-msg">${esc(w.message)}</div>
          ${w.how_to_fix ? `<div style="font-size:11px;color:var(--text3);margin-top:3px">${esc(w.how_to_fix)}</div>` : ''}
        </div>
      </div>`).join('')}</div></div>`;
  }

  // Sections list
  const secs = d.sections || [];
  const maxSz = secs.reduce((m, s) => Math.max(m, s.size), 1);
  const total = secs.reduce((a, s) => a + s.size, 0) || 1;
  document.getElementById('share-sections-list').innerHTML = `<div class="sec-rows">${secs.map(s => {
    const pct  = (s.size / total * 100).toFixed(1);
    const barW = (s.size / maxSz * 100).toFixed(1);
    const col  = s.color || 'var(--accent)';
    return `<div class="sec-row">
      <div><div class="sec-name" title="${esc(s.name)}">${esc(s.name)}</div></div>
      <div class="sec-track"><div class="sec-fill" style="width:${barW}%;background:${col}"></div></div>
      <span class="sec-sz">${fmtB(s.size)}</span>
      <span class="sec-pct">${pct}%</span>
    </div>`;
  }).join('')}</div>`;

  // Treemap
  if (d.treemap && typeof renderTreemap === 'function') {
    renderTreemap(d.treemap);
  }

  // Address map
  if (d.sections && d.sections.length && typeof renderAddrMap === 'function') {
    renderAddrMap(d.sections);
  }

  // Detected libraries
  const libs = d.libraries || [];
  if (libs.length) {
    const card = document.getElementById('share-libs-card');
    card.style.display = '';
    const maxFlash = libs[0].flash_bytes || 1;
    document.getElementById('share-libs-body').innerHTML = `
      <table style="width:100%;font-size:12px;border-collapse:collapse">
        <thead><tr>
          <th style="text-align:left;padding:6px 12px;color:var(--text3);font-size:10px;text-transform:uppercase;letter-spacing:.08em;border-bottom:1px solid var(--border)">Library</th>
          <th style="text-align:left;padding:6px 12px;color:var(--text3);font-size:10px;text-transform:uppercase;letter-spacing:.08em;border-bottom:1px solid var(--border)">Category</th>
          <th style="text-align:right;padding:6px 12px;color:var(--text3);font-size:10px;text-transform:uppercase;letter-spacing:.08em;border-bottom:1px solid var(--border)">Flash</th>
          <th style="text-align:right;padding:6px 12px;color:var(--text3);font-size:10px;text-transform:uppercase;letter-spacing:.08em;border-bottom:1px solid var(--border)">Symbols</th>
        </tr></thead>
        <tbody>${libs.map(lib => {
          const pct = Math.round((lib.flash_bytes / maxFlash) * 80);
          const nameCell = lib.url
            ? `<a href="${esc(lib.url)}" target="_blank" rel="noopener" style="color:var(--accent)">${esc(lib.name)}</a>`
            : esc(lib.name);
          return `<tr>
            <td style="padding:7px 12px;border-bottom:1px solid var(--border)">${nameCell}</td>
            <td style="padding:7px 12px;border-bottom:1px solid var(--border);color:var(--text3)">${esc(lib.category)}</td>
            <td style="padding:7px 12px;border-bottom:1px solid var(--border);text-align:right">
              <div style="display:flex;align-items:center;gap:8px;justify-content:flex-end">
                <div style="width:80px;background:var(--bg4);border-radius:2px;height:6px;overflow:hidden">
                  <div style="width:${pct}px;height:100%;background:var(--accent);border-radius:2px"></div>
                </div>
                <span style="font-family:var(--mono)">${esc(lib.flash_human)}</span>
              </div>
            </td>
            <td style="padding:7px 12px;border-bottom:1px solid var(--border);text-align:right;color:var(--text3)">${lib.symbol_count}</td>
          </tr>`;
        }).join('')}</tbody>
      </table>`;
  }

  // Symbol table
  _shareSyms = d.symbols || [];
  const secSel = document.getElementById('share-sym-sec');
  const secNames = [...new Set(_shareSyms.map(s => s.section))].sort();
  secNames.forEach(n => {
    const o = document.createElement('option');
    o.value = n; o.textContent = n;
    secSel.appendChild(o);
  });
  shareSymFilter();

  // Insights
  renderInsights(d.insights || {}, d.warnings || [], d.binary_info || {});
}

function shareSymFilter() {
  _shareDemangle = document.getElementById('share-demangle-toggle').checked;
  const q   = document.getElementById('share-sym-q').value.toLowerCase();
  const sec = document.getElementById('share-sym-sec').value;
  _shareFiltered = _shareSyms.filter(s => {
    if (sec && s.section !== sec) return false;
    const display = _shareDemangle ? (s.demangled || s.name) : s.name;
    if (q && !display.toLowerCase().includes(q)) return false;
    return true;
  });
  _sharePage = 0;
  _drawShareSyms();
}

function _drawShareSyms() {
  const pages = Math.max(1, Math.ceil(_shareFiltered.length / PAGE));
  if (_sharePage >= pages) _sharePage = pages - 1;
  const slice = _shareFiltered.slice(_sharePage * PAGE, (_sharePage + 1) * PAGE);
  const maxSz = slice.reduce((m, s) => Math.max(m, s.size), 1);
  document.getElementById('share-sym-tbody').innerHTML = slice.map(s => {
    const display = _shareDemangle ? (s.demangled || s.name) : s.name;
    const changed = display !== s.name;
    const barW = Math.round((s.size / maxSz) * 80);
    const col = tc(s.type);
    return `<tr>
      <td><span class="sym-name" title="${esc(s.name)}">${esc(display)}</span>${changed ? `<span style="font-size:10px;color:var(--text3);margin-left:6px;font-family:var(--mono)">(mangled)</span>` : ''}</td>
      <td class="sz-cell">
        <span class="sz-bar" style="width:${barW}px;background:${col}"></span>
        ${fmtB(s.size)}
      </td>
      <td><span style="font-family:var(--mono);font-size:11px;color:var(--text3)">${esc(s.section)}</span></td>
      <td><span class="obj-cell">${esc(s.object_file)}</span></td>
    </tr>`;
  }).join('');
  const start = _sharePage * PAGE + 1;
  const end = Math.min((_sharePage + 1) * PAGE, _shareFiltered.length);
  document.getElementById('share-sym-info').textContent =
    `${start}-${end} of ${_shareFiltered.length.toLocaleString()}`;
  document.getElementById('share-sym-prev').disabled = _sharePage === 0;
  document.getElementById('share-sym-next').disabled = _sharePage >= pages - 1;
}

function shareSymPg(d) { _sharePage += d; _drawShareSyms(); }

document.addEventListener('DOMContentLoaded', _init);
