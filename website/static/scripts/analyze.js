let _lastAnalysis = null;

function _countUpBytes(el, target, duration = 900) {
  if (!el) return;
  const start = performance.now();
  function step(now) {
    const t = Math.min(1, (now - start) / duration);
    const eased = 1 - Math.pow(1 - t, 3);
    el.textContent = fmtB(Math.round(target * eased));
    if (t < 1) requestAnimationFrame(step);
    else el.textContent = fmtB(target);
  }
  requestAnimationFrame(step);
}

function _countUpInt(el, target, duration = 900) {
  if (!el) return;
  const start = performance.now();
  function step(now) {
    const t = Math.min(1, (now - start) / duration);
    const eased = 1 - Math.pow(1 - t, 3);
    el.textContent = Math.round(target * eased).toLocaleString();
    if (t < 1) requestAnimationFrame(step);
    else el.textContent = target.toLocaleString();
  }
  requestAnimationFrame(step);
}

// ── Job notification chip ──────────────────────────────────────────────────────

const _JOB_KEY = 'memprobe-job';

function _getStoredJob() {
  try { return JSON.parse(localStorage.getItem(_JOB_KEY) || 'null'); } catch { return null; }
}
function _setStoredJob(obj) {
  if (obj) localStorage.setItem(_JOB_KEY, JSON.stringify(obj));
  else localStorage.removeItem(_JOB_KEY);
}

// Returns the chip element, creating it once if needed.
function _getChip() {
  let chip = document.getElementById('analysis-chip');
  if (chip) return chip;

  chip = document.createElement('div');
  chip.id = 'analysis-chip';
  chip.innerHTML = `
    <div class="ac-header">
      <span class="ac-title" id="ac-title">Analyzing…</span>
      <button class="ac-close" id="ac-close" title="Dismiss">✕</button>
    </div>
    <div class="ac-file" id="ac-file"></div>
    <div class="ac-track"><div class="ac-fill" id="ac-fill"></div></div>
    <div class="ac-status" id="ac-status">Uploading…</div>
    <button class="ac-view-btn" id="ac-view-btn" style="display:none">View results</button>
  `;
  document.body.appendChild(chip);

  document.getElementById('ac-close').addEventListener('click', () => {
    _setStoredJob(null);
    chip.classList.remove('show', 'done', 'failed');
  });

  document.getElementById('ac-view-btn').addEventListener('click', () => {
    const job = _getStoredJob();
    if (job && job.result) {
      _setStoredJob(null);
      chip.classList.remove('show', 'done');
      showTab('analyze', document.querySelector('.nav-btn'));
      renderResults(job.result, job.result.build_id || null);
    }
  });

  return chip;
}

function _setChipProgress(pct, statusText) {
  const fill   = document.getElementById('ac-fill');
  const status = document.getElementById('ac-status');
  if (fill)   fill.style.width = Math.round(pct) + '%';
  if (status) status.textContent = statusText;

  // Mirror into the in-tab analyzing UI.
  const tabFill   = document.getElementById('analyzing-fill');
  const tabStatus = document.getElementById('analyzing-status');
  const tabTitle  = document.getElementById('analyzing-title');
  if (tabFill)   tabFill.style.width = Math.round(pct) + '%';
  if (tabStatus) tabStatus.textContent = statusText;
  if (tabTitle && pct >= 100) tabTitle.textContent = statusText === 'Complete' ? 'Done!' : statusText;
}

// Real progress comes from the Modal worker via the poll endpoint.
// A lightweight simulation fills the gap between polls and during cold starts
// so the bar always appears to move forward.

let _progressInterval = null;
let _currentDisplayPct = 0;

// Smoothly animate the bar to a new real value.
function _animateTo(targetPct, statusText) {
  _setChipProgress(targetPct, statusText);
  _currentDisplayPct = targetPct;
  document.getElementById('ac-fill')?.classList.remove('pulsing');
  document.getElementById('analyzing-fill')?.classList.remove('pulsing');
}

// Start a gentle drift simulation: advance slowly so the bar never looks frozen
// when there are no new progress events from the server (e.g. during cold start
// or between DWARF worker chunks). The drift never reaches 100% on its own.
function _startDrift(fromPct) {
  if (_progressInterval) clearInterval(_progressInterval);
  _currentDisplayPct = fromPct;
  _progressInterval = setInterval(() => {
    const remaining = 90 - _currentDisplayPct;
    if (remaining <= 0) {
      clearInterval(_progressInterval);
      document.getElementById('ac-fill')?.classList.add('pulsing');
      document.getElementById('analyzing-fill')?.classList.add('pulsing');
      return;
    }
    // Drift 1% of the remaining gap each tick — asymptotic, never reaches 90%.
    _currentDisplayPct += remaining * 0.012;
    _setChipProgress(_currentDisplayPct, 'Analyzing…');
  }, 400);
}

function _stopDrift() {
  if (_progressInterval) { clearInterval(_progressInterval); _progressInterval = null; }
  document.getElementById('ac-fill')?.classList.remove('pulsing');
  document.getElementById('analyzing-fill')?.classList.remove('pulsing');
}

function _showAnalyzingUI(filename) {
  const uploadUI    = document.getElementById('upload-ui');
  const analyzingUI = document.getElementById('analyzing-ui');
  const title       = document.getElementById('analyzing-title');
  const fn          = document.getElementById('analyzing-filename');
  if (uploadUI)    uploadUI.style.display    = 'none';
  if (analyzingUI) analyzingUI.style.display = '';
  if (title)       title.textContent         = 'Analyzing…';
  if (fn)          fn.textContent            = filename || '';
}

function _hideAnalyzingUI() {
  const uploadUI    = document.getElementById('upload-ui');
  const analyzingUI = document.getElementById('analyzing-ui');
  if (analyzingUI) analyzingUI.style.display = 'none';
  // Only restore upload UI if results aren't showing.
  const results = document.getElementById('results');
  if (uploadUI && !(results && results.classList.contains('show'))) {
    uploadUI.style.display = '';
  }
}

// Main polling loop. Uses real progress from the server, with a drift
// simulation filling the gaps between polls.
async function _pollJob(job_id) {
  for (;;) {
    await new Promise(r => setTimeout(r, 1500));
    let data;
    try {
      const resp = await fetch(`/api/jobs/${job_id}`);
      data = await resp.json();
    } catch {
      // Network hiccup — keep retrying.
      continue;
    }

    // Advance bar to real progress if server reports higher than current display.
    if (data.progress != null) {
      const realPct = Math.round(data.progress * 100);
      if (realPct > _currentDisplayPct) {
        _stopDrift();
        _animateTo(realPct, 'Analyzing…');
        _startDrift(realPct);  // resume drift from new baseline
      }
    }

    if (data.status === 'done') {
      _stopDrift();
      _animateTo(100, 'Complete');

      const chip = _getChip();
      chip.classList.add('done');
      document.getElementById('ac-title').textContent = 'Analysis complete';
      document.getElementById('ac-view-btn').style.display = '';

      // Store result so the view button can render it.
      const job = _getStoredJob();
      if (job) { job.result = data.result; job.status = 'done'; _setStoredJob(job); }

      // If the user is on the analyze tab and results aren't already showing, auto-render.
      const analyzeTab  = document.getElementById('tab-analyze');
      const resultsEl   = document.getElementById('results');
      const onAnalyzeTab   = analyzeTab && analyzeTab.classList.contains('visible');
      const resultsVisible = resultsEl  && resultsEl.classList.contains('show');
      if (onAnalyzeTab && !resultsVisible) {
        _setStoredJob(null);
        chip.classList.remove('show', 'done');
        _hideAnalyzingUI();
        renderResults(data.result, data.result.build_id || null);
        setBusy('a', false);
      } else {
        // User is on another tab — leave the chip, hide the in-tab spinner.
        _hideAnalyzingUI();
      }
      return;
    }

    if (data.status === 'failed') {
      _stopDrift();
      _hideAnalyzingUI();

      const errMsg = data.error || 'Analysis failed. Please try again.';
      const chip = _getChip();
      chip.classList.add('failed');
      document.getElementById('ac-title').textContent = 'Analysis failed';
      document.getElementById('ac-status').textContent = errMsg;
      document.getElementById('ac-status').style.color = 'var(--red, #f06060)';
      // Move bar to 100% in red (done by .failed class on fill via CSS).
      const fill = document.getElementById('ac-fill');
      if (fill) fill.style.width = '100%';
      const tabFill = document.getElementById('analyzing-fill');
      if (tabFill) tabFill.style.width = '100%';

      _setStoredJob(null);

      showErr('a', errMsg);
      setBusy('a', false);
      return;
    }
    // status is pending or running — keep polling.
  }
}

// ── Main entry point ──────────────────────────────────────────────────────────

async function runAnalyze() {
  const f = document.getElementById('fi-a').files[0]; if (!f) return;
  const projName = _selectedProject === '__new__'
    ? (document.getElementById('proj-new-name')?.value.trim() || '')
    : (_selectedProject || '');
  if (_selectedProject === '__new__' && !projName) return;

  setBusy('a', true); hideErr('a');

  const fd = new FormData();
  fd.append('file', f);
  if (projName) fd.append('project', projName);

  let jobId, filename;
  try {
    const res = await fetch('/api/analyze', { method: 'POST', body: fd });
    const data = await res.json();
    if (!res.ok) {
      showErr('a', data.error || data.detail || res.statusText);
      setBusy('a', false);
      return;
    }
    jobId = data.job_id;
    filename = data.filename || f.name;
  } catch(e) {
    console.error('Analyze submit failed:', e);
    showErr('a', e?.message || 'Upload failed. Please try again.');
    setBusy('a', false);
    return;
  }

  if (projName) {
    localStorage.setItem('memprobe-last-project', projName);
    _selectedProject = projName;
  }
  if (typeof _IS_GUEST === 'undefined' || !_IS_GUEST) {
    await loadProjectPicker();
  }

  // Store job in localStorage for cross-tab-navigation persistence.
  _setStoredJob({ job_id: jobId, filename, status: 'running', started_at: Date.now() });

  // Show the in-tab analyzing state.
  _showAnalyzingUI(filename);

  // Show progress chip (corner).
  const chip = _getChip();
  chip.classList.remove('done', 'failed');
  chip.classList.add('show');
  document.getElementById('ac-title').textContent = 'Analyzing…';
  document.getElementById('ac-file').textContent = filename;
  document.getElementById('ac-view-btn').style.display = 'none';
  document.getElementById('ac-status').style.color = '';

  // Start bar at 5% and drift forward while waiting for real progress events.
  _animateTo(5, 'Uploaded, queued for analysis…');
  _startDrift(5);

  _pollJob(jobId);
}

// ── Page-load restore ─────────────────────────────────────────────────────────
// If a job was in progress when the user navigated away, resume polling.

(function _restoreJob() {
  const job = _getStoredJob();
  if (!job || !job.job_id) return;

  if (job.status === 'done' && job.result) {
    // Job finished while user was away — show the chip with "view results".
    const chip = _getChip();
    chip.classList.add('show', 'done');
    document.getElementById('ac-title').textContent = 'Analysis complete';
    document.getElementById('ac-file').textContent = job.filename || '';
    document.getElementById('ac-view-btn').style.display = '';
    _setChipProgress(100, 'Complete');
    return;
  }

  if (job.status === 'running') {
    // Resume the chip and restart polling.
    const elapsed  = Date.now() - (job.started_at || Date.now());
    // Mirror the ease-out from _startProgressSimulation: cap at 65% over 40s.
    const linear   = Math.min(1, elapsed / 40000);
    const eased    = 1 - Math.pow(1 - linear, 2);
    const pct      = Math.min(65, 10 + 55 * eased);

    _showAnalyzingUI(job.filename);

    const chip = _getChip();
    chip.classList.remove('done', 'failed');
    chip.classList.add('show');
    document.getElementById('ac-title').textContent = 'Analyzing…';
    document.getElementById('ac-file').textContent  = job.filename || '';
    document.getElementById('ac-view-btn').style.display = 'none';
    document.getElementById('ac-status').style.color = '';
    _setChipProgress(pct, 'Analyzing…');

    _startDrift(pct);
    _pollJob(job.job_id);
  }
})();

// ── Render results ────────────────────────────────────────────────────────────

function renderResults(d, histBuildId) {
  _lastAnalysis = d;
  document.getElementById('upload-ui').style.display = 'none';
  document.getElementById('results').classList.add('show');

  // Clear budget fields, then reload from the current project (which may have saved budgets).
  document.getElementById('budget-flash').value = '';
  document.getElementById('budget-ram').value = '';
  loadBudgetForProject(typeof _selectedProject !== 'undefined' ? _selectedProject : null);
  document.getElementById('res-filename').textContent = d.filename;

  if (histBuildId) pushBuildHash(histBuildId);

  const kpiEl = document.getElementById('kpi-row');
  const otaSub = (() => { const ota = (d.binary_info||{}).ota_estimate; return ota && ota.compressed_bytes ? `~${fmtB(ota.compressed_bytes)} OTA` : ''; })();
  kpiEl.innerHTML = `
    <div class="kpi kpi-has-bar" data-kpi-bytes="${d.total_flash}"><div class="kpi-label">Flash</div><div class="kpi-val" id="kv-flash">0 B</div><div class="kpi-sub">${otaSub}</div><div class="kpi-bar-track"><div class="kpi-bar-fill kpi-bar-flash"></div></div></div>
    <div class="kpi kpi-has-bar" data-kpi-bytes="${d.total_ram}"><div class="kpi-label">RAM</div><div class="kpi-val" id="kv-ram">0 B</div><div class="kpi-sub"></div><div class="kpi-bar-track"><div class="kpi-bar-fill kpi-bar-ram"></div></div></div>
    <div class="kpi"><div class="kpi-label">Sections</div><div class="kpi-val" id="kv-sections">0</div><div class="kpi-sub">${d.symbol_count.toLocaleString()} symbols</div></div>
    ${d.warnings.length ? `<div class="kpi warn"><div class="kpi-label">Warnings</div><div class="kpi-val" id="kv-warnings">0</div></div>` : ''}
  `;
  applyBudgetToKPIs(d.total_flash, d.total_ram);
  _countUpBytes(document.getElementById('kv-flash'), d.total_flash);
  _countUpBytes(document.getElementById('kv-ram'), d.total_ram);
  _countUpInt(document.getElementById('kv-sections'), d.section_count);
  if (d.warnings.length) _countUpInt(document.getElementById('kv-warnings'), d.warnings.length);

  const bi = d.binary_info || {};
  if (bi.arch) {
    document.getElementById('card-binfo').style.display = '';
    const fields = [
      ['Architecture', bi.arch],
      ['Chip family',  bi.chip_family || 'Unknown'],
      ['Bitness',      bi.bitness ? `${bi.bitness}-bit` : 'Unknown'],
      ['ELF type',     bi.elf_type || 'Unknown'],
      ['Endianness',   bi.endian || 'Unknown'],
      ['OS/ABI',       bi.osabi || 'Unknown'],
      ['Entry point',  bi.entry_point || 'Unknown'],
      ['ELF flags',    bi.e_flags || '0x0'],
    ];
    if (bi.flag_features && bi.flag_features.length) {
      fields.push(['CPU features', bi.flag_features.join(', ')]);
    }
    if (bi.compiler) fields.push(['Compiler', bi.compiler]);
    if (bi.build_id) fields.push(['Build ID', bi.build_id]);
    if (bi.ota_estimate && bi.ota_estimate.compressed_bytes) {
      const ota = bi.ota_estimate;
      fields.push(['OTA estimate', `~${fmtB(ota.compressed_bytes)} compressed (${Math.round(ota.ratio*100)}% of ${fmtB(ota.raw_bytes)} raw) · zlib`]);
    }
    if (bi.build_stamps && bi.build_stamps.length) {
      const stamps = bi.build_stamps;
      const dateStamp = stamps.find(s => s.type === 'date');
      const timeStamp = stamps.find(s => s.type === 'time');
      const parts = [];
      if (dateStamp) parts.push(`__DATE__ "${dateStamp.string}"`);
      if (timeStamp) parts.push(`__TIME__ "${timeStamp.string}"`);
      fields.push(['Build stamps', `${parts.join(', ')} - non-reproducible`]);
    }
    document.getElementById('binfo-grid').innerHTML = fields.map(([l,v]) =>
      `<div class="binfo-item"><div class="binfo-label">${l}</div><div class="binfo-val${v==='-'?' dim':''}">${esc(String(v))}</div></div>`
    ).join('');

    if (bi.segments && bi.segments.length) {
      document.getElementById('binfo-segs').innerHTML = `
        <div style="font-size:10px;font-weight:700;text-transform:uppercase;letter-spacing:.09em;color:var(--text3);margin-top:16px;margin-bottom:8px">Load segments (PT_LOAD)</div>
        <table class="seg-table">
          <thead><tr><th>VAddr</th><th>PAddr</th><th>File size</th><th>Mem size</th><th>Flags</th></tr></thead>
          <tbody>${bi.segments.map(s => `<tr>
            <td>${esc(s.vaddr)}</td><td>${esc(s.paddr)}</td>
            <td>${fmtB(s.filesz)}</td><td>${fmtB(s.memsz)}</td>
            <td style="font-weight:600;color:var(--text)">${esc(s.flags)}</td></tr>`).join('')}</tbody>
        </table>`;
    } else {
      document.getElementById('binfo-segs').innerHTML = '';
    }
  } else {
    document.getElementById('card-binfo').style.display = 'none';
  }

  if (d.regions.length) {
    document.getElementById('card-regions').style.display = '';
    document.getElementById('region-list').innerHTML = d.regions.map(r => `
      <div class="region-row">
        <span class="rname">${esc(r.name)}</span>
        <div class="rtrack"><div class="rfill ${r.name.toLowerCase().includes('flash')?'flash':r.name.toLowerCase().includes('ram')?'ram':'other'}" style="width:${Math.min(r.pct,100)}%"></div></div>
        <div class="rstat"><strong>${r.used_human}</strong> / ${r.length_human} &nbsp; ${r.pct}%</div>
      </div>`).join('');
  }

  renderSections(d.sections);

  document.getElementById('legend').innerHTML = Object.entries(TC)
    .filter(([t]) => d.sections.some(s => s.type === t))
    .map(([t,c]) => `<div class="leg"><div class="leg-dot" style="background:${c}"></div>${t}</div>`).join('');

  {
    const warnCount = d.warnings ? d.warnings.filter(w => w.level === 'warning').length : 0;
    const btn = document.getElementById('atab-insights-btn');
    btn.textContent = warnCount > 0 ? `Insights (${warnCount})` : 'Insights';
    if (warnCount > 0) btn.style.color = 'var(--amber)';
    else btn.style.color = '';
  }

  if (d.warnings.length) {
    document.getElementById('card-warnings').style.display = '';
    document.getElementById('warn-list').innerHTML = d.warnings.map((w,i) => `
      <div class="warn-item ${w.level}">
        <div class="wi-icon ${w.level}">${w.level==='warning'?'!':'i'}</div>
        <div class="wi-body">
          <div class="wi-msg">${esc(w.message)}</div>
        </div>
      </div>`).join('');
  }

  renderAddrMap(d.sections);

  if (d.insights) renderInsights(d.insights, d.warnings || [], d.binary_info || {});
  renderLibraries(d.libraries || []);

  SYMS = d.symbols;
  const secSel = document.getElementById('tbl-sec');
  secSel.innerHTML = '<option value="">All sections</option>';
  [...new Set(SYMS.map(s=>s.section))].sort().forEach(n => {
    const o = document.createElement('option'); o.value=n; o.textContent=n; secSel.appendChild(o);
  });
  symPage = 0; sortCol = 'size'; sortDir = -1;
  tblFilter();

  renderTreemap(d.treemap);

  window.scrollTo({ top: 0, behavior: 'smooth' });

  // Guests get one analysis - permanently hide the upload area after first use
  if (typeof _IS_GUEST !== 'undefined' && _IS_GUEST) {
    document.getElementById('upload-ui').remove();
  }
}

function resetAnalyze() {
  if (typeof _IS_GUEST !== 'undefined' && _IS_GUEST) return;
  document.getElementById('upload-ui').style.display = '';
  document.getElementById('results').classList.remove('show');
  document.getElementById('fi-a').value = '';
  document.getElementById('dz-a').classList.remove('has-file');
  pushBuildHash(null);
  updateBtns();
}
