let _lastAnalysis = null;

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
  try {
    const res = await fetch('/api/analyze', { method: 'POST', body: fd });
    const data = await res.json();
    if (!res.ok) { showErr('a', data.detail || res.statusText); return; }
    if (projName) {
      localStorage.setItem('memprobe-last-project', projName);
      _selectedProject = projName;
    }
    if (typeof _IS_GUEST === 'undefined' || !_IS_GUEST) {
      await loadProjectPicker();
    }
    renderResults(data, data.build_id || null);
  } catch(e) { showErr('a', e.message); }
  finally { setBusy('a', false); }
}

function renderResults(d, histBuildId) {
  _lastAnalysis = d;
  document.getElementById('upload-ui').style.display = 'none';
  document.getElementById('results').classList.add('show');
  document.getElementById('res-filename').textContent = d.filename;

  if (histBuildId) pushBuildHash(histBuildId);

  const kpiEl = document.getElementById('kpi-row');
  kpiEl.innerHTML = `
    <div class="kpi"><div class="kpi-label">Flash</div><div class="kpi-val">${d.total_flash_human}</div><div class="kpi-sub">${(() => { const ota = (d.binary_info||{}).ota_estimate; return ota && ota.compressed_bytes ? `~${fmtB(ota.compressed_bytes)} OTA` : ''; })()}</div></div>
    <div class="kpi"><div class="kpi-label">RAM</div><div class="kpi-val">${d.total_ram_human}</div><div class="kpi-sub"></div></div>
    <div class="kpi"><div class="kpi-label">Sections</div><div class="kpi-val">${d.section_count}</div><div class="kpi-sub">${d.symbol_count.toLocaleString()} symbols</div></div>
    ${d.warnings.length ? `<div class="kpi warn"><div class="kpi-label">Warnings</div><div class="kpi-val">${d.warnings.length}</div></div>` : ''}
  `;
  applyBudgetToKPIs(d.total_flash, d.total_ram);

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

  document.getElementById('results').scrollIntoView({ behavior: 'smooth', block: 'start' });

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
