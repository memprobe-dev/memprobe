// ── State ────────────────────────────────────────────────────────────────────
const _cmpFiles = [];
const _cmpIds   = [];

let _cmpDiffs        = [];
let _filteredCmpDiffs = [];
let _cmpDiffSortCol  = 'delta';
let _cmpDiffSortDir  = -1;
let _cmpDiffPage     = 0;

const _CMP_PALETTE = ['#4a9eff','#f0a040','#3dd68c','#e05858','#9070d0','#60a0b0','#d06080','#a0d060'];

// ── File / history slot management ───────────────────────────────────────────

// Canonical file type: .elf and .axf are the same family (both ELF-format).
function _cmpCanonType(name) {
  const m = String(name || '').toLowerCase().match(/\.([^.]+)$/);
  if (!m) return '';
  const ext = '.' + m[1];
  return ext === '.axf' ? '.elf' : ext;
}

function _cmpCurrentType() {
  for (const f of _cmpFiles)  { const t = _cmpCanonType(f.name); if (t) return t; }
  for (const b of _cmpIds)    { const t = _cmpCanonType(b.name); if (t) return t; }
  return '';
}

function _cmpShowErr(msg) {
  let bar = document.getElementById('cmp-type-err');
  if (!bar) {
    bar = document.createElement('div');
    bar.id = 'cmp-type-err';
    bar.style.cssText = 'margin-top:12px;padding:10px 14px;background:rgba(244,114,114,.08);border:1px solid rgba(244,114,114,.4);border-radius:7px;color:#f47272;font-size:13px;line-height:1.5';
    const slots = document.getElementById('cmp-slots-wrap');
    (slots || document.getElementById('cmp-upload-zone')).appendChild(bar);
  }
  bar.textContent = msg;
  clearTimeout(_cmpShowErr._t);
  _cmpShowErr._t = setTimeout(() => bar.remove(), 4500);
}

function cmpAddFiles(fileList) {
  const existing = _cmpCurrentType();
  const accepted = [];
  const rejected = [];
  for (const f of fileList) {
    const t = _cmpCanonType(f.name);
    if (existing && t && t !== existing) {
      rejected.push(f.name);
    } else {
      accepted.push(f);
    }
  }
  for (const f of accepted) _cmpFiles.push(f);
  _renderCmpSlots();
  if (rejected.length) {
    const niceType = existing === '.elf' ? 'ELF (.elf/.axf)' : existing.replace('.', '').toUpperCase() + ' (' + existing + ')';
    _cmpShowErr(`Skipped ${rejected.length} file${rejected.length>1?'s':''} (${rejected.join(', ')}). Compare only works between builds of the same type. Current type: ${niceType}.`);
  }
}

function cmpFromHistory() {
  fetch('/api/history').then(r => r.ok ? r.json() : Promise.reject(r.status)).then(builds => {
    const tbody = document.getElementById('cmp-hist-rows');
    tbody.innerHTML = '';
    builds.forEach(b => {
      const tr = document.createElement('tr');
      tr.dataset.id    = b.id;
      tr.dataset.name  = b.basename;
      tr.dataset.flash = b.total_flash;
      tr.dataset.ram   = b.total_ram;
      tr.style.cssText = 'cursor:pointer;border-bottom:1px solid var(--border)';
      tr.innerHTML = `
        <td style="padding:4px 8px">${b.id}</td>
        <td style="padding:4px 8px">${esc(b.basename)}</td>
        <td style="padding:4px 8px;text-align:right">${fmtB(b.total_flash)}</td>
        <td style="padding:4px 8px;text-align:right">${fmtB(b.total_ram)}</td>
        <td style="padding:4px 8px;color:var(--text3)">${(b.timestamp||'').slice(0,10)}</td>`;
      tr.addEventListener('click', () => tr.classList.toggle('selected'));
      tbody.appendChild(tr);
    });
    document.getElementById('cmp-hist-modal').style.display = 'flex';
  });
}

function cmpHistCancel() {
  document.getElementById('cmp-hist-modal').style.display = 'none';
}

function cmpHistConfirm() {
  const existing = _cmpCurrentType();
  const picks = [...document.querySelectorAll('#cmp-hist-rows tr.selected')];
  const accepted = [];
  const rejected = [];
  for (const tr of picks) {
    const name = tr.dataset.name;
    const t = _cmpCanonType(name);
    const cmp = accepted.length ? accepted[0]._t : existing;
    if (cmp && t && t !== cmp) {
      rejected.push(name);
    } else {
      accepted.push({ id: +tr.dataset.id, name,
                      flash: +tr.dataset.flash, ram: +tr.dataset.ram, _t: t || cmp });
    }
  }
  for (const b of accepted) {
    delete b._t;
    _cmpIds.push(b);
  }
  document.getElementById('cmp-hist-modal').style.display = 'none';
  _renderCmpSlots();
  if (rejected.length) {
    const niceType = (existing || _cmpCanonType(accepted[0]?.name)) === '.elf' ? 'ELF (.elf/.axf)' : 'the current type';
    _cmpShowErr(`Skipped ${rejected.length} build${rejected.length>1?'s':''} (${rejected.join(', ')}). Compare only works between builds of the same type as ${niceType}.`);
  }
}

const _CMP_LETTERS = ['A','B','C','D','E','F','G','H'];

function _renderCmpSlots() {
  const wrap = document.getElementById('cmp-file-list');
  const slotsWrap = document.getElementById('cmp-slots-wrap');
  const total = _cmpFiles.length + _cmpIds.length;

  if (slotsWrap) slotsWrap.style.display = total > 0 ? '' : 'none';
  if (!wrap) return;
  wrap.innerHTML = '';

  let idx = 0;
  const makeCard = (label, sub, color, onRemove) => {
    const card = document.createElement('div');
    card.className = 'cmp-slot-card';
    card.innerHTML = `
      <div class="cmp-slot-badge" style="background:${color}">${_CMP_LETTERS[idx] || idx+1}</div>
      <div class="cmp-slot-text">
        <div class="cmp-slot-name" title="${esc(label)}">${esc(label)}</div>
        <div class="cmp-slot-sub">${esc(sub)}</div>
      </div>
      <button class="cmp-slot-x" aria-label="Remove">
        <svg xmlns="http://www.w3.org/2000/svg" width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round"><line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/></svg>
      </button>`;
    card.querySelector('.cmp-slot-x').addEventListener('click', onRemove);
    wrap.appendChild(card);
    idx++;
  };

  _cmpFiles.forEach((f, i) => {
    const color = _CMP_PALETTE[idx % _CMP_PALETTE.length];
    makeCard(f.name, `${(f.size/1024).toFixed(1)} KB · uploaded`, color, () => _cmpRemoveFile(i));
  });
  _cmpIds.forEach((b, i) => {
    const color = _CMP_PALETTE[idx % _CMP_PALETTE.length];
    makeCard(b.name, `Build #${b.id} · ${fmtB(b.flash)} flash`, color, () => _cmpRemoveId(i));
  });

  const btn = document.getElementById('cmp-run-btn');
  const lbl = document.getElementById('cmp-run-label');
  const cnt = document.getElementById('cmp-slots-count');
  btn.disabled = total < 2;
  if (lbl) lbl.textContent = total < 2 ? `Pick at least 2 builds (${total}/2)` : `Compare ${total} build${total > 1 ? 's' : ''}`;
  if (cnt) cnt.textContent = `${total} selected`;
}

function _cmpRemoveFile(i) { _cmpFiles.splice(i, 1); _renderCmpSlots(); }
function _cmpRemoveId(i)   { _cmpIds.splice(i, 1);   _renderCmpSlots(); }

function cmpClearSlots() {
  _cmpFiles.length = 0;
  _cmpIds.length = 0;
  _renderCmpSlots();
}

// Drag-and-drop on the dropzone
document.addEventListener('DOMContentLoaded', () => {
  const dz = document.getElementById('cmp-dropzone');
  if (!dz) return;
  ['dragenter', 'dragover'].forEach(ev => dz.addEventListener(ev, e => {
    e.preventDefault();
    dz.style.borderColor = 'var(--accent)';
    dz.style.background  = 'rgba(96, 165, 250, .08)';
  }));
  ['dragleave', 'drop'].forEach(ev => dz.addEventListener(ev, e => {
    e.preventDefault();
    dz.style.borderColor = '';
    dz.style.background  = '';
  }));
  dz.addEventListener('drop', e => {
    const files = e.dataTransfer?.files;
    if (files && files.length) cmpAddFiles(files);
  });
});

function cmpReset() {
  _cmpFiles.length = 0;
  _cmpIds.length   = 0;
  _cmpDiffs        = [];
  _filteredCmpDiffs = [];
  _renderCmpSlots();
  document.getElementById('cmp-results').style.display    = 'none';
  document.getElementById('cmp-upload-zone').style.display = '';
  document.getElementById('cmp-reset-btn').style.display  = 'none';
}

// ── Run ───────────────────────────────────────────────────────────────────────
async function runCompare() {
  const btn = document.getElementById('cmp-run-btn');
  btn.disabled    = true;
  btn.textContent = 'Running...';

  const total = _cmpFiles.length + _cmpIds.length;
  const fd = new FormData();
  _cmpFiles.forEach((f, i) => fd.append(`file_${i}`, f));
  const offset = _cmpFiles.length;
  _cmpIds.forEach((b, i) => fd.append(`id_${offset + i}`, b.id));

  try {
    // Always run the multi-target compare
    const cmpPromise = fetch('/api/compare', { method: 'POST', body: fd });

    // For exactly 2 inputs, also run the symbol-level diff in parallel
    let diffPromise = null;
    if (total === 2) {
      const fd2 = new FormData();
      if (_cmpFiles.length === 2) {
        fd2.append('old_file', _cmpFiles[0]);
        fd2.append('new_file', _cmpFiles[1]);
      } else if (_cmpFiles.length === 1 && _cmpIds.length === 1) {
        fd2.append('old_file', _cmpFiles[0]);
        fd2.append('new_id',   _cmpIds[0].id);
      } else {
        fd2.append('old_id', _cmpIds[0].id);
        fd2.append('new_id', _cmpIds[1].id);
      }
      diffPromise = fetch('/api/diff', { method: 'POST', body: fd2 });
    }

    const [cmpRes, diffRes] = await Promise.all([cmpPromise, diffPromise]);
    const cmpData  = await cmpRes.json();
    if (!cmpRes.ok) { alert(cmpData.error || 'Compare failed'); return; }

    let diffData = null;
    if (diffRes) {
      diffData = await diffRes.json();
      if (!diffRes.ok) diffData = null; // soft-fail: show compare without delta
    }

    _renderCompare(cmpData, diffData);
  } catch(e) {
    alert('Compare failed: ' + e.message);
  } finally {
    btn.disabled    = false;
    btn.textContent = 'Compare';
  }
}

// ── Render: summary (always) ──────────────────────────────────────────────────
function _renderCompare(data, diffData) {
  const { targets, all_sections, differing_symbols } = data;
  const isTwoWay = targets.length === 2;

  document.getElementById('cmp-upload-zone').style.display = 'none';
  document.getElementById('cmp-results').style.display     = '';
  document.getElementById('cmp-reset-btn').style.display   = '';

  // Summary cards
  const cards = document.getElementById('cmp-summary-cards');
  cards.innerHTML = '';
  const baseFlash = targets[0]?.total_flash || 0;
  const baseRam   = targets[0]?.total_ram   || 0;
  const _fmtDelta = (curr, base, isBase) => {
    if (isBase) return '<span style="font-size:11px;color:var(--text3);font-weight:600;text-transform:uppercase;letter-spacing:.06em">baseline</span>';
    const d = curr - base;
    if (d === 0) return '<span style="font-size:12px;color:var(--text3);font-family:var(--mono)">no change</span>';
    const color = d > 0 ? '#f47272' : '#3dd68c';
    const sign = d > 0 ? '+' : '';
    const pct = base > 0 ? ` (${d > 0 ? '+' : ''}${((d/base)*100).toFixed(1)}%)` : '';
    return `<span style="font-size:12px;color:${color};font-family:var(--mono);font-weight:600">${sign}${fmtB(Math.abs(d) * (d > 0 ? 1 : -1))}${pct}</span>`;
  };
  targets.forEach((t, i) => {
    const color = _CMP_PALETTE[i % _CMP_PALETTE.length];
    const isBase = i === 0;
    cards.innerHTML += `
      <div style="flex:1;min-width:220px;background:var(--bg2);border:1px solid var(--border);border-radius:10px;overflow:hidden;display:flex;flex-direction:column">
        <div style="display:flex;align-items:center;gap:9px;padding:12px 16px;border-bottom:1px solid var(--border);background:var(--bg3)">
          <div style="flex-shrink:0;width:24px;height:24px;border-radius:50%;background:${color};color:#fff;font-weight:700;font-size:12px;display:flex;align-items:center;justify-content:center">${_CMP_LETTERS[i] || i+1}</div>
          <div style="font-size:13px;font-weight:600;color:var(--text);word-break:break-all;line-height:1.3;flex:1;min-width:0;overflow:hidden;text-overflow:ellipsis;white-space:nowrap" title="${esc(t.name)}">${esc(t.name)}</div>
        </div>
        <div style="padding:14px 16px;display:flex;flex-direction:column;gap:12px">
          <div>
            <div style="display:flex;align-items:baseline;justify-content:space-between;gap:8px">
              <div style="font-size:10px;font-weight:700;text-transform:uppercase;letter-spacing:.1em;color:var(--text3)">Flash</div>
              ${_fmtDelta(t.total_flash, baseFlash, isBase)}
            </div>
            <div style="font-size:20px;font-weight:700;color:var(--text);font-family:var(--mono);margin-top:2px">${t.total_flash_human}</div>
          </div>
          <div>
            <div style="display:flex;align-items:baseline;justify-content:space-between;gap:8px">
              <div style="font-size:10px;font-weight:700;text-transform:uppercase;letter-spacing:.1em;color:var(--text3)">RAM</div>
              ${_fmtDelta(t.total_ram, baseRam, isBase)}
            </div>
            <div style="font-size:20px;font-weight:700;color:var(--text);font-family:var(--mono);margin-top:2px">${t.total_ram_human}</div>
          </div>
        </div>
      </div>`;
  });

  // Region bars
  const regWrap = document.getElementById('cmp-regions-wrap');
  regWrap.innerHTML = '';
  const allRegNames = [...new Set(targets.flatMap(t => t.regions.map(r => r.name)))];
  if (allRegNames.length) {
    regWrap.innerHTML = '<div style="margin-bottom:8px;font-weight:600;font-size:13px">Memory regions</div>';
    allRegNames.forEach(rname => {
      regWrap.innerHTML += `<div style="font-size:12px;color:var(--text2);margin-bottom:10px"><strong>${esc(rname)}</strong></div>`;
      targets.forEach((t, i) => {
        const r = t.regions.find(x => x.name === rname);
        if (!r) return;
        const color = _CMP_PALETTE[i % _CMP_PALETTE.length];
        const pct = Math.min(r.pct, 100);
        regWrap.innerHTML += `
          <div style="display:flex;align-items:center;gap:10px;margin-bottom:6px;font-size:12px">
            <div style="width:120px;color:var(--text3);overflow:hidden;text-overflow:ellipsis;white-space:nowrap" title="${esc(t.name)}">${esc(t.name)}</div>
            <div style="flex:1;background:var(--bg3);border-radius:3px;height:14px;overflow:hidden">
              <div style="height:100%;width:${pct}%;background:${color};border-radius:3px;transition:width .3s"></div>
            </div>
            <div style="min-width:90px;text-align:right">${esc(r.used_human)} / ${esc(r.length_human)} (${r.pct}%)</div>
          </div>`;
      });
    });
  }

  // Section matrix
  const thead = document.getElementById('cmp-section-head');
  const tbody = document.getElementById('cmp-section-body');
  const thS = 'padding:6px 12px;text-align:right;border-bottom:1px solid var(--border);white-space:nowrap';
  const tdS = 'padding:5px 12px;text-align:right;border-bottom:1px solid var(--border)';

  thead.innerHTML = '<tr>'
    + `<th style="${thS};text-align:left">Section</th>`
    + targets.map((t, i) => `<th style="${thS};color:${_CMP_PALETTE[i%_CMP_PALETTE.length]}">${esc(t.name)}</th>`).join('')
    + '</tr>';

  tbody.innerHTML = '';
  all_sections.forEach(secName => {
    const sizes = targets.map(t => { const s = t.sections.find(x => x.name === secName); return s ? s.size : 0; });
    if (Math.max(...sizes) === 0) return;
    const allSame = sizes.every(s => s === sizes[0]);
    const maxSz = Math.max(...sizes);
    const tr = document.createElement('tr');
    tr.innerHTML = `<td style="${tdS};text-align:left;font-family:monospace">${esc(secName)}</td>`
      + sizes.map((sz, i) => {
          const barW = maxSz > 0 ? Math.round((sz / maxSz) * 48) : 0;
          const hi   = !allSame && sz === maxSz ? 'color:var(--amber)' : '';
          return `<td style="${tdS}">
            <div style="display:flex;align-items:center;gap:6px;justify-content:flex-end">
              <div style="width:48px;background:var(--bg3);border-radius:2px;height:8px;overflow:hidden">
                <div style="width:${barW}px;height:100%;background:${_CMP_PALETTE[i%_CMP_PALETTE.length]};border-radius:2px"></div>
              </div>
              <span style="${hi}">${sz > 0 ? fmtB(sz) : '-'}</span>
            </div></td>`;
        }).join('') + '</tr>';
    tbody.appendChild(tr);
  });

  // Differing symbols table (3+ targets) vs symbol delta (2 targets)
  const differingWrap = document.getElementById('cmp-differing-wrap');
  const deltaWrap     = document.getElementById('cmp-delta');

  if (isTwoWay && diffData) {
    differingWrap.style.display = 'none';
    deltaWrap.style.display     = '';
    _renderDelta(diffData);
  } else {
    differingWrap.style.display = '';
    deltaWrap.style.display     = 'none';

    const symHead = document.getElementById('cmp-sym-head');
    const symBody = document.getElementById('cmp-sym-body');
    symHead.innerHTML = '<tr>'
      + `<th style="${thS};text-align:left">Symbol</th>`
      + targets.map((t, i) => `<th style="${thS};color:${_CMP_PALETTE[i%_CMP_PALETTE.length]}">${esc(t.name)}</th>`).join('')
      + '</tr>';
    symBody.innerHTML = '';
    if (!differing_symbols.length) {
      symBody.innerHTML = `<tr><td colspan="${targets.length + 1}" style="padding:12px;color:var(--text3);text-align:center">All symbols are the same size across targets.</td></tr>`;
    } else {
      differing_symbols.forEach(d => {
        const maxSz = Math.max(...d.sizes);
        const tr = document.createElement('tr');
        tr.innerHTML = `<td style="${tdS};text-align:left;font-family:monospace;max-width:300px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap" title="${esc(d.name)}">${esc(d.name)}</td>`
          + d.sizes.map((sz, i) => {
              const barW = maxSz > 0 ? Math.round((sz / maxSz) * 48) : 0;
              const hi   = sz === maxSz && d.sizes.some(s => s !== sz) ? 'color:var(--amber);font-weight:600' : '';
              return `<td style="${tdS}">
                <div style="display:flex;align-items:center;gap:6px;justify-content:flex-end">
                  <div style="width:48px;background:var(--bg3);border-radius:2px;height:8px;overflow:hidden">
                    <div style="width:${barW}px;height:100%;background:${_CMP_PALETTE[i%_CMP_PALETTE.length]};border-radius:2px"></div>
                  </div>
                  <span style="${hi}">${sz > 0 ? fmtB(sz) : '-'}</span>
                </div></td>`;
            }).join('') + '</tr>';
        symBody.appendChild(tr);
      });
    }
  }
}

// ── Render: symbol delta (2-build only) ──────────────────────────────────────
function _renderDelta(d) {
  const sign = n => n > 0 ? '+' : '';
  const cls  = n => n > 0 ? 'pos' : n < 0 ? 'neg' : 'zero';

  document.getElementById('cmp-diff-kpis').innerHTML = `
    <div class="diff-kpi"><div class="dk-label">Flash delta</div><div class="dk-val ${cls(d.flash_delta)}">${sign(d.flash_delta)}${d.flash_delta.toLocaleString()} B</div><div style="font-size:11px;color:var(--text3)">${esc(d.old_flash_human)} to ${esc(d.new_flash_human)}</div></div>
    <div class="diff-kpi"><div class="dk-label">RAM delta</div><div class="dk-val ${cls(d.ram_delta)}">${sign(d.ram_delta)}${d.ram_delta.toLocaleString()} B</div><div style="font-size:11px;color:var(--text3)">${esc(d.old_ram_human)} to ${esc(d.new_ram_human)}</div></div>
    <div class="diff-kpi"><div class="dk-label">Changed</div><div class="dk-val">${d.diffs.length}</div><div style="font-size:11px;color:var(--text3)">symbols</div></div>
    <div class="diff-kpi"><div class="dk-label">Added</div><div class="dk-val" style="color:var(--green)">${d.diffs.filter(x=>x.kind==='added').length}</div></div>
    <div class="diff-kpi"><div class="dk-label">Removed</div><div class="dk-val" style="color:var(--red)">${d.diffs.filter(x=>x.kind==='removed').length}</div></div>`;

  const secTotals = {};
  for (const s of d.diffs) {
    const k = s.section || '(unknown)';
    secTotals[k] = (secTotals[k] || 0) + s.delta;
  }
  const secEntries = Object.entries(secTotals).filter(([,v]) => v !== 0)
    .sort((a,b) => Math.abs(b[1]) - Math.abs(a[1]));
  const secCard = document.getElementById('cmp-diff-sec-card');
  if (secEntries.length) {
    secCard.style.display = '';
    document.getElementById('cmp-diff-sec-grid').innerHTML = secEntries.map(([name, delta]) => {
      const s = delta > 0 ? '+' : '';
      const c = delta > 0 ? 'pos' : delta < 0 ? 'neg' : 'zero';
      return `<div class="sec-diff-item">
        <div class="sec-diff-name" title="${esc(name)}">${esc(name)}</div>
        <div class="sec-diff-val ${c}">${s}${delta.toLocaleString()} B</div>
      </div>`;
    }).join('');
  } else {
    secCard.style.display = 'none';
  }

  _cmpDiffs = d.diffs;
  _cmpDiffPage = 0;
  cmpDiffFilter();
}

// ── Delta table filter / sort / page ─────────────────────────────────────────
function cmpDiffFilter() {
  const q = document.getElementById('cmp-diff-q').value.toLowerCase();
  const k = document.getElementById('cmp-diff-kind').value;
  _filteredCmpDiffs = _cmpDiffs.filter(d => {
    if (k && d.kind !== k) return false;
    if (q && !d.name.toLowerCase().includes(q)) return false;
    return true;
  });
  _filteredCmpDiffs.sort((a, b) => {
    const av = _cmpDiffSortCol === 'delta' ? Math.abs(a.delta) : a[_cmpDiffSortCol];
    const bv = _cmpDiffSortCol === 'delta' ? Math.abs(b.delta) : b[_cmpDiffSortCol];
    return _cmpDiffSortDir * (av > bv ? 1 : av < bv ? -1 : 0);
  });
  _cmpDiffPage = 0;
  _drawCmpDiff();
}

function _drawCmpDiff() {
  const pages = Math.max(1, Math.ceil(_filteredCmpDiffs.length / PAGE));
  if (_cmpDiffPage >= pages) _cmpDiffPage = pages - 1;
  const slice = _filteredCmpDiffs.slice(_cmpDiffPage * PAGE, (_cmpDiffPage + 1) * PAGE);
  document.getElementById('cmp-diff-tbody').innerHTML = slice.map(d => {
    const sign = d.delta >= 0 ? '+' : '';
    const cc   = d.delta > 0 ? 'pos' : d.delta < 0 ? 'neg' : 'zero';
    return `<tr>
      <td><span class="tag ${d.kind}">${d.kind}</span></td>
      <td><span class="sym-name" title="${esc(d.name)}">${esc(d.name)}</span></td>
      <td style="font-family:var(--mono);font-size:12px;color:var(--text2)">${d.old_size ? d.old_size.toLocaleString() : '-'}</td>
      <td style="font-family:var(--mono);font-size:12px;color:var(--text2)">${d.new_size ? d.new_size.toLocaleString() : '-'}</td>
      <td class="${cc}" style="font-family:var(--mono);font-size:12px;font-weight:600">${sign}${d.delta.toLocaleString()}</td>
      <td><span class="obj-cell">${esc(d.object_file)}</span></td>
    </tr>`;
  }).join('');
  const start = _cmpDiffPage * PAGE + 1;
  const end   = Math.min((_cmpDiffPage + 1) * PAGE, _filteredCmpDiffs.length);
  document.getElementById('cdpg-info').textContent = `${start}-${end} of ${_filteredCmpDiffs.length.toLocaleString()}`;
  document.getElementById('cdpg-prev').disabled = _cmpDiffPage === 0;
  document.getElementById('cdpg-next').disabled = _cmpDiffPage >= pages - 1;
}

function cmpDpg(d) { _cmpDiffPage += d; _drawCmpDiff(); }

// Sort on delta column header clicks
document.addEventListener('click', e => {
  const th = e.target.closest('#cdth-name, #cdth-old, #cdth-new, #cdth-delta');
  if (!th) return;
  const colMap = { 'cdth-name': 'name', 'cdth-old': 'old_size', 'cdth-new': 'new_size', 'cdth-delta': 'delta' };
  const col = colMap[th.id];
  _cmpDiffSortDir = col === _cmpDiffSortCol ? -_cmpDiffSortDir : -1;
  _cmpDiffSortCol = col;
  _cmpDiffPage = 0;
  cmpDiffFilter();
});
