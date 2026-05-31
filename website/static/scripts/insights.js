// Build the "Savings" rows from analysis results. Pure (no DOM) so it can be
// unit-tested. Each row is { tag: 'info'|'warn', amt: bytes|null, desc }.
function computeSavingsRows(ins, warnings, bi) {
  ins = ins || {};
  warnings = warnings || [];
  bi = bi || {};
  const rows = [];

  // Duplicate symbols: same name and identical size at multiple addresses.
  // This is only recoverable if the code is byte-identical, so it is a
  // candidate (info), not a guaranteed saving.
  const dups = ins.duplicate_symbols || [];
  if (dups.length > 0) {
    const saved = dups.reduce((s, d) => s + d.total_size - d.size_each, 0);
    if (saved > 0)
      rows.push({ tag: 'info', amt: saved, desc: `${dups.length} symbol(s) share a name and size at multiple addresses. If their code is identical, -flto or --icf=safe can merge them` });
  }

  // Alignment padding: deliberately not added to the recoverable total because
  // most padding in code sections is required by the architecture.
  const pad = ins.padding_waste || {};
  if (pad.total_bytes > 0)
    rows.push({ tag: 'info', amt: null, desc: `${fmtB(pad.total_bytes)} alignment padding between symbols` });

  // Duplicate string literals across translation units.
  const dupStrs = ins.duplicate_strings || [];
  if (dupStrs.length > 0) {
    const saved = dupStrs.reduce((s, d) => s + d.wasted_bytes, 0);
    if (saved > 0)
      rows.push({ tag: 'info', amt: saved, desc: `${dupStrs.length} string literal(s) duplicated across translation units. Add -fmerge-all-constants to deduplicate` });
  }

  // Build timestamps: only a reliable non-reproducible-build signal when BOTH a
  // __DATE__ and a __TIME__ string are present. A lone date- or time-shaped
  // string in .rodata is too likely to be coincidental to warn on.
  const stamps = bi.build_stamps || [];
  const dateStamp = stamps.find(s => s.type === 'date');
  const timeStamp = stamps.find(s => s.type === 'time');
  if (dateStamp && timeStamp)
    rows.push({ tag: 'warn', amt: null, desc: `Non-reproducible build. __DATE__ "${dateStamp.string}", __TIME__ "${timeStamp.string}" found in .rodata. Replace with a build-system variable` });

  for (const w of warnings) {
    if (!w.symbol) continue;
    if (w.symbol === '__cxa_throw' || w.symbol === '__cxa_allocate_exception')
      rows.push({ tag: 'warn', amt: null, desc: 'C++ exceptions linked. Build with -fno-exceptions to remove unwind tables' });
    else if (w.symbol === '_printf_float' || w.symbol === '_scanf_float')
      rows.push({ tag: 'warn', amt: w.size > 0 ? w.size : null, desc: `Float printf/scanf linked (${w.symbol}). Remove -u ${w.symbol} from linker flags` });
  }

  return rows;
}

function renderInsights(ins, warnings, bi) {
  warnings = warnings || [];
  bi = bi || {};
  const hasFiles     = ins.file_contributors && ins.file_contributors.length > 0;
  const hasDirs      = ins.dir_contributors  && ins.dir_contributors.length  > 0;
  const hasDist      = ins.symbol_size_distribution && ins.symbol_size_distribution.length > 0;
  const hasPad       = ins.padding_waste && ins.padding_waste.total_bytes > 0;
  const hasDups      = ins.duplicate_symbols && ins.duplicate_symbols.length > 0;
  const hasRodata    = ins.rodata_summary && ins.rodata_summary.symbol_count > 0;
  const hasDupStrs   = ins.duplicate_strings && ins.duplicate_strings.length > 0;

  if (!hasFiles && !hasDirs && !hasDist && !hasPad && !hasDups && !hasRodata && !hasDupStrs) {
    document.getElementById('card-insights').style.display = '';
    document.getElementById('insights-body').innerHTML = `
      <div style="padding:24px 0;text-align:center;color:var(--text3)">
        <svg xmlns="http://www.w3.org/2000/svg" width="28" height="28" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round" style="margin-bottom:10px;opacity:.4"><circle cx="11" cy="11" r="8"/><line x1="21" y1="21" x2="16.65" y2="16.65"/></svg>
        <div style="font-size:13px;font-weight:600;color:var(--text2);margin-bottom:6px">No symbol data</div>
        <div style="font-size:12px;line-height:1.6;max-width:380px;margin:0 auto">
          This binary was stripped. Compile with <code style="font-family:var(--mono);background:var(--bg4);padding:1px 5px;border-radius:4px">-g</code>
          to get per-file breakdowns, duplicate detection, and size distribution.
        </div>
      </div>`;
    return;
  }
  document.getElementById('card-insights').style.display = '';

  let html = '';

  {
    const savingsRows = computeSavingsRows(ins, warnings, bi);
    if (savingsRows.length > 0) {
      const knownTotal = savingsRows.reduce((s, r) => s + (r.amt || 0), 0);
      html += `<div class="insights-section">
        <span class="insights-label">Savings</span>
        <div class="savings-card" style="margin-top:10px">
          ${knownTotal > 0 ? `<div class="savings-total">${fmtB(knownTotal)}</div><div class="savings-sub">recoverable flash</div>` : ''}
          ${savingsRows.map(r => `<div class="savings-row">
            <span class="savings-tag ${r.tag}">${r.tag.toUpperCase()}</span>
            <span class="savings-amt">${r.amt ? fmtB(r.amt) : '-'}</span>
            <span class="savings-desc">${esc(r.desc)}</span>
          </div>`).join('')}
        </div>
      </div>`;
    }
  }

  if (hasFiles) {
    const SHOW_LIMIT = 15;
    window._insFileRows = ins.file_contributors.slice();
    window._insFileSortKey = 'flash';
    window._insFileSortAsc = false;

    const renderFileTable = () => {
      const key = window._insFileSortKey;
      const asc = window._insFileSortAsc;
      const sorted = window._insFileRows.slice().sort((a, b) => asc ? a[key] - b[key] : b[key] - a[key]);
      const maxFlash = sorted.reduce((m, r) => Math.max(m, r.flash), 1);
      const rowHtml = (r) => {
        const barW = Math.round((r.flash / maxFlash) * 100);
        const filePath = r.file || '(unknown)';
        const parts = filePath.replace(/\\/g, '/').split('/').filter(Boolean);
        const short = parts.length > 3 ? '.../' + parts.slice(-3).join('/') : filePath;
        return `<tr>
          <td class="name-cell" title="${esc(filePath)}">${esc(short)}</td>
          <td class="flash-cell">
            <span class="ins-flash-bar" style="width:${barW}px;max-width:100px"></span>
            <span class="mono">${fmtB(r.flash)}</span>
          </td>
          <td class="num">${r.ram > 0 ? fmtB(r.ram) : '<span style="color:var(--text3)">-</span>'}</td>
        </tr>`;
      };
      const visibleRows = sorted.slice(0, SHOW_LIMIT);
      const hiddenRows  = sorted.slice(SHOW_LIMIT);
      const arrow = (col) => {
        if (window._insFileSortKey !== col) return '<span style="opacity:.25;margin-left:4px">&#8597;</span>';
        return window._insFileSortAsc
          ? '<span style="margin-left:4px">&#8593;</span>'
          : '<span style="margin-left:4px">&#8595;</span>';
      };
      const thStyle = 'cursor:pointer;user-select:none;white-space:nowrap;';
      document.getElementById('ins-files-wrap').innerHTML = `
        <div class="tbl-scroll" style="margin-top:10px">
          <table class="ins-tbl" style="table-layout:auto">
            <thead><tr>
              <th style="min-width:200px">Source file</th>
              <th style="min-width:160px;${thStyle}" onclick="insFilesSort('flash')" title="Sort by Flash">Flash${arrow('flash')}</th>
              <th style="min-width:80px;text-align:right;${thStyle}" onclick="insFilesSort('ram')" title="Sort by RAM">RAM${arrow('ram')}</th>
            </tr></thead>
            <tbody>${visibleRows.map(rowHtml).join('')}</tbody>
            ${hiddenRows.length ? `<tbody id="ins-files-extra" style="display:none">${hiddenRows.map(rowHtml).join('')}</tbody>` : ''}
          </table>
        </div>
        ${hiddenRows.length ? `<button class="ins-show-all" onclick="insToggleExtra('ins-files-extra', this)">Show ${hiddenRows.length} more</button>` : ''}`;
    };
    window._insFilesRender = renderFileTable;

    html += `<div class="insights-section">
      <span class="insights-label">File contributors</span>
      <div id="ins-files-wrap"></div>
    </div>`;
  }

  if (hasDirs) {
    const dirs = ins.dir_contributors.slice(0, 12);
    const maxFlash = dirs.reduce((m, d) => Math.max(m, d.flash), 1);
    html += `<div class="insights-section">
      <span class="insights-label">Flash usage by directory</span>
      <div style="margin-top:10px">
        ${dirs.map(d => {
          const pct = Math.round((d.flash / maxFlash) * 100);
          return `<div class="ins-bar-row">
            <span class="ins-bar-label wide">${esc(d.dir)}</span>
            <div class="ins-bar-track"><div class="ins-bar" style="width:${pct}%"></div></div>
            <span class="ins-bar-stat">${fmtB(d.flash)}</span>
          </div>`;
        }).join('')}
      </div>
    </div>`;
  }

  if (hasDist) {
    const dist = ins.symbol_size_distribution;
    const maxCount = dist.reduce((m, b) => Math.max(m, b.count), 1);
    html += `<div class="insights-section">
      <span class="insights-label">Symbol size distribution</span>
      <div style="margin-top:10px">
        ${dist.map(b => {
          const pct = Math.round((b.count / maxCount) * 100);
          return `<div class="ins-bar-row">
            <span class="ins-bar-label">${esc(b.label)}</span>
            <div class="ins-bar-track"><div class="ins-bar green" style="width:${pct}%"></div></div>
            <span class="ins-bar-count">${b.count.toLocaleString()}</span>
            <span class="ins-bar-stat">${fmtB(b.bytes)}</span>
          </div>`;
        }).join('')}
      </div>
    </div>`;
  }

  if (hasRodata) {
    const rd = ins.rodata_summary;
    html += `<div class="insights-section">
      <span class="insights-label">Read-only data (.rodata)</span>
      <div style="display:flex;gap:32px;margin-top:10px;flex-wrap:wrap">
        <div><div style="font-size:18px;font-weight:600;color:var(--text)">${rd.symbol_count.toLocaleString()}</div><div style="font-size:11px;color:var(--text3);margin-top:2px">symbols</div></div>
        <div><div style="font-size:18px;font-weight:600;color:var(--text)">${fmtB(rd.total_bytes)}</div><div style="font-size:11px;color:var(--text3);margin-top:2px">total size</div></div>
        <div><div style="font-size:18px;font-weight:600;color:var(--text)">${rd.unique_source_files.toLocaleString()}</div><div style="font-size:11px;color:var(--text3);margin-top:2px">source files</div></div>
      </div>
    </div>`;
  }

  if (hasPad) {
    const pw = ins.padding_waste;
    const topSecs = pw.by_section.slice(0, 8);
    html += `<div class="insights-section">
      <span class="insights-label">Alignment padding - ${fmtB(pw.total_bytes)} wasted</span>
      <table class="ins-tbl" style="table-layout:auto;margin-top:10px">
        <thead><tr><th>Section</th><th style="text-align:right">Padding</th></tr></thead>
        <tbody>${topSecs.map(s => `<tr>
          <td class="mono">${esc(s.section)}</td>
          <td class="num">${fmtB(s.bytes)}</td>
        </tr>`).join('')}</tbody>
      </table>
    </div>`;
  }

  if (hasDups) {
    const dups = ins.duplicate_symbols.slice(0, 20);
    html += `<div class="insights-section">
      <span class="insights-label">Identical symbols at multiple addresses (${ins.duplicate_symbols.length})</span>
      <div class="tbl-scroll" style="margin-top:10px">
        <table class="ins-tbl" style="table-layout:auto">
          <thead><tr>
            <th style="min-width:260px">Symbol</th>
            <th style="text-align:right">Copies</th>
            <th style="text-align:right">Each</th>
            <th style="text-align:right">Total</th>
          </tr></thead>
          <tbody>${dups.map(d => `<tr>
            <td class="name-cell" title="${esc(d.name)}">${esc(d.name)}</td>
            <td class="num">${d.count}</td>
            <td class="num">${fmtB(d.size_each)}</td>
            <td class="num">${fmtB(d.total_size)}</td>
          </tr>`).join('')}</tbody>
        </table>
      </div>
    </div>`;
  }

  if (hasDupStrs) {
    const strs = ins.duplicate_strings.slice(0, 20);
    const hiddenStrs = ins.duplicate_strings.slice(20);
    const totalWasted = ins.duplicate_strings.reduce((s, d) => s + d.wasted_bytes, 0);
    html += `<div class="insights-section">
      <span class="insights-label">Duplicate string literals in .rodata (${ins.duplicate_strings.length}) - ${fmtB(totalWasted)} wasted</span>
      <div class="tbl-scroll" style="margin-top:10px">
        <table class="ins-tbl" style="table-layout:auto">
          <thead><tr>
            <th style="min-width:260px">String</th>
            <th style="text-align:right">Copies</th>
            <th style="text-align:right">Length</th>
            <th style="text-align:right">Wasted</th>
          </tr></thead>
          <tbody>${strs.map(d => `<tr>
            <td class="name-cell" title="${esc(d.string)}">${esc(d.string)}</td>
            <td class="num">${d.count}</td>
            <td class="num">${d.length} B</td>
            <td class="num">${fmtB(d.wasted_bytes)}</td>
          </tr>`).join('')}</tbody>
          ${hiddenStrs.length ? `<tbody id="ins-strs-extra" style="display:none">${hiddenStrs.map(d => `<tr>
            <td class="name-cell" title="${esc(d.string)}">${esc(d.string)}</td>
            <td class="num">${d.count}</td>
            <td class="num">${d.length} B</td>
            <td class="num">${fmtB(d.wasted_bytes)}</td>
          </tr>`).join('')}</tbody>` : ''}
        </table>
      </div>
      ${hiddenStrs.length ? `<button class="ins-show-all" onclick="insToggleExtra('ins-strs-extra', this)">Show ${hiddenStrs.length} more</button>` : ''}
      <p style="font-size:10px;color:var(--text3);margin:8px 0 0">Strings at two or more distinct addresses means the linker did not merge them. <code>-fmerge-constants</code> (on by default at -O1+) merges within a single TU. To merge identical literals across translation units, add <code>-fmerge-all-constants</code> to CFLAGS/CXXFLAGS.</p>
    </div>`;
  }

  document.getElementById('insights-body').innerHTML = html;
  if (window._insFilesRender) window._insFilesRender();
}

function insFilesSort(key) {
  if (window._insFileSortKey === key) {
    window._insFileSortAsc = !window._insFileSortAsc;
  } else {
    window._insFileSortKey = key;
    window._insFileSortAsc = false;
  }
  if (window._insFilesRender) window._insFilesRender();
}

function insToggleExtra(id, btn) {
  const el = document.getElementById(id);
  if (!el) return;
  const hidden = el.style.display === 'none';
  el.style.display = hidden ? '' : 'none';
  btn.textContent = hidden ? 'Show less' : `Show more`;
}

if (typeof module !== 'undefined' && module.exports) {
  module.exports = { computeSavingsRows };
}
