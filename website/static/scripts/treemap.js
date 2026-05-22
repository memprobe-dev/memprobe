// Each drill-in creates a fresh D3 hierarchy from the raw data node.
// This avoids stale x0/y0/x1/y1 coordinates from parent layout passes.
const TM_H = 500;
let tmRawRoot, tmRawCurrent, tmRawHistory = [];

const TM_PAGE = 200; // max children shown per level before an overflow bucket appears

function groupSmall(node) {
  if (!node.children) return node;
  const kids = node.children.map(groupSmall);
  if (kids.length > TM_PAGE) {
    const sorted = [...kids].sort((a,b) => (b.size_bytes||0) - (a.size_bytes||0));
    const keep = sorted.slice(0, TM_PAGE);
    const rest = sorted.slice(TM_PAGE);
    const restSize = rest.reduce((s,c) => s + (c.size_bytes||0), 0);
    // Recursively group the overflow bucket so each page shows 200 at a time
    if (restSize > 0) keep.push(groupSmall({
      name: `(${rest.length} more)`, size_bytes: restSize,
      type: node.type || 'other', is_overflow: true, children: rest,
    }));
    return { ...node, children: keep };
  }
  return { ...node, children: kids };
}

function renderTreemap(data) {
  tmRawRoot = groupSmall(data);
  tmRawHistory = [];
  hideTmNoSyms();
  _tmDraw(tmRawRoot);
  _tmUpdateBC();
}

function hideTmNoSyms() {
  document.getElementById('tm-no-syms').classList.remove('show');
  document.getElementById('treemap-svg').style.display = '';
}
function showTmNoSyms() {
  document.getElementById('tm-no-syms').classList.add('show');
  document.getElementById('treemap-svg').style.display = 'none';
}

function _tmDraw(rawData) {
  tmRawCurrent = rawData;

  if (!rawData.children || rawData.children.length === 0) {
    showTmNoSyms(); _tmUpdateBC(); return;
  }
  hideTmNoSyms();

  const svgEl = document.getElementById('treemap-svg');
  const W = svgEl.getBoundingClientRect().width || svgEl.parentElement.clientWidth || 900;
  svgEl.setAttribute('viewBox', `0 0 ${W} ${TM_H}`);

  // Build hierarchy - sum only leaves so interior nodes get correct aggregate sizes
  const root = d3.hierarchy(rawData, d => d.children)
    .sum(d => (!d.children || d.children.length === 0) ? (d.size_bytes || 0) : 0)
    .sort((a,b) => b.value - a.value);

  if (!root.value) { showTmNoSyms(); _tmUpdateBC(); return; }

  const isRoot = (rawData === tmRawRoot);

  d3.treemap()
    .size([W, TM_H])
    .paddingOuter(3).paddingInner(2)
    .round(true)
    .tile(d3.treemapSquarify.ratio(1.618))
    (root);

  const svg = d3.select('#treemap-svg');
  svg.selectAll('*').remove();

  svg.append('rect').attr('width', W).attr('height', TM_H).attr('fill', 'transparent')
    .style('cursor', tmRawHistory.length ? 'pointer' : 'default')
    .on('click', () => {
      if (!tmRawHistory.length) return;
      hideSymPanel();
      const prev = tmRawHistory.pop();
      _tmDraw(prev); _tmUpdateBC();
      if (prev === tmRawRoot) filterBySection('');
    });

  // Render only DIRECT CHILDREN at each level (never leaves).
  // This gives clean solid blocks at every depth instead of a noisy symbol mosaic.
  const cells = root.children || [];

  const cell = svg.selectAll('g.c').data(cells).join('g').attr('class','c')
    .attr('transform', d => `translate(${d.x0},${d.y0})`)
    .style('cursor', 'pointer')
    .on('click', (event, d) => {
      event.stopPropagation();
      const data = d.data;
      if (data.children && data.children.length > 0) {
        hideSymPanel();
        if (isRoot) filterBySection(data.name);
        tmRawHistory.push(tmRawCurrent);
        _tmDraw(data); _tmUpdateBC();
      } else {
        showSymPanel(data);
      }
    });

  const isDrillable = d => !!(d.data.children && d.data.children.length > 0);
  cell.append('rect')
    .attr('width',  d => Math.max(0, d.x1-d.x0-0.5))
    .attr('height', d => Math.max(0, d.y1-d.y0-0.5))
    .attr('rx', 3)
    .attr('fill', d => d.data.is_overflow ? '#2a2a3e' : tc(d.data.type || 'other'))
    .attr('fill-opacity', d => d.data.is_overflow ? 1 : isDrillable(d) ? 0.62 : 0.75)
    .attr('stroke', d => d.data.is_overflow ? '#5b9cf6' : isDrillable(d) ? tc(d.data.type || 'other') : '#0c0c10')
    .attr('stroke-width', d => d.data.is_overflow ? 1.5 : 1)
    .attr('stroke-opacity', d => d.data.is_overflow ? 0.7 : isDrillable(d) ? 0.5 : 1)
    .attr('stroke-dasharray', d => d.data.is_overflow ? '5,3' : null);

  cell.each(function(d) {
    const rw = d.x1-d.x0, rh = d.y1-d.y0;
    if (rw < 24 || rh < 14) return;
    const isOvf = d.data.is_overflow;
    const col = isOvf ? '#5b9cf6' : tc(d.data.type||'other');
    const lum = isOvf ? 0 : getLum(col);
    const fg  = isOvf ? '#5b9cf6' : (lum > 0.35 ? '#000' : '#fff');
    const fs  = Math.min(13, Math.max(9, rw / 9));
    const maxC = Math.floor((rw - 10) / fs * 0.65);
    let label = d.data.name;
    if (label.length > maxC) label = label.slice(0, Math.max(3, maxC - 1)) + '…';
    d3.select(this).append('text')
      .attr('x', 6).attr('y', Math.min(16, rh * 0.65))
      .attr('fill', fg).attr('fill-opacity', isOvf ? 1 : 0.92)
      .attr('font-size', isOvf ? Math.min(fs + 1, 14) : fs)
      .attr('font-weight', isOvf ? '600' : 'normal')
      .attr('font-family', "'SF Mono','Fira Code',monospace")
      .text(label);
    if (rh > 30 && d.value) {
      d3.select(this).append('text')
        .attr('x', 6).attr('y', Math.min(30, rh * 0.88))
        .attr('fill', fg).attr('fill-opacity', isOvf ? 0.7 : 0.50)
        .attr('font-size', Math.min(10, fs - 1))
        .text(fmtB(d.value));
    }
  });

  cell.append('title').text(d => {
    let tip = `${d.data.name}\n${fmtB(d.value || d.data.size_bytes || 0)}`;
    if (d.data.is_overflow)   tip += `\nClick to expand`;
    else if (isDrillable(d))  tip += `\nClick to drill in`;
    if (d.data.object_file && !d.data.is_obj_group) tip += `\n${d.data.object_file}`;
    if (d.data.source_location) tip += `\n@ ${d.data.source_location}`;
    return tip;
  });

  _tmUpdateBC();
}

function tmZoomOut() {
  tmRawHistory = []; hideTmNoSyms(); hideSymPanel(); _tmDraw(tmRawRoot); _tmUpdateBC();
  filterBySection('');
}

function filterBySection(secName) {
  const sel = document.getElementById('tbl-sec');
  if (!sel) return;
  const opt = [...sel.options].find(o => o.value === secName);
  if (opt || secName === '') {
    sel.value = secName;
    tblFilter();
  }
}

function hideSymPanel() {
  document.getElementById('sym-panel').classList.remove('show');
}

function showSymPanel(data) {
  const panel = document.getElementById('sym-panel');
  const col = tc(data.type || 'other');
  const rows = [
    ['Symbol',  data.name],
    ['Size',    fmtB(data.size_bytes || 0) + `  (${(data.size_bytes||0).toLocaleString()} bytes)`],
    ['Section', tmRawCurrent.name || ''],
    ['Type',    data.type || 'other'],
    ['Object',  data.object_file && data.object_file !== '(elf)' ? data.object_file : ''],
    ['Library', data.library || ''],
    ['Source',  data.source_location || ''],
  ].filter(([, v]) => v);

  panel.innerHTML = rows.map(([k, v]) => {
    let valHtml = esc(v);
    if (k === 'Source') valHtml = fmtSrc(v);
    return `<div class="sym-panel-row">
      <span class="sym-panel-key">${k}</span>
      <span class="sym-panel-val" style="${k==='Symbol'?'color:'+col:''}">${valHtml}</span>
    </div>`;
  }).join('');
  panel.classList.add('show');
}

function _tmUpdateBC() {
  const bc = document.getElementById('bc');
  bc.innerHTML = '';
  const add = (label, fn) => {
    const sp = document.createElement('span');
    if (fn) { sp.className='bc-link'; sp.onclick=fn; } else { sp.className='bc-cur'; }
    sp.textContent = label; bc.appendChild(sp);
  };
  const sep = () => { const sp = document.createElement('span'); sp.className='bc-sep'; sp.textContent='›'; bc.appendChild(sp); };

  if (tmRawCurrent === tmRawRoot) { add('firmware', null); return; }
  add('firmware', () => { tmRawHistory=[]; hideTmNoSyms(); hideSymPanel(); _tmDraw(tmRawRoot); _tmUpdateBC(); });

  // Skip overflow nodes in breadcrumb - they'd create a chain like (1680 more) › (1480 more) › …
  for (let i = 1; i < tmRawHistory.length; i++) {
    const raw = tmRawHistory[i];
    if (raw.is_overflow) continue;
    sep();
    add(raw.name, () => {
      tmRawHistory.length = i; hideTmNoSyms(); hideSymPanel(); _tmDraw(raw); _tmUpdateBC();
    });
  }
  sep();
  // If current is overflow, show a compact page indicator instead of the full name
  if (tmRawCurrent.is_overflow) {
    add(`(${tmRawCurrent.children?.length ?? '?'} more)`, null);
  } else {
    add(tmRawCurrent.name, null);
  }
}
