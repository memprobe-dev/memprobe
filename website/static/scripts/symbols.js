let SYMS = [], filteredSyms = [], sortCol = 'size', sortDir = -1, symPage = 0;
const PAGE = 100;

function tblFilter() {
  const q = document.getElementById('tbl-q').value.toLowerCase();
  const sf = document.getElementById('tbl-sec').value;
  const tf = document.getElementById('tbl-type').value;
  const dem = document.getElementById('tbl-demangle')?.checked;
  filteredSyms = SYMS.filter(s => {
    if (sf && s.section !== sf) return false;
    if (tf && s.type !== tf) return false;
    if (q) {
      const haystack = (dem && s.demangled ? s.demangled : s.name).toLowerCase()
        + ' ' + (s.object_file || '').toLowerCase();
      if (!haystack.includes(q)) return false;
    }
    return true;
  });
  filteredSyms.sort((a,b) => sortDir*(a[sortCol]>b[sortCol]?1:a[sortCol]<b[sortCol]?-1:0));
  symPage = 0; drawTable();
}

function drawTable() {
  const pages = Math.max(1,Math.ceil(filteredSyms.length/PAGE));
  if (symPage>=pages) symPage=pages-1;
  const slice = filteredSyms.slice(symPage*PAGE,(symPage+1)*PAGE);
  const maxSz = SYMS[0]?.size || 1;
  const dem = document.getElementById('tbl-demangle')?.checked;
  document.getElementById('sym-tbody').innerHTML = slice.map(s => {
    const bw = Math.max(2,Math.round(s.size/maxSz*50));
    const col = tc(s.type);
    const dispName = dem && s.demangled ? s.demangled : s.name;
    const obj = s.library ? `${esc(s.library)} › ${esc(s.object_file)}` : esc(s.object_file);
    return `<tr>
      <td><span class="sym-name" title="${esc(s.name)}">${esc(dispName)}</span></td>
      <td class="sz-cell"><span class="sz-bar" style="width:${Math.min(bw,20)}px;background:${col}"></span>${s.size.toLocaleString()}</td>
      <td><span class="badge" style="background:${hexRgba(col,0.15)};color:${col}">${esc(s.section)}</span></td>
      <td><span class="src-cell">${fmtSrc(s.source_location)}</span></td>
    </tr>`;
  }).join('');
  document.getElementById('sym-count').textContent = `${filteredSyms.length.toLocaleString()} symbols`;
  document.getElementById('pg-info').textContent = `${symPage*PAGE+1}–${Math.min((symPage+1)*PAGE,filteredSyms.length)} of ${filteredSyms.length.toLocaleString()}`;
  document.getElementById('pg-prev').disabled = symPage===0;
  document.getElementById('pg-next').disabled = symPage>=pages-1;
}

function pg(d) { symPage+=d; drawTable(); }

document.querySelectorAll('[data-c]').forEach(th => {
  th.addEventListener('click', () => {
    const c = th.dataset.c;
    sortDir = c===sortCol ? -sortDir : (c==='size'?-1:1);
    sortCol = c;
    document.querySelectorAll('[data-c]').forEach(h => h.classList.remove('sorted'));
    th.classList.add('sorted');
    symPage=0; tblFilter();
  });
});

function initColResize(table) {
  let dragging = null;
  let didDrag = false;

  table.querySelectorAll('.col-resize-handle').forEach(handle => {
    handle.addEventListener('mousedown', e => {
      e.preventDefault();
      e.stopPropagation();
      const th = handle.closest('th');
      dragging = { th, handle, startX: e.clientX, startW: th.offsetWidth };
      didDrag = false;
      handle.classList.add('dragging');
      document.body.style.cursor = 'col-resize';
      document.body.style.userSelect = 'none';
    });
    // Block the th's sort click if we just finished a drag
    handle.addEventListener('click', e => { e.stopPropagation(); });
  });

  document.addEventListener('mousemove', e => {
    if (!dragging) return;
    const dx = e.clientX - dragging.startX;
    if (Math.abs(dx) < 2) return;
    didDrag = true;
    const newW = Math.max(50, dragging.startW + dx);
    const delta = newW - dragging.th.offsetWidth;
    dragging.th.style.width = newW + 'px';
    table.style.width = (table.offsetWidth + delta) + 'px';
  });

  document.addEventListener('mouseup', e => {
    if (!dragging) return;
    // If mouse moved enough to be a drag, swallow the upcoming click on th
    if (didDrag) {
      const th = dragging.th;
      const once = ev => { ev.stopPropagation(); th.removeEventListener('click', once, true); };
      th.addEventListener('click', once, true);
    }
    dragging.handle.classList.remove('dragging');
    document.body.style.cursor = '';
    document.body.style.userSelect = '';
    dragging = null;
    didDrag = false;
  });
}

document.querySelectorAll('table.sym-tbl, table.diff-tbl').forEach(initColResize);
