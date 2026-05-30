/**
 * Call graph tab — interactive node graph + search.
 *
 * Data shape:
 *   _callGraph = {
 *     "func_name": { "calls": ["a","b"], "called_by": ["x"] },
 *     ...
 *   }
 */

let _callGraph    = null;
let _cgNames      = [];
let _cgHistory    = [];
let _cgCurrent    = null;
let _cgSuggestIdx = -1;

// ── Init ──────────────────────────────────────────────────────────────────────

function initCallGraph(data) {
  const graph = data.call_graph;
  console.log('[callgraph] initCallGraph called, call_graph keys:', graph ? Object.keys(graph).length : 'null/missing');

  cgClear();

  const noData = document.getElementById('cg-no-data');

  if (!graph || Object.keys(graph).length === 0) {
    _callGraph = null;
    _cgNames   = [];
    if (noData) noData.style.display = '';
    const expLabel = document.getElementById('exp-callgraph-label');
    if (expLabel) expLabel.style.display = 'none';
    return;
  }

  _callGraph = graph;
  _cgNames   = Object.keys(graph).sort();

  if (noData) noData.style.display = 'none';

  const summary = document.getElementById('cg-summary');
  if (summary) summary.textContent = `${_cgNames.length.toLocaleString()} functions`;

  // Show the call graph export option only when data is available
  const expLabel = document.getElementById('exp-callgraph-label');
  if (expLabel) expLabel.style.display = '';

  _cgRenderEntryPoints();
}

// ── Entry points ──────────────────────────────────────────────────────────────

function _cgRenderEntryPoints() {
  const wrap  = document.getElementById('cg-entrypoints');
  const list  = document.getElementById('cg-ep-list');
  const count = document.getElementById('cg-ep-count');
  if (!wrap || !list || !_callGraph) return;

  const roots = _cgNames.filter(n => {
    const e = _callGraph[n];
    return e && (!e.called_by || e.called_by.length === 0);
  });

  if (roots.length === 0) { wrap.style.display = 'none'; return; }

  count.textContent = `(${roots.length})`;
  list.innerHTML = '';
  roots.slice(0, 30).forEach(n => {
    const btn = document.createElement('button');
    btn.className = 'cg-ep-item';
    btn.textContent = n;
    btn.addEventListener('click', () => cgSelect(n));
    list.appendChild(btn);
  });
  if (roots.length > 30) {
    const more = document.createElement('span');
    more.className = 'cg-ep-more';
    more.textContent = `+${roots.length - 30} more — search to find them`;
    list.appendChild(more);
  }
  wrap.style.display = '';
}

// ── Search ────────────────────────────────────────────────────────────────────

function cgSearch(query) {
  _cgSuggestIdx = -1;
  const clear = document.getElementById('cg-clear');
  if (clear) clear.style.display = query ? '' : 'none';

  if (!_callGraph) {
    document.getElementById('cg-no-data').style.display = '';
    return;
  }

  const q = query.trim().toLowerCase();

  document.getElementById('cg-result').style.display    = 'none';
  document.getElementById('cg-empty').style.display     = 'none';
  document.getElementById('cg-entrypoints').style.display = 'none';
  _cgCurrent = null;

  if (!q) {
    _cgCloseSuggestions();
    _cgRenderEntryPoints();
    _cgUpdateBack();
    return;
  }

  if (_callGraph[query]) {
    _cgPush(query);
    _cgCloseSuggestions();
    return;
  }

  const matches = _cgNames.filter(n => n.toLowerCase().includes(q)).slice(0, 14);

  if (matches.length === 0) {
    document.getElementById('cg-empty').style.display = '';
    _cgCloseSuggestions();
    return;
  }

  const suggestEl = document.getElementById('cg-suggestions');
  suggestEl.innerHTML = '';
  const escapedQ = q.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  matches.forEach((name, i) => {
    const div = document.createElement('div');
    div.className = 'cg-suggest-item';
    div.dataset.idx  = i;
    div.dataset.name = name;
    // Highlight matched substring
    div.innerHTML = esc(name).replace(
      new RegExp(escapedQ.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'), 'gi'),
      m => `<mark>${m}</mark>`,
    );
    div.addEventListener('mousedown', e => e.preventDefault());
    div.addEventListener('click', () => cgSelect(name));
    suggestEl.appendChild(div);
  });
  suggestEl.style.display = '';
}

function _cgCloseSuggestions() {
  const el = document.getElementById('cg-suggestions');
  if (el) { el.innerHTML = ''; el.style.display = 'none'; }
  _cgSuggestIdx = -1;
}

function _cgHighlightSuggestion(idx) {
  const items = document.querySelectorAll('.cg-suggest-item');
  items.forEach((el, i) => el.classList.toggle('cg-suggest-focused', i === idx));
  _cgSuggestIdx = idx;
}

function cgSelect(name) {
  document.getElementById('cg-search').value = name;
  document.getElementById('cg-clear').style.display = '';
  _cgCloseSuggestions();
  _cgPush(name);
}

function cgBack() {
  if (_cgHistory.length < 2) return;
  _cgHistory.pop();
  const prev = _cgHistory[_cgHistory.length - 1];
  _cgHistory.pop();
  document.getElementById('cg-search').value = prev;
  _cgPush(prev);
}

function cgClear() {
  const search = document.getElementById('cg-search');
  if (search) search.value = '';
  _cgCloseSuggestions();
  const result = document.getElementById('cg-result');
  if (result) result.style.display = 'none';
  const empty = document.getElementById('cg-empty');
  if (empty) empty.style.display = 'none';
  const clearBtn = document.getElementById('cg-clear');
  if (clearBtn) clearBtn.style.display = 'none';
  _cgHistory = [];
  _cgCurrent = null;
  _cgUpdateBack();
  if (_callGraph) _cgRenderEntryPoints();
}

// ── Navigation ────────────────────────────────────────────────────────────────

function _cgPush(name) {
  if (!_callGraph || !_callGraph[name]) return;
  _cgHistory.push(name);
  _cgCurrent = name;
  _cgShowFunction(name);
  _cgUpdateBack();
  _cgUpdateBreadcrumb();
}

function _cgUpdateBack() {
  const btn = document.getElementById('cg-back');
  if (btn) btn.disabled = _cgHistory.length < 2;
}

function _cgUpdateBreadcrumb() {
  const el = document.getElementById('cg-breadcrumb');
  if (!el) return;
  const slice = _cgHistory.slice(-4);
  el.innerHTML = slice.map((name, i) => {
    const isLast = i === slice.length - 1;
    const safe   = esc(name);
    if (isLast) return `<span class="cg-bc-current">${safe}</span>`;
    const histIdx = _cgHistory.length - slice.length + i;
    return `<span class="cg-bc-link" onclick="_cgJumpTo(${histIdx})">${safe}</span>
            <span class="cg-bc-sep">›</span>`;
  }).join('');
}

function _cgJumpTo(histIdx) {
  const name = _cgHistory[histIdx];
  if (!name) return;
  _cgHistory = _cgHistory.slice(0, histIdx + 1);
  _cgCurrent = name;
  document.getElementById('cg-search').value = name;
  _cgShowFunction(name);
  _cgUpdateBack();
  _cgUpdateBreadcrumb();
}

// ── Display ───────────────────────────────────────────────────────────────────

function _cgShowFunction(name) {
  if (!_callGraph || !_callGraph[name]) return;

  const entry    = _callGraph[name];
  const calls    = entry.calls     || [];
  const calledBy = entry.called_by || [];

  document.getElementById('cg-func-name').textContent = name;
  document.getElementById('cg-entrypoints').style.display = 'none';

  // Stats
  const callsCountEl    = document.getElementById('cg-calls-count');
  const calledByCountEl = document.getElementById('cg-calledby-count');
  const statsCallsEl    = document.getElementById('cg-stat-calls');
  const statsCalledByEl = document.getElementById('cg-stat-calledby');

  if (callsCountEl)    callsCountEl.textContent    = calls.length    ? `${calls.length}`    : '';
  if (calledByCountEl) calledByCountEl.textContent  = calledBy.length ? `${calledBy.length}` : '';
  if (statsCallsEl)    statsCallsEl.textContent    = calls.length;
  if (statsCalledByEl) statsCalledByEl.textContent = calledBy.length;

  // List filters
  const callsFilter    = document.getElementById('cg-calls-filter');
  const calledByFilter = document.getElementById('cg-calledby-filter');
  if (callsFilter)    { callsFilter.value    = ''; callsFilter.style.display    = calls.length    > 10 ? '' : 'none'; }
  if (calledByFilter) { calledByFilter.value = ''; calledByFilter.style.display = calledBy.length > 10 ? '' : 'none'; }

  _cgReplaceList('cg-calls-list',    calls);
  _cgReplaceList('cg-calledby-list', calledBy);

  document.getElementById('cg-result').style.display = '';
  document.getElementById('cg-empty').style.display   = 'none';

  // Draw graph after the panel is visible so dimensions are correct.
  requestAnimationFrame(() => _cgDrawGraph(name));
}

function _cgReplaceList(id, names) {
  const container = document.getElementById(id);
  if (!container) return;
  const newList = _cgBuildList(names);
  // Copy id and class from the placeholder ul
  newList.id = id;
  newList.className = container.className;
  container.replaceWith(newList);
}

function _cgBuildList(names) {
  const ul = document.createElement('ul');
  ul.className = 'cg-list';
  if (names.length === 0) {
    const li = document.createElement('li');
    li.className = 'cg-list-empty';
    li.textContent = 'none';
    ul.appendChild(li);
    return ul;
  }
  names.forEach(n => {
    const inGraph = !!(_callGraph && _callGraph[n]);
    const li = document.createElement('li');
    li.className = `cg-list-item${inGraph ? ' cg-link' : ''}`;
    li.textContent = n;
    if (inGraph) li.addEventListener('click', () => cgSelect(n));
    ul.appendChild(li);
  });
  return ul;
}

function cgFilterList(side) {
  const inputId = side === 'calls' ? 'cg-calls-filter' : 'cg-calledby-filter';
  const listId  = side === 'calls' ? 'cg-calls-list'   : 'cg-calledby-list';
  if (!_cgCurrent || !_callGraph || !_callGraph[_cgCurrent]) return;
  const q     = document.getElementById(inputId).value.trim().toLowerCase();
  const entry = _callGraph[_cgCurrent];
  const all   = (side === 'calls' ? entry.calls : entry.called_by) || [];
  _cgReplaceList(listId, q ? all.filter(n => n.toLowerCase().includes(q)) : all);
}

function cgCopyName() {
  if (!_cgCurrent) return;
  navigator.clipboard.writeText(_cgCurrent).then(() => {
    const btn   = document.getElementById('cg-copy-btn');
    const label = btn?.querySelector('.cg-copy-label');
    if (!btn) return;
    btn.classList.add('cg-copy-ok');
    if (label) label.textContent = 'Copied!';
    setTimeout(() => {
      btn.classList.remove('cg-copy-ok');
      if (label) label.textContent = 'Copy';
    }, 1500);
  }).catch(() => {});
}

// ── Graph renderer ────────────────────────────────────────────────────────────

const _CG_MAX_SIDE = 10;   // max caller/callee nodes shown in graph
const _CG_COLORS = {
  callerStroke: '#5b9cf6',
  callerFill:   'rgba(91,156,246,0.08)',
  calleeStroke: '#3dd68c',
  calleeFill:   'rgba(61,214,140,0.08)',
  centerStroke: '#5b9cf6',
  edgeCaller:   'rgba(91,156,246,0.45)',
  edgeCallee:   'rgba(61,214,140,0.45)',
};

const SVG_NS = 'http://www.w3.org/2000/svg';

function _svgEl(tag, attrs) {
  const el = document.createElementNS(SVG_NS, tag);
  for (const [k, v] of Object.entries(attrs)) el.setAttribute(k, v);
  return el;
}

function _cgDrawGraph(name) {
  const svg = document.getElementById('cg-graph');
  if (!svg || !_callGraph || !_callGraph[name]) return;

  const entry    = _callGraph[name];
  const calls    = (entry.calls     || []).slice(0, _CG_MAX_SIDE);
  const calledBy = (entry.called_by || []).slice(0, _CG_MAX_SIDE);
  const moreCallees = (entry.calls     || []).length - calls.length;
  const moreCallers = (entry.called_by || []).length - calledBy.length;

  const W = svg.parentElement?.clientWidth || 640;
  const maxSide = Math.max(calls.length, calledBy.length, 1);
  const NODE_SPACING = 38;
  const H = Math.max(180, maxSide * NODE_SPACING + 80);

  svg.setAttribute('width',   W);
  svg.setAttribute('height',  H);
  svg.setAttribute('viewBox', `0 0 ${W} ${H}`);

  // Clear previous content
  while (svg.firstChild) svg.removeChild(svg.firstChild);

  const cx = W / 2;
  const cy = H / 2;
  const CENTER_R = 28;
  const SIDE_R   = 16;

  const sideOffset = Math.min(cx - 90, Math.max(160, W * 0.28));
  const leftX  = cx - sideOffset;
  const rightX = cx + sideOffset;

  function sideY(i, total) {
    if (total <= 1) return cy;
    const used = Math.min(total * NODE_SPACING, H - 60);
    const step = used / (total - 1);
    return (H - used) / 2 + i * step;
  }

  function truncate(s, max) {
    return s.length > max ? s.slice(0, max - 1) + '…' : s;
  }

  // Defs: markers + glow filter
  const defs = _svgEl('defs', {});

  function makeMarker(id, color) {
    const m = _svgEl('marker', { id, markerWidth: '7', markerHeight: '7', refX: '5', refY: '3.5', orient: 'auto' });
    const p = _svgEl('path', { d: 'M0,1 L5,3.5 L0,6 Z', fill: color, opacity: '.8' });
    m.appendChild(p);
    return m;
  }
  defs.appendChild(makeMarker('arr-callee', _CG_COLORS.calleeStroke));
  defs.appendChild(makeMarker('arr-caller', _CG_COLORS.callerStroke));

  const filter = _svgEl('filter', { id: 'cg-glow', x: '-30%', y: '-30%', width: '160%', height: '160%' });
  const blur   = _svgEl('feGaussianBlur', { stdDeviation: '3', result: 'blur' });
  const merge  = _svgEl('feMerge', {});
  merge.appendChild(_svgEl('feMergeNode', { in: 'blur' }));
  merge.appendChild(_svgEl('feMergeNode', { in: 'SourceGraphic' }));
  filter.appendChild(blur);
  filter.appendChild(merge);
  defs.appendChild(filter);
  svg.appendChild(defs);

  // Edges (drawn first, behind nodes)
  calledBy.forEach((n, i) => {
    const y    = sideY(i, calledBy.length + (moreCallers > 0 ? 1 : 0));
    const cp1x = leftX + sideOffset * 0.45;
    const cp2x = cx    - sideOffset * 0.45;
    svg.appendChild(_svgEl('path', {
      d: `M${leftX + SIDE_R},${y} C${cp1x},${y} ${cp2x},${cy} ${cx - CENTER_R},${cy}`,
      stroke: _CG_COLORS.edgeCaller, 'stroke-width': '1.5', fill: 'none',
      'marker-end': 'url(#arr-caller)',
    }));
  });

  calls.forEach((n, i) => {
    const y    = sideY(i, calls.length + (moreCallees > 0 ? 1 : 0));
    const cp1x = cx     + sideOffset * 0.45;
    const cp2x = rightX - sideOffset * 0.45;
    svg.appendChild(_svgEl('path', {
      d: `M${cx + CENTER_R},${cy} C${cp1x},${cy} ${cp2x},${y} ${rightX - SIDE_R},${y}`,
      stroke: _CG_COLORS.edgeCallee, 'stroke-width': '1.5', fill: 'none',
      'marker-end': 'url(#arr-callee)',
    }));
  });

  // Side node builder
  function makeNode(x, y, label, fullName, stroke, fill, clickable) {
    const g = _svgEl('g', { style: `cursor:${clickable ? 'pointer' : 'default'}`, 'pointer-events': 'all' });

    const circle = _svgEl('circle', {
      cx: x, cy: y, r: SIDE_R,
      fill, stroke, 'stroke-width': '1.5',
    });
    if (clickable) circle.classList.add('cg-gnode');

    const text = _svgEl('text', {
      x, y: y + 4, 'text-anchor': 'middle',
      'font-size': '9', 'font-family': 'var(--mono,monospace)',
      fill: stroke, 'font-weight': '500', 'pointer-events': 'none',
    });
    text.textContent = truncate(label, 15);

    const title = _svgEl('title', {});
    title.textContent = fullName;

    g.appendChild(circle);
    g.appendChild(text);
    g.appendChild(title);

    if (clickable) {
      g.addEventListener('click', () => cgSelect(fullName));
    }
    return g;
  }

  // Caller nodes (left)
  calledBy.forEach((n, i) => {
    const y = sideY(i, calledBy.length + (moreCallers > 0 ? 1 : 0));
    svg.appendChild(makeNode(leftX, y, n, n, _CG_COLORS.callerStroke, _CG_COLORS.callerFill, !!_callGraph[n]));
  });

  // Callee nodes (right)
  calls.forEach((n, i) => {
    const y = sideY(i, calls.length + (moreCallees > 0 ? 1 : 0));
    svg.appendChild(makeNode(rightX, y, n, n, _CG_COLORS.calleeStroke, _CG_COLORS.calleeFill, !!_callGraph[n]));
  });

  // Overflow labels
  if (moreCallers > 0) {
    const y = sideY(calledBy.length, calledBy.length + 1);
    const t = _svgEl('text', { x: leftX, y: y + 4, 'text-anchor': 'middle',
      'font-size': '10', fill: _CG_COLORS.callerStroke, opacity: '.55',
      'font-family': 'var(--mono,monospace)' });
    t.textContent = `+${moreCallers} more`;
    svg.appendChild(t);
  }
  if (moreCallees > 0) {
    const y = sideY(calls.length, calls.length + 1);
    const t = _svgEl('text', { x: rightX, y: y + 4, 'text-anchor': 'middle',
      'font-size': '10', fill: _CG_COLORS.calleeStroke, opacity: '.55',
      'font-family': 'var(--mono,monospace)' });
    t.textContent = `+${moreCallees} more`;
    svg.appendChild(t);
  }

  // Column labels
  if (calledBy.length > 0 || moreCallers > 0) {
    const t = _svgEl('text', { x: leftX, y: '14', 'text-anchor': 'middle',
      'font-size': '8', 'font-weight': '700', 'letter-spacing': '1.5',
      fill: _CG_COLORS.callerStroke, opacity: '.7', 'font-family': 'var(--sans,sans-serif)' });
    t.textContent = 'CALLED BY';
    svg.appendChild(t);
  }
  if (calls.length > 0 || moreCallees > 0) {
    const t = _svgEl('text', { x: rightX, y: '14', 'text-anchor': 'middle',
      'font-size': '8', 'font-weight': '700', 'letter-spacing': '1.5',
      fill: _CG_COLORS.calleeStroke, opacity: '.7', 'font-family': 'var(--sans,sans-serif)' });
    t.textContent = 'CALLS';
    svg.appendChild(t);
  }

  // Center glow ring
  const glowG = _svgEl('g', { filter: 'url(#cg-glow)' });
  glowG.appendChild(_svgEl('circle', {
    cx, cy, r: CENTER_R + 4, fill: 'none',
    stroke: _CG_COLORS.centerStroke, 'stroke-width': '1', opacity: '.2',
  }));
  svg.appendChild(glowG);

  // Center node (on top, not clickable — already selected)
  const centerCircle = _svgEl('circle', {
    cx, cy, r: CENTER_R, fill: 'var(--bg2)',
    stroke: _CG_COLORS.centerStroke, 'stroke-width': '2',
  });
  const centerText = _svgEl('text', {
    x: cx, y: cy + 4, 'text-anchor': 'middle',
    'font-size': '9', 'font-family': 'var(--mono,monospace)',
    fill: 'var(--text)', 'font-weight': '700', 'pointer-events': 'none',
  });
  centerText.textContent = truncate(name, 20);
  svg.appendChild(centerCircle);
  svg.appendChild(centerText);
}

// ── Keyboard shortcuts ────────────────────────────────────────────────────────

document.addEventListener('DOMContentLoaded', () => {
  const search = document.getElementById('cg-search');
  if (!search) return;

  search.addEventListener('keydown', e => {
    const items = document.querySelectorAll('.cg-suggest-item');
    if (e.key === 'ArrowDown') {
      e.preventDefault();
      _cgHighlightSuggestion(Math.min(_cgSuggestIdx + 1, items.length - 1));
    } else if (e.key === 'ArrowUp') {
      e.preventDefault();
      _cgHighlightSuggestion(Math.max(_cgSuggestIdx - 1, 0));
    } else if (e.key === 'Enter') {
      if (_cgSuggestIdx >= 0 && items[_cgSuggestIdx]) {
        items[_cgSuggestIdx].click();
      } else if (items.length > 0) {
        items[0].click();
      }
    } else if (e.key === 'Escape') {
      _cgCloseSuggestions();
      search.blur();
    }
  });

  search.addEventListener('blur', () => setTimeout(_cgCloseSuggestions, 150));
});

// Redraw graph on window resize.
window.addEventListener('resize', () => {
  if (_cgCurrent) requestAnimationFrame(() => _cgDrawGraph(_cgCurrent));
});
