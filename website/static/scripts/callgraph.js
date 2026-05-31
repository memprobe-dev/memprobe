/**
 * Call graph tab: interactive node graph + search.
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

  cgClear();

  const noData = document.getElementById('cg-no-data');

  if (!graph || Object.keys(graph).length === 0) {
    _callGraph = null;
    _cgNames   = [];
    if (noData) noData.style.display = '';
    // Surface the parser's explicit reason so an absent graph is never silent.
    const reasonEl = document.getElementById('cg-no-data-reason');
    if (reasonEl) {
      const status = (data.binary_info || {}).call_graph_status;
      reasonEl.textContent = status || 'No call graph could be extracted from this binary.';
    }
    const expLabel = document.getElementById('exp-callgraph-label');
    if (expLabel) expLabel.style.display = 'none';
    return;
  }

  _callGraph = graph;
  _cgNames   = Object.keys(graph).sort();

  // Map function name -> flash bytes so graph nodes can be sized by cost. The
  // call graph keys may be mangled or demangled, so index under both.
  _cgSizeByName = {};
  for (const s of (data.symbols || [])) {
    if (!s || !s.size) continue;
    if (s.name)      _cgSizeByName[s.name]      = s.size;
    if (s.demangled) _cgSizeByName[s.demangled] = s.size;
  }
  _cgDepth    = 1;
  _cgOverview = false;
  _cgSyncControls();

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
    more.textContent = `+${roots.length - 30} more, search to find them`;
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
  // Selecting a function always focuses it; leave the whole-graph overview.
  _cgOverview = false;
  _cgSyncControls();
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

// ── Graph model (pure helpers, unit-tested) ──────────────────────────────────

const _CG_EGO_CAP  = 80;    // max nodes in a focused neighborhood view
const _CG_FULL_CAP = 400;   // max nodes in the whole-graph overview
const _CG_LABEL_MAX = 200;  // above this, full-graph labels collapse into noise

// Build the nodes + links to show around `focus`, walking callees downstream and
// callers upstream up to `depth` hops. Each node keeps the direction it was
// first reached from: 'focus', 'down' (callee chain), 'up' (caller chain), or
// 'both'. Pure (no DOM) so it can be unit-tested.
function cgEgoGraph(graph, focus, depth, cap) {
  cap = cap || _CG_EGO_CAP;
  if (!graph || !graph[focus]) return { nodes: [], links: [], truncated: false };

  const side  = new Map([[focus, 'focus']]);
  const order = [focus];
  let truncated = false;

  function mark(name, dir) {
    const prev = side.get(name);
    if (prev === undefined) {
      if (side.size >= cap) { truncated = true; return false; }
      side.set(name, dir);
      order.push(name);
      return true;
    }
    if (prev !== dir && prev !== 'focus') side.set(name, 'both');
    return false;
  }

  function walk(dir, neighborsOf) {
    let frontier = [focus];
    for (let d = 0; d < depth; d++) {
      const next = [];
      for (const cur of frontier) {
        const e = graph[cur];
        if (!e) continue;
        for (const nb of (neighborsOf(e) || [])) {
          if (mark(nb, dir)) next.push(nb);
        }
      }
      frontier = next;
    }
  }
  walk('down', e => e.calls);
  walk('up',   e => e.called_by);

  return _cgLinkUp(graph, order, side, truncated);
}

// Whole-graph overview: every function, capped for performance. Pure.
function cgFullGraph(graph, cap) {
  cap = cap || _CG_FULL_CAP;
  if (!graph) return { nodes: [], links: [], truncated: false };
  const all   = Object.keys(graph);
  const order = all.slice(0, cap);
  const side  = new Map(order.map(n => [n, 'none']));
  return _cgLinkUp(graph, order, side, all.length > cap);
}

// Shared tail of the two builders: collect intra-set call edges and shape nodes.
function _cgLinkUp(graph, order, side, truncated) {
  const visible = new Set(order);
  const links = [];
  for (const u of order) {
    const e = graph[u];
    if (!e) continue;
    for (const v of (e.calls || [])) {
      if (visible.has(v)) links.push({ source: u, target: v });
    }
  }
  return {
    nodes: order.map(n => ({ name: n, side: side.get(n) })),
    links,
    truncated,
  };
}

// Node radius from function size: sqrt scale so area tracks bytes. Pure.
function cgNodeRadius(bytes, maxBytes) {
  const MIN = 6, MAX = 26;
  if (!bytes || !maxBytes || maxBytes <= 0) return MIN;
  const r = MIN + (MAX - MIN) * Math.sqrt(bytes / maxBytes);
  return Math.max(MIN, Math.min(MAX, r));
}

// ── Graph renderer (d3 force layout) ──────────────────────────────────────────

const _CG_SIDE_COLOR = {
  focus: '#e8edf5',
  up:    '#5b9cf6',   // caller chain
  down:  '#3dd68c',   // callee chain
  both:  '#b48ce8',   // on both a caller and a callee path
  none:  '#7a8699',   // overview (direction not meaningful)
};

let _cgDepth     = 1;
let _cgOverview  = false;
let _cgSizeByName = {};
let _cgSim       = null;
let _cgZoom      = null;
let _cgSvgSel    = null;
let _cgNodes     = [];
let _cgW = 640, _cgH = 380;
// Auto-fit frames the graph once after the initial layout settles. Any user
// gesture (zoom, pan, drag) turns it off so the view never jumps out from
// under the user when the simulation re-cools.
let _cgAutoFit   = false;

function _cgSizeOf(name) {
  return _cgSizeByName[name] || 0;
}

function cgSetDepth(d) {
  _cgDepth = d;
  _cgOverview = false;
  _cgSyncControls();
  if (_cgCurrent) _cgDrawGraph(_cgCurrent);
}

function cgToggleOverview() {
  _cgOverview = !_cgOverview;
  _cgSyncControls();
  if (_cgCurrent) _cgDrawGraph(_cgCurrent);
}

function cgFit() { _cgFitNow(); }

function _cgSyncControls() {
  document.querySelectorAll('.cg-depth-btn').forEach(b => {
    b.classList.toggle('cg-depth-active', Number(b.dataset.depth) === _cgDepth && !_cgOverview);
  });
  const ov = document.getElementById('cg-overview-btn');
  if (ov) {
    ov.classList.toggle('cg-tool-active', _cgOverview);
    ov.textContent = _cgOverview ? 'Focused' : 'Full graph';
  }
}

function _cgDrawGraph(name) {
  const model = _cgOverview
    ? cgFullGraph(_callGraph, _CG_FULL_CAP)
    : cgEgoGraph(_callGraph, name, _cgDepth, _CG_EGO_CAP);
  _cgRenderForce(model, name);
  _cgRenderHint(model, name);
}

function _cgRenderHint(model, name) {
  const el = document.getElementById('cg-graph-hint');
  if (!el) return;
  const n = model.nodes.length;
  let msg;
  if (_cgOverview) {
    msg = `Full call graph: ${n.toLocaleString()} function${n === 1 ? '' : 's'}.`;
  } else {
    msg = `${n.toLocaleString()} function${n === 1 ? '' : 's'} within ${_cgDepth} hop${_cgDepth === 1 ? '' : 's'} of ${name}.`;
  }
  if (model.truncated) msg += ` Capped${_cgOverview ? ` at ${_CG_FULL_CAP}` : ` at ${_CG_EGO_CAP}`}; refine with search.`;
  if (_cgOverview && n > _CG_LABEL_MAX) msg += ' Too many to label; hover for names.';
  msg += ' Click a node to focus, drag to move, scroll to zoom.';
  el.textContent = msg;
}

function _cgRenderForce(model, focus) {
  const svg = document.getElementById('cg-graph');
  if (!svg || typeof d3 === 'undefined') return;

  if (_cgSim) { _cgSim.stop(); _cgSim = null; }
  _cgTipHide();
  while (svg.firstChild) svg.removeChild(svg.firstChild);

  const W = svg.parentElement?.clientWidth || 640;
  const H = 380;
  _cgW = W; _cgH = H;
  svg.setAttribute('width', W);
  svg.setAttribute('height', H);
  svg.setAttribute('viewBox', `0 0 ${W} ${H}`);

  if (!model.nodes.length) return;

  const maxBytes = model.nodes.reduce((m, n) => Math.max(m, _cgSizeOf(n.name)), 0);
  // Full-graph mode shows names too, but only while the count stays legible;
  // past that they overlap into noise, so fall back to hover-only.
  const showLabels = !_cgOverview || model.nodes.length <= _CG_LABEL_MAX;

  const nodes = model.nodes.map(n => ({
    name: n.name,
    side: n.side,
    r: cgNodeRadius(_cgSizeOf(n.name), maxBytes),
  }));
  const links = model.links.map(l => ({ source: l.source, target: l.target }));

  const svgSel = d3.select(svg);
  _cgSvgSel = svgSel;

  // Arrowhead marker (neutral, sized in user space so it stays crisp on zoom).
  const defs = svgSel.append('defs');
  defs.append('marker')
    .attr('id', 'cg-arrow')
    .attr('viewBox', '0 0 8 8')
    .attr('refX', 7).attr('refY', 4)
    .attr('markerWidth', 6).attr('markerHeight', 6)
    .attr('markerUnits', 'userSpaceOnUse')
    .attr('orient', 'auto')
    .append('path')
    .attr('d', 'M0,1 L7,4 L0,7 Z')
    .attr('fill', 'var(--text3, #7a8699)');

  const g = svgSel.append('g').attr('class', 'cg-zoom');

  _cgZoom = d3.zoom().scaleExtent([0.2, 4]).on('zoom', e => {
    g.attr('transform', e.transform);
    // e.sourceEvent is set only for user-driven zoom/pan, not our programmatic
    // fit transition. Once the user moves the view, stop auto-fitting.
    if (e.sourceEvent) _cgAutoFit = false;
  });
  svgSel.call(_cgZoom).on('dblclick.zoom', null);

  const linkSel = g.append('g')
    .attr('stroke', 'var(--border2, #3a4150)')
    .attr('stroke-opacity', 0.7)
    .selectAll('line')
    .data(links)
    .join('line')
    .attr('stroke-width', 1.4)
    .attr('marker-end', 'url(#cg-arrow)');

  const nodeSel = g.append('g')
    .selectAll('g')
    .data(nodes)
    .join('g')
    .attr('class', d => 'cg-gnode' + (d.name === focus ? ' cg-gnode-focus' : ''))
    .style('cursor', d => d.name === focus ? 'default' : 'pointer')
    .on('click', (e, d) => { if (d.name !== focus) cgSelect(d.name); })
    .on('mouseenter', (e, d) => _cgTipShow(e, d.name))
    .on('mousemove', e => _cgTipMove(e))
    .on('mouseleave', () => _cgTipHide())
    .call(_cgDragBehavior());

  nodeSel.filter(d => d.name === focus)
    .append('circle')
    .attr('class', 'cg-focus-ring')
    .attr('r', d => d.r + 5)
    .attr('fill', 'none')
    .attr('stroke', _CG_SIDE_COLOR.focus)
    .attr('stroke-opacity', 0.35)
    .attr('stroke-width', 1.5);

  nodeSel.append('circle')
    .attr('r', d => d.r)
    .attr('fill', d => d.name === focus ? 'var(--bg2, #1a1f29)' : _cgFill(d.side))
    .attr('stroke', d => _CG_SIDE_COLOR[d.side] || _CG_SIDE_COLOR.none)
    .attr('stroke-width', d => d.name === focus ? 2 : 1.5);

  if (showLabels) {
    nodeSel.append('text')
      .attr('x', d => d.r + 5)
      .attr('y', 3)
      .attr('font-size', 10)
      .attr('font-family', 'var(--mono, monospace)')
      .attr('fill', d => d.name === focus ? 'var(--text, #e8edf5)' : 'var(--text2, #aab3c0)')
      .attr('font-weight', d => d.name === focus ? 700 : 400)
      .attr('pointer-events', 'none')
      .text(d => _cgTruncate(d.name, 22));
  }

  const sim = d3.forceSimulation(nodes)
    .force('link', d3.forceLink(links).id(d => d.name).distance(d => 60 + d.source.r + d.target.r).strength(0.5))
    .force('charge', d3.forceManyBody().strength(_cgOverview ? -120 : -260))
    .force('center', d3.forceCenter(W / 2, H / 2))
    .force('collide', d3.forceCollide().radius(d => d.r + (showLabels ? 16 : 4)))
    .on('tick', () => {
      linkSel
        .attr('x1', d => d.source.x)
        .attr('y1', d => d.source.y)
        .attr('x2', d => { const a = Math.atan2(d.target.y - d.source.y, d.target.x - d.source.x); return d.target.x - Math.cos(a) * (d.target.r + 4); })
        .attr('y2', d => { const a = Math.atan2(d.target.y - d.source.y, d.target.x - d.source.x); return d.target.y - Math.sin(a) * (d.target.r + 4); });
      nodeSel.attr('transform', d => `translate(${d.x},${d.y})`);
    })
    .on('end', () => { if (_cgAutoFit) { _cgAutoFit = false; _cgFitNow(); } });

  _cgSim = sim;
  _cgNodes = nodes;
  _cgAutoFit = true;  // frame once when this layout settles
}

function _cgFill(side) {
  const c = _CG_SIDE_COLOR[side] || _CG_SIDE_COLOR.none;
  return c + '1f';  // ~12% alpha (hex)
}

function _cgDragBehavior() {
  function started(event, d) { _cgAutoFit = false; if (!event.active && _cgSim) _cgSim.alphaTarget(0.3).restart(); d.fx = d.x; d.fy = d.y; }
  function dragged(event, d) { d.fx = event.x; d.fy = event.y; }
  function ended(event, d)   { if (!event.active && _cgSim) _cgSim.alphaTarget(0); d.fx = null; d.fy = null; }
  return d3.drag().on('start', started).on('drag', dragged).on('end', ended);
}

function _cgFitNow() {
  if (!_cgNodes.length || !_cgZoom || !_cgSvgSel) return;
  let minX = Infinity, maxX = -Infinity, minY = Infinity, maxY = -Infinity;
  for (const n of _cgNodes) {
    if (n.x == null) return;  // simulation has not produced positions yet
    minX = Math.min(minX, n.x - n.r); maxX = Math.max(maxX, n.x + n.r);
    minY = Math.min(minY, n.y - n.r); maxY = Math.max(maxY, n.y + n.r);
  }
  const w = (maxX - minX) || 1, h = (maxY - minY) || 1;
  const scale = Math.min(_cgW / (w + 70), _cgH / (h + 70), 2);
  const tx = _cgW / 2 - scale * (minX + maxX) / 2;
  const ty = _cgH / 2 - scale * (minY + maxY) / 2;
  _cgSvgSel.transition().duration(300).call(_cgZoom.transform, d3.zoomIdentity.translate(tx, ty).scale(scale));
}

function _cgTruncate(s, max) {
  return s.length > max ? s.slice(0, max - 1) + '…' : s;
}

function _cgFmtBytes(n) {
  if (typeof fmtB === 'function') return fmtB(n);
  return `${n} B`;
}

// ── Hover tooltip ─────────────────────────────────────────────────────────────

function _cgTipShow(event, name) {
  const tip = document.getElementById('cg-tooltip');
  if (!tip) return;
  const e    = (_callGraph && _callGraph[name]) || {};
  const sz   = _cgSizeOf(name);
  const nCallers = (e.called_by || []).length;
  const nCallees = (e.calls || []).length;
  const safe = typeof esc === 'function' ? esc(name) : name;
  const sizeStr = sz ? `<span class="cg-tt-size">${_cgFmtBytes(sz)}</span> · ` : '';
  tip.innerHTML =
    `<div class="cg-tt-name">${safe}</div>` +
    `<div class="cg-tt-meta">${sizeStr}${nCallers} caller${nCallers === 1 ? '' : 's'} · ${nCallees} callee${nCallees === 1 ? '' : 's'}</div>`;
  tip.style.display = 'block';
  _cgTipMove(event);
}

function _cgTipMove(event) {
  const tip = document.getElementById('cg-tooltip');
  if (!tip || tip.style.display === 'none') return;
  // Keep the tooltip on-screen: flip to the left of the cursor near the right edge.
  const pad = 14;
  let x = event.clientX + pad;
  let y = event.clientY - 10;
  const w = tip.offsetWidth, h = tip.offsetHeight;
  if (x + w > window.innerWidth - 8)  x = event.clientX - pad - w;
  if (y + h > window.innerHeight - 8) y = window.innerHeight - 8 - h;
  if (y < 8) y = 8;
  tip.style.left = x + 'px';
  tip.style.top  = y + 'px';
}

function _cgTipHide() {
  const tip = document.getElementById('cg-tooltip');
  if (tip) tip.style.display = 'none';
}

// ── Keyboard shortcuts ────────────────────────────────────────────────────────

if (typeof document !== 'undefined') document.addEventListener('DOMContentLoaded', () => {
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
if (typeof window !== 'undefined') window.addEventListener('resize', () => {
  if (_cgCurrent) requestAnimationFrame(() => _cgDrawGraph(_cgCurrent));
});

// Pure graph-model helpers are exported for unit tests; DOM/d3 rendering is not.
if (typeof module !== 'undefined' && module.exports) {
  module.exports = { cgEgoGraph, cgFullGraph, cgNodeRadius };
}
