// Plain node tests (no framework) for the pure graph-model helpers in
// callgraph.js. Run: node website/static/scripts/tests/callgraph.test.js
const assert = require('assert');
const { cgEgoGraph, cgFullGraph, cgNodeRadius } = require('../callgraph.js');

let passed = 0;
function test(name, fn) {
  fn();
  passed++;
  console.log('  ok  ' + name);
}

const sideOf = (model, name) => (model.nodes.find(n => n.name === name) || {}).side;
const names = (model) => model.nodes.map(n => n.name).sort();
const hasLink = (model, s, t) => model.links.some(l => l.source === s && l.target === t);

// A small graph:  main -> a, b ;  a -> c ;  b -> c
const G = {
  main: { calls: ['a', 'b'], called_by: [] },
  a:    { calls: ['c'],      called_by: ['main'] },
  b:    { calls: ['c'],      called_by: ['main'] },
  c:    { calls: [],         called_by: ['a', 'b'] },
};

// --- cgNodeRadius --------------------------------------------------------
test('node radius: zero or unknown size is the minimum', () => {
  assert.strictEqual(cgNodeRadius(0, 1000), 6);
  assert.strictEqual(cgNodeRadius(500, 0), 6);
  assert.strictEqual(cgNodeRadius(undefined, 1000), 6);
});

test('node radius: the largest function gets the maximum', () => {
  assert.strictEqual(cgNodeRadius(1000, 1000), 26);
});

test('node radius: scales by sqrt of the size fraction', () => {
  // quarter of max area -> half-way up the radius range
  assert.strictEqual(cgNodeRadius(250, 1000), 6 + (26 - 6) * 0.5);
});

// --- cgEgoGraph ----------------------------------------------------------
test('ego graph: missing focus yields an empty model', () => {
  assert.deepStrictEqual(cgEgoGraph(G, 'nope', 1), { nodes: [], links: [], truncated: false });
});

test('ego graph depth 1: focus plus immediate callers and callees', () => {
  const m = cgEgoGraph(G, 'a', 1);
  assert.deepStrictEqual(names(m), ['a', 'c', 'main']);
  assert.strictEqual(sideOf(m, 'a'), 'focus');
  assert.strictEqual(sideOf(m, 'c'), 'down');     // a calls c
  assert.strictEqual(sideOf(m, 'main'), 'up');    // main calls a
  assert.ok(hasLink(m, 'a', 'c'));
  assert.ok(hasLink(m, 'main', 'a'));
  assert.ok(!hasLink(m, 'main', 'b'), 'b is not in the visible set');
  assert.strictEqual(m.truncated, false);
});

test('ego graph depth 1 from root: callees only, no callers', () => {
  const m = cgEgoGraph(G, 'main', 1);
  assert.deepStrictEqual(names(m), ['a', 'b', 'main']);
  assert.strictEqual(sideOf(m, 'a'), 'down');
  assert.strictEqual(sideOf(m, 'b'), 'down');
});

test('ego graph depth 2: reaches the second hop', () => {
  const m = cgEgoGraph(G, 'main', 2);
  assert.deepStrictEqual(names(m), ['a', 'b', 'c', 'main']);
  assert.strictEqual(sideOf(m, 'c'), 'down');
  assert.ok(hasLink(m, 'a', 'c'));
  assert.ok(hasLink(m, 'b', 'c'));
});

test('ego graph: a node on both a caller and a callee path is "both"', () => {
  // Direct recursion: f calls x and x calls f.
  const R = {
    f: { calls: ['x'], called_by: ['x'] },
    x: { calls: ['f'], called_by: ['f'] },
  };
  const m = cgEgoGraph(R, 'f', 1);
  assert.strictEqual(sideOf(m, 'x'), 'both');
});

test('ego graph: honors the node cap and reports truncation', () => {
  const star = { f: { calls: ['n1', 'n2', 'n3', 'n4', 'n5'], called_by: [] } };
  for (let i = 1; i <= 5; i++) star['n' + i] = { calls: [], called_by: ['f'] };
  const m = cgEgoGraph(star, 'f', 1, 3);
  assert.strictEqual(m.nodes.length, 3);   // focus + 2 before the cap
  assert.strictEqual(m.truncated, true);
});

// --- cgFullGraph ---------------------------------------------------------
test('full graph: every function and its intra-set edges', () => {
  const m = cgFullGraph(G);
  assert.deepStrictEqual(names(m), ['a', 'b', 'c', 'main']);
  assert.ok(hasLink(m, 'main', 'a'));
  assert.ok(hasLink(m, 'a', 'c'));
  assert.strictEqual(m.truncated, false);
  m.nodes.forEach(n => assert.strictEqual(n.side, 'none'));
});

test('full graph: caps the node count and reports truncation', () => {
  const m = cgFullGraph(G, 2);
  assert.strictEqual(m.nodes.length, 2);
  assert.strictEqual(m.truncated, true);
});

console.log(`\n${passed} passed`);
