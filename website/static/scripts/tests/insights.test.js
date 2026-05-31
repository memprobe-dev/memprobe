// Plain node test (no framework) for computeSavingsRows in insights.js.
// Run: node website/static/scripts/tests/insights.test.js

// computeSavingsRows calls the global fmtB (defined in utils.js in the browser).
// Provide a minimal stand-in before requiring the module under test.
global.fmtB = (n) => (n ? `${n} B` : '0 B');

const assert = require('assert');
const { computeSavingsRows } = require('../insights.js');

let passed = 0;
function test(name, fn) {
  fn();
  passed++;
  console.log('  ok  ' + name);
}

const rowFor = (rows, substr) => rows.find(r => r.desc.includes(substr));

test('empty input yields no rows', () => {
  assert.deepStrictEqual(computeSavingsRows({}, [], {}), []);
});

// --- Build stamps: require BOTH a date and a time ------------------------
test('build stamp: date only does not warn', () => {
  const bi = { build_stamps: [{ type: 'date', string: 'May 21 2026' }] };
  const rows = computeSavingsRows({}, [], bi);
  assert.strictEqual(rowFor(rows, 'Non-reproducible'), undefined);
});

test('build stamp: time only does not warn', () => {
  const bi = { build_stamps: [{ type: 'time', string: '15:30:00' }] };
  const rows = computeSavingsRows({}, [], bi);
  assert.strictEqual(rowFor(rows, 'Non-reproducible'), undefined);
});

test('build stamp: date AND time warns once', () => {
  const bi = { build_stamps: [
    { type: 'date', string: 'May 21 2026' },
    { type: 'time', string: '15:30:00' },
  ] };
  const rows = computeSavingsRows({}, [], bi);
  const row = rowFor(rows, 'Non-reproducible');
  assert.ok(row, 'expected a non-reproducible-build warning');
  assert.strictEqual(row.tag, 'warn');
  assert.ok(row.desc.includes('May 21 2026'));
  assert.ok(row.desc.includes('15:30:00'));
});

// --- Duplicate symbols: softened, conditional wording -------------------
test('duplicate symbols: wording is conditional on identical code', () => {
  const ins = { duplicate_symbols: [
    { name: 'foo', total_size: 200, size_each: 100 },
  ] };
  const rows = computeSavingsRows(ins, [], {});
  const row = rowFor(rows, 'multiple addresses');
  assert.ok(row, 'expected a duplicate-symbol row');
  assert.strictEqual(row.tag, 'info');
  assert.strictEqual(row.amt, 100); // total_size - size_each
  assert.ok(row.desc.includes('If their code is identical'),
    'wording must not claim unconditional savings');
  assert.ok(!row.desc.includes('in multiple translation units. Link'),
    'old absolute wording must be gone');
});

// --- Padding stays informational (no recoverable amount) ----------------
test('padding waste has no recoverable amount', () => {
  const ins = { padding_waste: { total_bytes: 329 } };
  const rows = computeSavingsRows(ins, [], {});
  const row = rowFor(rows, 'alignment padding');
  assert.ok(row);
  assert.strictEqual(row.amt, null);
});

// --- Pass-through warnings still produce rows ---------------------------
test('cxa_throw warning produces an exceptions row', () => {
  const rows = computeSavingsRows({}, [{ symbol: '__cxa_throw' }], {});
  assert.ok(rowFor(rows, 'C++ exceptions linked'));
});

console.log(`\n${passed} passed`);
