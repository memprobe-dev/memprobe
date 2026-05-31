// Plain node test (no framework) for clusterSections in address-map.js.
// Run: node website/static/scripts/tests/address-map.test.js
const assert = require('assert');
const { clusterSections } = require('../address-map.js');

const addrFn = s => s.vma;
let passed = 0;
function test(name, fn) {
  fn();
  passed++;
  console.log('  ok  ' + name);
}

// Helper: build a section.
const sec = (name, vma, size) => ({ name, vma, size, type: 't', color: '#000' });

test('empty input yields no clusters', () => {
  assert.deepStrictEqual(clusterSections([], addrFn), []);
});

test('single section is one cluster', () => {
  const clusters = clusterSections([sec('a', 0x1000, 256)], addrFn);
  assert.strictEqual(clusters.length, 1);
  assert.strictEqual(clusters[0].minAddr, 0x1000);
  assert.strictEqual(clusters[0].maxAddr, 0x1100);
});

test('contiguous sections stay in one cluster', () => {
  // STM32-style: text then rodata directly adjacent in flash.
  const clusters = clusterSections([
    sec('.text', 0x08000000, 0x4000),
    sec('.rodata', 0x08004000, 0x1000),
  ], addrFn);
  assert.strictEqual(clusters.length, 1);
  assert.strictEqual(clusters[0].secs.length, 2);
});

test('ESP32 split flash splits into two clusters', () => {
  // rodata in DROM (~0x3c00) and text in IROM (~0x4200), ~96 MB apart,
  // with only ~120 KB total content -> must break.
  const clusters = clusterSections([
    sec('.flash.rodata', 0x3c000020, 24576),
    sec('.flash.text',   0x42000020, 81920),
  ], addrFn);
  assert.strictEqual(clusters.length, 2);
  assert.strictEqual(clusters[0].secs[0].name, '.flash.rodata');
  assert.strictEqual(clusters[1].secs[0].name, '.flash.text');
});

test('small gap (< total content) stays in one cluster', () => {
  // gap of 0x100 between two 0x1000 sections: gap < total content -> no break.
  const clusters = clusterSections([
    sec('a', 0x1000, 0x1000),
    sec('b', 0x2100, 0x1000),
  ], addrFn);
  assert.strictEqual(clusters.length, 1);
});

test('unsorted input is sorted by address', () => {
  const clusters = clusterSections([
    sec('hi', 0x42000020, 81920),
    sec('lo', 0x3c000020, 24576),
  ], addrFn);
  assert.strictEqual(clusters[0].secs[0].name, 'lo');
  assert.strictEqual(clusters[1].secs[0].name, 'hi');
});

test('three far-apart regions yield three clusters', () => {
  const clusters = clusterSections([
    sec('a', 0x10000000, 0x100),
    sec('b', 0x20000000, 0x100),
    sec('c', 0x30000000, 0x100),
  ], addrFn);
  assert.strictEqual(clusters.length, 3);
});

test('cluster bounds cover all member sections', () => {
  const clusters = clusterSections([
    sec('a', 0x1000, 0x800),
    sec('b', 0x1800, 0x800),
  ], addrFn);
  assert.strictEqual(clusters[0].minAddr, 0x1000);
  assert.strictEqual(clusters[0].maxAddr, 0x2000);
});

console.log(`\n${passed} passed`);
