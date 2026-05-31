// Plain node test (no framework) for clusterSections in address-map.js.
// Run: node website/static/scripts/tests/address-map.test.js
const assert = require('assert');
const { clusterSections, isFlashSection } = require('../address-map.js');

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

// --- isFlashSection: which sections land on the flash ruler --------------
const fsec = (o) => Object.assign(
  { name: 'x', type: 'text', size: 100, vma: 0x8000000, lma: 0x8000000, occupies_file: true },
  o);

test('text and rodata ship to flash', () => {
  assert.ok(isFlashSection(fsec({ type: 'text' })));
  assert.ok(isFlashSection(fsec({ type: 'rodata' })));
});

test('NOBITS reservation (occupies_file false) is not flash', () => {
  // .flash_rodata_dummy: rodata-typed but stores no image bytes.
  assert.ok(!isFlashSection(fsec({ type: 'rodata', occupies_file: false })));
});

test('bss is never on the flash ruler', () => {
  assert.ok(!isFlashSection(fsec({ type: 'bss', occupies_file: false })));
});

test('data with a distinct LMA appears on the flash ruler at its LMA', () => {
  const d = fsec({ type: 'data', vma: 0x20000000, lma: 0x8004000 });
  assert.ok(isFlashSection(d));
});

test('data without a separate LMA (lma == vma) stays off the flash ruler', () => {
  // ESP32 / desktop: bootloader handles the copy, ELF has no distinct LMA.
  const d = fsec({ type: 'data', vma: 0x20000000, lma: 0x20000000 });
  assert.ok(!isFlashSection(d));
});

test('zero-size or zero-lma sections are excluded', () => {
  assert.ok(!isFlashSection(fsec({ size: 0 })));
  assert.ok(!isFlashSection(fsec({ lma: 0 })));
});

console.log(`\n${passed} passed`);
