// ── Export tab ─────────────────────────────────────────────────────────────────

function _expSelectedParts() {
  return [...document.querySelectorAll('.exp-part:checked')].map(c => c.value);
}

function _expSelectedFormat() {
  return document.querySelector('input[name="exp-fmt"]:checked')?.value || 'json';
}

function exportSelectAll(on) {
  document.querySelectorAll('.exp-part').forEach(c => { c.checked = on; });
}

function _expBuildPayload(parts) {
  if (!_lastAnalysis) return null;
  const out = { filename: _lastAnalysis.filename };
  // Always include the basic file/size totals as a "meta" block when anything is selected
  out.totals = {
    total_flash: _lastAnalysis.total_flash,
    total_ram:   _lastAnalysis.total_ram,
    section_count: _lastAnalysis.section_count,
    symbol_count:  _lastAnalysis.symbol_count,
  };
  if (parts.includes('binary_info')) out.binary_info = _lastAnalysis.binary_info || {};
  if (parts.includes('regions'))     out.regions     = _lastAnalysis.regions     || [];
  if (parts.includes('sections')) {
    out.sections = (_lastAnalysis.sections || []).map(({ color, ...rest }) => rest);
  }
  if (parts.includes('symbols'))   out.symbols   = _lastAnalysis.symbols   || [];
  if (parts.includes('warnings'))  out.warnings  = _lastAnalysis.warnings  || [];
  if (parts.includes('insights'))  out.insights  = _lastAnalysis.insights  || {};
  if (parts.includes('libraries')) out.libraries = _lastAnalysis.libraries || [];
  if (parts.includes('treemap'))   out.treemap   = _lastAnalysis.treemap   || {};
  return out;
}

function _expBasename() {
  return (_lastAnalysis?.filename || 'analysis').replace(/\.[^.]+$/, '');
}

function _expDownload(filename, content, mime) {
  const a = document.createElement('a');
  a.href = URL.createObjectURL(new Blob([content], { type: mime }));
  a.download = filename;
  a.click();
  URL.revokeObjectURL(a.href);
}

function _expShowErr(msg) {
  const el = document.getElementById('export-err');
  if (!el) return;
  el.textContent = msg;
  el.classList.add('show');
  setTimeout(() => el.classList.remove('show'), 3500);
}

// JSON
function _expToJSON(data) { return JSON.stringify(data, null, 2); }

// TOML (lightweight emitter; arrays of objects become [[tables]])
function _expToTOML(data) {
  const lines = [];
  const isPlainObj = v => v && typeof v === 'object' && !Array.isArray(v);
  const tomlVal = v => {
    if (v === null || v === undefined) return '""';
    if (typeof v === 'string')  return JSON.stringify(v);
    if (typeof v === 'number' || typeof v === 'boolean') return String(v);
    if (Array.isArray(v)) {
      // Array of primitives only: arrays of objects are emitted as [[table]] below
      return '[' + v.map(x => tomlVal(x)).join(', ') + ']';
    }
    return JSON.stringify(String(v));
  };
  const emitTable = (path, obj) => {
    const scalars = [];
    const nestedTables = [];
    const arrayTables = [];
    for (const [k, v] of Object.entries(obj)) {
      if (Array.isArray(v) && v.length && v.every(isPlainObj)) {
        arrayTables.push([k, v]);
      } else if (isPlainObj(v)) {
        nestedTables.push([k, v]);
      } else {
        scalars.push([k, v]);
      }
    }
    if (path.length) lines.push(`[${path.join('.')}]`);
    for (const [k, v] of scalars) lines.push(`${k} = ${tomlVal(v)}`);
    if (scalars.length) lines.push('');
    for (const [k, v] of nestedTables) emitTable([...path, k], v);
    for (const [k, arr] of arrayTables) {
      for (const item of arr) {
        lines.push(`[[${[...path, k].join('.')}]]`);
        for (const [ik, iv] of Object.entries(item)) {
          if (isPlainObj(iv) || (Array.isArray(iv) && iv.some(isPlainObj))) {
            // skip nested-of-nested for simplicity
            lines.push(`# ${ik} omitted (nested structure)`);
          } else {
            lines.push(`${ik} = ${tomlVal(iv)}`);
          }
        }
        lines.push('');
      }
    }
  };
  emitTable([], data);
  return lines.join('\n');
}

// XML
function _expEscXML(s) {
  return String(s ?? '')
    .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;').replace(/'/g, '&apos;');
}
function _expToXML(data, rootName='analysis') {
  const lines = ['<?xml version="1.0" encoding="UTF-8"?>'];
  const safeTag = k => /^[A-Za-z_][\w-]*$/.test(k) ? k : 'item';
  const emit = (name, val, indent) => {
    const pad = '  '.repeat(indent);
    if (val === null || val === undefined) {
      lines.push(`${pad}<${name}/>`);
    } else if (Array.isArray(val)) {
      lines.push(`${pad}<${name}>`);
      for (const item of val) emit('item', item, indent + 1);
      lines.push(`${pad}</${name}>`);
    } else if (typeof val === 'object') {
      lines.push(`${pad}<${name}>`);
      for (const [k, v] of Object.entries(val)) emit(safeTag(k), v, indent + 1);
      lines.push(`${pad}</${name}>`);
    } else {
      lines.push(`${pad}<${name}>${_expEscXML(val)}</${name}>`);
    }
  };
  emit(rootName, data, 0);
  return lines.join('\n');
}

// CSV: produces one CSV per "table-like" array; bundled into a .zip if >1
function _expArrayToCSV(arr) {
  if (!arr.length) return '';
  const cols = [...new Set(arr.flatMap(o => Object.keys(o)))];
  const esc = v => {
    if (v === null || v === undefined) return '';
    const s = typeof v === 'object' ? JSON.stringify(v) : String(v);
    return /[",\n\r]/.test(s) ? `"${s.replace(/"/g, '""')}"` : s;
  };
  return [cols.join(','), ...arr.map(o => cols.map(c => esc(o[c])).join(','))].join('\n');
}

function _expCollectCSVFiles(data) {
  // Returns [{name, content}] for each array-of-objects in data
  const files = [];
  const tryAdd = (key, arr) => {
    if (Array.isArray(arr) && arr.length && typeof arr[0] === 'object') {
      files.push({ name: `${key}.csv`, content: _expArrayToCSV(arr) });
    }
  };
  tryAdd('sections', data.sections);
  tryAdd('symbols', data.symbols);
  tryAdd('regions', data.regions);
  tryAdd('warnings', data.warnings);
  tryAdd('libraries', data.libraries);
  // Scalar/object-only data goes into meta.csv as key,value rows
  const scalar = {};
  for (const [k, v] of Object.entries(data)) {
    if (Array.isArray(v)) continue;
    if (v && typeof v === 'object') {
      for (const [k2, v2] of Object.entries(v)) {
        if (v2 !== null && typeof v2 !== 'object') scalar[`${k}.${k2}`] = v2;
      }
    } else {
      scalar[k] = v;
    }
  }
  if (Object.keys(scalar).length) {
    const rows = ['key,value', ...Object.entries(scalar).map(([k, v]) => {
      const sv = String(v ?? '').replace(/"/g, '""');
      return `${k},"${sv}"`;
    })];
    files.push({ name: 'meta.csv', content: rows.join('\n') });
  }
  return files;
}

// Minimal zip writer (store, no compression): keeps us dependency-free
function _expMakeZip(files) {
  const enc = new TextEncoder();
  const chunks = [];
  const central = [];
  let offset = 0;
  const crcTable = (() => {
    const t = new Uint32Array(256);
    for (let i = 0; i < 256; i++) {
      let c = i;
      for (let k = 0; k < 8; k++) c = (c & 1) ? (0xEDB88320 ^ (c >>> 1)) : (c >>> 1);
      t[i] = c >>> 0;
    }
    return t;
  })();
  const crc32 = bytes => {
    let c = 0xFFFFFFFF;
    for (let i = 0; i < bytes.length; i++) c = crcTable[(c ^ bytes[i]) & 0xFF] ^ (c >>> 8);
    return (c ^ 0xFFFFFFFF) >>> 0;
  };
  const u16 = n => new Uint8Array([n & 0xFF, (n >>> 8) & 0xFF]);
  const u32 = n => new Uint8Array([n & 0xFF, (n >>> 8) & 0xFF, (n >>> 16) & 0xFF, (n >>> 24) & 0xFF]);
  const concat = arrs => {
    const total = arrs.reduce((s, a) => s + a.length, 0);
    const out = new Uint8Array(total);
    let p = 0;
    for (const a of arrs) { out.set(a, p); p += a.length; }
    return out;
  };

  for (const f of files) {
    const nameBytes = enc.encode(f.name);
    const dataBytes = enc.encode(f.content);
    const crc = crc32(dataBytes);
    const local = concat([
      u32(0x04034b50), u16(20), u16(0), u16(0), u16(0), u16(0),
      u32(crc), u32(dataBytes.length), u32(dataBytes.length),
      u16(nameBytes.length), u16(0), nameBytes, dataBytes,
    ]);
    chunks.push(local);
    const cdh = concat([
      u32(0x02014b50), u16(20), u16(20), u16(0), u16(0), u16(0), u16(0),
      u32(crc), u32(dataBytes.length), u32(dataBytes.length),
      u16(nameBytes.length), u16(0), u16(0), u16(0), u16(0), u32(0),
      u32(offset), nameBytes,
    ]);
    central.push(cdh);
    offset += local.length;
  }
  const centralBytes = concat(central);
  const eocd = concat([
    u32(0x06054b50), u16(0), u16(0), u16(files.length), u16(files.length),
    u32(centralBytes.length), u32(offset), u16(0),
  ]);
  return concat([...chunks, centralBytes, eocd]);
}

function downloadExport() {
  if (!_lastAnalysis) { _expShowErr('No analysis to export.'); return; }
  const parts = _expSelectedParts();
  if (!parts.length) { _expShowErr('Select at least one section to include.'); return; }
  const fmt = _expSelectedFormat();
  if (!_IS_PRO && (fmt === 'toml' || fmt === 'csv' || fmt === 'xml')) {
    _expShowErr('TOML, CSV, and XML export are Pro features.');
    return;
  }
  const data = _expBuildPayload(parts);
  const base = _expBasename();

  if (fmt === 'json') {
    _expDownload(`${base}_analysis.json`, _expToJSON(data), 'application/json');
  } else if (fmt === 'toml') {
    _expDownload(`${base}_analysis.toml`, _expToTOML(data), 'application/toml');
  } else if (fmt === 'xml') {
    _expDownload(`${base}_analysis.xml`, _expToXML(data), 'application/xml');
  } else if (fmt === 'csv') {
    const files = _expCollectCSVFiles(data);
    if (files.length === 0) {
      _expShowErr('Selected sections have no tabular data for CSV.');
    } else if (files.length === 1) {
      _expDownload(`${base}_${files[0].name}`, files[0].content, 'text/csv');
    } else {
      const zip = _expMakeZip(files);
      _expDownload(`${base}_analysis.zip`, zip, 'application/zip');
    }
  }
}

// Show/hide the CSV note depending on selected format
document.addEventListener('change', e => {
  if (e.target && e.target.name === 'exp-fmt') {
    const note = document.getElementById('export-csv-note');
    if (note) note.style.display = (e.target.value === 'csv') ? '' : 'none';
  }
});

function pushBuildHash(id) {
  history.replaceState(null, '', id ? `#build/${id}` : '#');
}

async function initFromHash() {
  const m = location.hash.match(/^#build\/(\d+)$/);
  if (m) await loadHistBuild(parseInt(m[1]));
}

// ── Share ──────────────────────────────────────────────────────────────────────

async function shareAnalysis() {
  if (!_lastAnalysis) return;
  const btn = document.getElementById('share-btn');
  btn.disabled = true;
  const orig = btn.innerHTML;
  btn.innerHTML = 'Creating link...';
  try {
    const res = await fetch('/api/share', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ analysis: _lastAnalysis, filename: _lastAnalysis.filename || 'firmware' }),
    });
    const data = await res.json();
    if (!res.ok) throw new Error(data.error || res.statusText);
    document.getElementById('share-url-input').value = `${location.origin}/s/${data.id}`;
    document.getElementById('share-modal').style.display = 'flex';
  } catch(e) {
    alert('Could not create share link: ' + e.message);
  } finally {
    btn.disabled = false;
    btn.innerHTML = orig;
  }
}

function closeShareModal() {
  document.getElementById('share-modal').style.display = 'none';
}

function copyShareUrl() {
  const inp = document.getElementById('share-url-input');
  inp.select();
  navigator.clipboard?.writeText(inp.value).then(() => {
    const btn = document.getElementById('share-copy-btn');
    const orig = btn.textContent;
    btn.textContent = 'Copied';
    setTimeout(() => { btn.textContent = orig; }, 1600);
  });
}

// ── Library card ───────────────────────────────────────────────────────────────

function renderLibraries(libs) {
  const card = document.getElementById('card-libraries');
  if (!libs || !libs.length) { card.style.display = 'none'; return; }

  const maxFlash = libs[0].flash_bytes || 1;
  document.getElementById('lib-tbody').innerHTML = libs.map(lib => {
    const barW = Math.round(lib.flash_bytes / maxFlash * 80);
    const nameCell = lib.url
      ? `<a href="${esc(lib.url)}" target="_blank" rel="noopener" style="color:var(--accent);text-decoration:none">${esc(lib.name)}</a>`
      : esc(lib.name);
    return `<tr style="border-bottom:1px solid var(--border2)">
      <td style="padding:7px 10px">${nameCell}</td>
      <td style="padding:7px 10px;color:var(--text3)">${esc(lib.category)}</td>
      <td style="padding:7px 10px">
        <div style="display:flex;align-items:center;gap:7px">
          <div style="width:80px;height:6px;background:var(--bg3);border-radius:3px;overflow:hidden">
            <div style="width:${barW}px;height:100%;background:var(--accent);border-radius:3px"></div>
          </div>
          <span style="color:var(--text2)">${esc(lib.flash_human)}</span>
        </div>
      </td>
      <td style="padding:7px 10px;text-align:right;color:var(--text3)">${lib.symbol_count.toLocaleString()}</td>
    </tr>`;
  }).join('');
  card.style.display = '';
}
