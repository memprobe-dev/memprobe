const TYPE_COLOR = {
  text:   '#5b9cf6', rodata: '#3dd68c', data: '#f0a040',
  bss:    '#f06060', heap:   '#a07ae0', stack: '#60a090', other: '#505068',
};
const TC = TYPE_COLOR;
function tc(t) { return TC[t] || TC.other; }
function hexRgba(h, a) {
  if (!h || h[0] !== '#') return `rgba(91,156,246,${a})`;
  const n = parseInt(h.slice(1),16);
  return `rgba(${n>>16&255},${n>>8&255},${n&255},${a})`;
}

// Section name explanations - pattern matching against section name
const SEC_DESCS = {
  '.text':         'Executable machine code',
  '.iram0.text':   'Code placed in IRAM for fast execution (ESP32)',
  '.flash.text':   'Executable code stored in flash (ESP32)',
  '.rodata':       'Read-only constants - strings, lookup tables',
  '.flash.rodata': 'Read-only data in flash (ESP32)',
  '.data':         'Initialized global/static variables (copied from flash to RAM at boot)',
  '.dram0.data':   'Initialized data in DRAM (ESP32)',
  '.bss':          'Uninitialized globals/statics - zeroed at startup, no flash cost',
  '.dram0.bss':    'Uninitialized data in DRAM (ESP32)',
  '.noinit':       'Variables not initialized at startup',
  '.heap':         'Dynamic memory heap region',
  '.stack':        'Call stack. Grows downward at runtime.',
  '.xt.prop':      'Xtensa property table. Toolchain metadata; not loaded into firmware at runtime.',
  '.xt.lit':       'Xtensa literal pool. 32-bit constants for L32R instructions.',
  '.xtensa.info':  'Xtensa processor info. Used by debugger; not loaded at runtime.',
  '.got':          'Global offset table. Used by dynamic linker (uncommon in bare-metal firmware).',
  '.got.plt':      'Procedure linkage table. Dynamic dispatch stubs.',
  '.plt':          'Procedure linkage table entries.',
  '.init_array':   'C++ constructor pointers. Called automatically at startup.',
  '.fini_array':   'C++ destructor pointers. Called at program exit.',
  '.eh_frame':     'C++ exception unwind tables. Build with -fno-exceptions to eliminate this.',
  '.ARM.exidx':    'ARM exception index table. Used for C++ stack unwinding.',
  '.ARM.extab':    'ARM exception handling tables.',
  '.symtab':       'Symbol table. Debug info only; stripped from production firmware.',
  '.strtab':       'Symbol name strings. Debug info only.',
  '.shstrtab':     'Section name strings. Debug info only.',
  '.vectors':      'Interrupt/exception vector table. Must be at a fixed address.',
  '.isr_vector':   'ISR vector table (STM32).',
  '.ccmram':       'Core-coupled memory. Fast RAM available on STM32 devices.',
  '.dtcm':         'Data tightly coupled memory. Fast RAM on ARM Cortex-M7.',
  '.itcm':         'Instruction tightly coupled memory. Fast RAM for hot code paths.',
  '.sdram':        'External SDRAM region.',
};

function secDesc(name) {
  if (SEC_DESCS[name]) return SEC_DESCS[name];
  const n = name.toLowerCase();
  if (n.includes('text'))   return 'Executable machine code.';
  if (n.includes('rodata')) return 'Read-only constant data.';
  if (n.includes('data') && !n.includes('rodata') && !n.includes('bss')) return 'Initialized global/static variables.';
  if (n.includes('bss'))    return 'Uninitialized globals. Zeroed at startup; no flash cost.';
  if (n.includes('heap'))   return 'Dynamic memory heap.';
  if (n.includes('stack'))  return 'Call stack.';
  if (n.includes('vector')) return 'Interrupt vector table.';
  if (n.includes('debug') || n.includes('dwarf')) return 'Debug info. Not loaded into firmware.';
  if (n.includes('eh_frame') || n.includes('exidx')) return 'C++ exception unwind data.';
  return null;
}

function fmtB(n) { if(!n)return'0 B'; if(n>=1048576)return(n/1048576).toFixed(2)+' MB'; if(n>=1024)return(n/1024).toFixed(1)+' KB'; return n+' B'; }
function fmtBH(n) { if(!n)return'0 B'; if(n>=1048576)return(n/1048576).toFixed(1)+' MB'; if(n>=1024)return(n/1024).toFixed(1)+' KB'; return n+' B'; }
function esc(s) { return String(s||'').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;'); }
function fmtSrc(loc) {
  if (!loc) return '<span style="color:var(--text3)">-</span>';
  const ci = loc.lastIndexOf(':');
  if (ci < 0) return `<span class="src-file">${esc(loc)}</span>`;
  const file = loc.slice(0, ci), line = loc.slice(ci + 1);
  const parts = file.split('/');
  const short = parts.length > 3 ? '…/' + parts.slice(-3).join('/') : file;
  const full = `${file}:${line}`;
  return `<span class="src-file" title="${esc(full)}">${esc(short)}</span><span style="color:var(--text3)">:</span><span class="src-line">${esc(line)}</span>`;
}
function getLum(hex) {
  if (!hex||hex[0]!=='#') return 0;
  const toL=c=>{c/=255;return c<=.03928?c/12.92:Math.pow((c+.055)/1.055,2.4);};
  return .2126*toL(parseInt(hex.slice(1,3),16))+.7152*toL(parseInt(hex.slice(3,5),16))+.0722*toL(parseInt(hex.slice(5,7),16));
}
function setBusy(key, on) {
  const btn = document.getElementById('btn-'+key);
  const sp  = document.getElementById('sp-'+key);
  if (!btn) return;
  btn.disabled = on;
  btn.classList.toggle('loading', on);
  if (sp) sp.style.display = on ? 'inline-block' : 'none';
}
function showErr(key, msg) { const el=document.getElementById('err-'+key); if(el){el.textContent=msg;el.classList.add('show');} }
function hideErr(key) { const el=document.getElementById('err-'+key); if(el) el.classList.remove('show'); }
