function renderAddrMap(sections) {
  const card = document.getElementById('card-addrmap');
  const body = document.getElementById('addrmap-body');

  // Flash ruler: only text + rodata - these always run in-place from flash,
  // so their VMA IS their flash address. We deliberately exclude 'data' because
  // on most embedded targets p_paddr == p_vaddr in the ELF (the bootloader
  // handles the copy), so we cannot recover a reliable flash LMA for .data
  // from the ELF alone - showing it at its RAM VMA in the flash ruler would
  // be wrong.
  const FLASH_TYPES = new Set(['text', 'rodata']);
  // RAM ruler: data + bss + heap + stack - all live at their VMA (RAM address).
  const RAM_TYPES   = new Set(['bss', 'data', 'heap', 'stack']);

  const flashSecs = sections.filter(s => FLASH_TYPES.has(s.type) && s.vma > 0 && s.size > 0);
  const ramSecs   = sections.filter(s => RAM_TYPES.has(s.type)   && s.vma > 0 && s.size > 0);

  if (!flashSecs.length && !ramSecs.length) {
    card.style.display = 'none';
    return;
  }
  card.style.display = '';

  const tooltip = document.getElementById('addr-tooltip');

  function buildRuler(label, secsRaw, addrFn) {
    const secs = secsRaw.slice().sort((a, b) => addrFn(a) - addrFn(b));
    const minAddr = addrFn(secs[0]);
    const maxAddr = Math.max(...secs.map(s => addrFn(s) + s.size));
    const span = maxAddr - minAddr || 1;

    const gaps = [];
    for (let i = 0; i < secs.length - 1; i++) {
      const end = addrFn(secs[i]) + secs[i].size;
      const next = addrFn(secs[i + 1]);
      if (next > end + 3) gaps.push({ start: end, size: next - end });
    }

    const TICK_COUNT = 4;
    const tickStep = Math.pow(2, Math.ceil(Math.log2(span / TICK_COUNT)));
    const ticks = [];
    for (let a = Math.floor(minAddr / tickStep) * tickStep; a <= maxAddr; a += tickStep) {
      ticks.push(a);
    }

    const segments = secs.map(s => {
      const left  = ((addrFn(s) - minAddr) / span * 100).toFixed(3);
      const width = Math.max((s.size / span * 100), 0.3).toFixed(3);
      return `<div class="addr-seg" style="left:${left}%;width:${width}%;background:${esc(s.color)}"
        data-name="${esc(s.name)}" data-addr="0x${addrFn(s).toString(16)}"
        data-size="${esc(fmtB(s.size))}"
        onmouseenter="addrTip(event,this)" onmouseleave="addrTipHide()"></div>`;
    }).join('');

    const gapHtml = gaps.map(g => {
      const left  = ((g.start - minAddr) / span * 100).toFixed(3);
      const width = Math.max((g.size / span * 100), 0.2).toFixed(3);
      return `<div class="addr-gap" style="left:${left}%;width:${width}%"
        data-name="gap" data-addr="0x${g.start.toString(16)}" data-size="${esc(fmtB(g.size))}"
        onmouseenter="addrTip(event,this)" onmouseleave="addrTipHide()"></div>`;
    }).join('');

    const tickHtml = ticks.map(t => {
      const left = ((t - minAddr) / span * 100).toFixed(1);
      const hex = '0x' + t.toString(16).toUpperCase();
      return `<div style="position:absolute;left:${left}%;transform:translateX(-50%);font-size:9px;color:var(--text3);font-family:var(--mono);white-space:nowrap">${hex}</div>`;
    }).join('');

    return `<div class="addr-ruler-row">
      <span class="addr-ruler-lbl">${esc(label)}</span>
      <div style="flex:1;min-width:300px">
        <div class="addr-ruler-bar">${segments}${gapHtml}</div>
        <div style="position:relative;height:14px;margin-top:2px">${tickHtml}</div>
      </div>
    </div>`;
  }

  let html = '<div class="addr-ruler-wrap">';
  if (flashSecs.length) html += buildRuler('FLASH', flashSecs, s => s.vma);
  if (ramSecs.length)   html += buildRuler('RAM',   ramSecs,   s => s.vma);
  html += '</div>';
  html += `<p style="font-size:10px;color:var(--text3);margin:8px 0 0">Hover a segment for details. Hatched areas are gaps in the address space.</p>`;

  body.innerHTML = html;
}

function addrTip(e, el) {
  const t = document.getElementById('addr-tooltip');
  const isGap = el.dataset.name === 'gap';
  t.innerHTML = isGap
    ? `<span style="color:var(--text3)">Gap</span> &nbsp; <span style="font-family:var(--mono)">${esc(el.dataset.addr)}</span> &nbsp; <strong>${esc(el.dataset.size)}</strong>`
    : `<span style="color:var(--text)">${esc(el.dataset.name)}</span> &nbsp; <span style="font-family:var(--mono);color:var(--text3)">${esc(el.dataset.addr)}</span> &nbsp; <strong>${esc(el.dataset.size)}</strong>`;
  t.style.display = 'block';
  document.addEventListener('mousemove', _addrTipMove);
}
function _addrTipMove(e) {
  const t = document.getElementById('addr-tooltip');
  t.style.left = (e.clientX + 14) + 'px';
  t.style.top  = (e.clientY - 28) + 'px';
}
function addrTipHide() {
  document.getElementById('addr-tooltip').style.display = 'none';
  document.removeEventListener('mousemove', _addrTipMove);
}
