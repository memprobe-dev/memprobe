// Group sections into clusters of nearby addresses. A cluster break is inserted
// when the gap between two consecutive sections is larger than the total size of
// all content in the ruler. This keeps split address spaces (e.g. ESP32 DROM at
// 0x3c000000 and IROM at 0x42000000, ~96 MB apart) from collapsing every segment
// into an invisible sliver next to one dominant hatched gap. Each returned cluster
// is { secs, minAddr, maxAddr } with secs sorted by address.
function clusterSections(secsRaw, addrFn) {
  const sorted = secsRaw.slice().sort((a, b) => addrFn(a) - addrFn(b));
  if (!sorted.length) return [];

  const totalContent = sorted.reduce((sum, s) => sum + s.size, 0);
  const breakThreshold = Math.max(totalContent, 1);

  const clusters = [];
  let current = null;
  for (const s of sorted) {
    const start = addrFn(s);
    const end   = start + s.size;
    if (current === null) {
      current = { secs: [s], minAddr: start, maxAddr: end };
      continue;
    }
    if (start - current.maxAddr > breakThreshold) {
      clusters.push(current);
      current = { secs: [s], minAddr: start, maxAddr: end };
    } else {
      current.secs.push(s);
      current.maxAddr = Math.max(current.maxAddr, end);
    }
  }
  if (current) clusters.push(current);
  return clusters;
}

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

  // Render one cluster's segments + intra-cluster gaps + tick labels, all scaled
  // to that cluster's own local span so segments stay visible.
  function clusterColumn(cluster, addrFn, tickCount) {
    const { secs, minAddr, maxAddr } = cluster;
    const span = (maxAddr - minAddr) || 1;

    const segments = secs.map(s => {
      const left  = ((addrFn(s) - minAddr) / span * 100).toFixed(3);
      const width = Math.max((s.size / span * 100), 0.8).toFixed(3);
      return `<div class="addr-seg" style="left:${left}%;width:${width}%;background:${esc(s.color)}"
        data-name="${esc(s.name)}" data-addr="0x${addrFn(s).toString(16)}"
        data-size="${esc(fmtB(s.size))}"
        onmouseenter="addrTip(event,this)" onmouseleave="addrTipHide()"></div>`;
    }).join('');

    let gapHtml = '';
    for (let i = 0; i < secs.length - 1; i++) {
      const end  = addrFn(secs[i]) + secs[i].size;
      const next = addrFn(secs[i + 1]);
      if (next <= end + 3) continue;
      const left  = ((end - minAddr) / span * 100).toFixed(3);
      const width = Math.max(((next - end) / span * 100), 0.2).toFixed(3);
      gapHtml += `<div class="addr-gap" style="left:${left}%;width:${width}%"
        data-name="gap" data-addr="0x${end.toString(16)}" data-size="${esc(fmtB(next - end))}"
        onmouseenter="addrTip(event,this)" onmouseleave="addrTipHide()"></div>`;
    }

    const tickStep = Math.pow(2, Math.ceil(Math.log2(span / tickCount)));
    const tickSet = new Set([minAddr, maxAddr]);
    for (let a = Math.ceil(minAddr / tickStep) * tickStep; a < maxAddr; a += tickStep) {
      tickSet.add(a);
    }
    const ticks = Array.from(tickSet).sort((a, b) => a - b);
    const tickHtml = ticks.map(t => {
      const left = ((t - minAddr) / span * 100).toFixed(1);
      const clamp = t === minAddr ? 'translateX(0)' : t === maxAddr ? 'translateX(-100%)' : 'translateX(-50%)';
      const hex = '0x' + t.toString(16).toUpperCase();
      return `<div style="position:absolute;left:${left}%;transform:${clamp};font-size:9px;color:var(--text3);font-family:var(--mono);white-space:nowrap">${hex}</div>`;
    }).join('');

    return `<div class="addr-cluster" style="flex:${Math.max(span, 1)} 1 0;min-width:60px">
      <div class="addr-ruler-bar" style="position:relative">${segments}${gapHtml}</div>
      <div style="position:relative;height:14px;margin-top:2px">${tickHtml}</div>
    </div>`;
  }

  function buildRuler(label, secsRaw, addrFn) {
    const clusters = clusterSections(secsRaw, addrFn);
    const tickCount = clusters.length > 1 ? 2 : 4;

    let inner = '';
    clusters.forEach((cluster, i) => {
      if (i > 0) {
        const gap = cluster.minAddr - clusters[i - 1].maxAddr;
        inner += `<div class="addr-cluster-break" title="gap ${esc(fmtB(gap))}"
          data-name="gap" data-addr="0x${clusters[i - 1].maxAddr.toString(16)}" data-size="${esc(fmtB(gap))}"
          onmouseenter="addrTip(event,this)" onmouseleave="addrTipHide()"></div>`;
      }
      inner += clusterColumn(cluster, addrFn, tickCount);
    });

    return `<div class="addr-ruler-row">
      <span class="addr-ruler-lbl">${esc(label)}</span>
      <div style="flex:1;min-width:300px;display:flex;align-items:flex-start;gap:0">${inner}</div>
    </div>`;
  }

  let html = '<div class="addr-ruler-wrap">';
  if (flashSecs.length) html += buildRuler('FLASH', flashSecs, s => s.vma);
  if (ramSecs.length)   html += buildRuler('RAM',   ramSecs,   s => s.vma);
  html += '</div>';
  html += `<p style="font-size:10px;color:var(--text3);margin:8px 0 0">Hover a segment for details. Hatched areas are gaps; a slashed break marks a large jump in the address space.</p>`;

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

if (typeof module !== 'undefined' && module.exports) {
  module.exports = { clusterSections };
}
