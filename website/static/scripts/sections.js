let allSections = [], showAllSec = false;

function renderSections(secs) {
  allSections = secs;
  showAllSec = false;
  drawSections();
}

function drawSections() {
  const maxSz = Math.max(...allSections.map(s=>s.size)) || 1;
  const total = allSections.reduce((a,s)=>a+s.size,0) || 1;
  const show = showAllSec ? allSections : allSections.slice(0, 15);
  document.getElementById('sec-rows').innerHTML = show.map(s => {
    const pct = (s.size/total*100).toFixed(1);
    const bw = (s.size/maxSz*100).toFixed(1);
    const desc = secDesc(s.name);
    return `<div class="sec-row">
      <div>
        <div class="sec-name" title="${esc(s.name)}">${esc(s.name)}</div>
        ${desc ? `<div class="sec-desc">${esc(desc)}</div>` : ''}
      </div>
      <div class="sec-track"><div class="sec-fill" style="width:${bw}%;background:${s.color}"></div></div>
      <span class="sec-sz">${fmtB(s.size)}</span>
      <span class="sec-pct">${pct}%</span>
    </div>`;
  }).join('');
  const btn = document.getElementById('sec-more');
  if (allSections.length > 15) {
    btn.style.display = '';
    btn.textContent = showAllSec ? 'Show less' : `Show all ${allSections.length} sections`;
  } else {
    btn.style.display = 'none';
  }
}

function toggleAllSections() { showAllSec = !showAllSec; drawSections(); }
