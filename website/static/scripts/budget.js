function getBudgetBytes() {
  const fkb = parseFloat(document.getElementById('budget-flash').value);
  const rkb = parseFloat(document.getElementById('budget-ram').value);
  return {
    flash: isNaN(fkb) || fkb <= 0 ? null : Math.round(fkb * 1024),
    ram:   isNaN(rkb) || rkb <= 0 ? null : Math.round(rkb * 1024),
  };
}

function applyBudgetToKPIs(flashBytes, ramBytes) {
  const { flash: fb, ram: rb } = getBudgetBytes();
  document.querySelectorAll('.kpi').forEach(el => {
    el.classList.remove('budget-exceeded', 'budget-ok');
  });
  const kpiEl = document.getElementById('kpi-row');
  if (!kpiEl) return;
  const kpis = kpiEl.querySelectorAll('.kpi');
  // kpis[0] = Flash, kpis[1] = RAM

  function setBar(kpiEl, usedBytes, budgetBytes, barSelector) {
    const fill = kpiEl.querySelector(barSelector);
    if (!fill) return;
    if (budgetBytes !== null && budgetBytes > 0) {
      const pct = Math.min(100, (usedBytes / budgetBytes) * 100);
      fill.style.width = pct.toFixed(1) + '%';
      fill.style.opacity = '1';
    } else {
      fill.style.width = '0%';
      fill.style.opacity = '0';
    }
  }

  if (kpis[0]) {
    if (fb !== null) {
      const exceeded = flashBytes > fb;
      kpis[0].classList.toggle('budget-exceeded', exceeded);
      kpis[0].classList.toggle('budget-ok', !exceeded);
      kpis[0].querySelector('.kpi-sub') && (kpis[0].querySelector('.kpi-sub').innerHTML = exceeded
        ? `<svg xmlns="http://www.w3.org/2000/svg" width="12" height="12" viewBox="0 0 24 24" fill="currentColor" style="vertical-align:middle;margin-right:3px"><path d="M12 2L1 21h22L12 2zm0 3.5L20.5 19h-17L12 5.5zM11 10v4h2v-4h-2zm0 6v2h2v-2h-2z"/></svg> exceeds ${fmtB(fb)} budget by ${fmtB(flashBytes - fb)}`
        : `<svg xmlns="http://www.w3.org/2000/svg" width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round" style="vertical-align:middle;margin-right:3px"><polyline points="20 6 9 17 4 12"/></svg> ${fmtB(fb - flashBytes)} under budget`);
    }
    setBar(kpis[0], flashBytes, fb, '.kpi-bar-flash');
  }
  if (kpis[1]) {
    if (rb !== null) {
      const exceeded = ramBytes > rb;
      kpis[1].classList.toggle('budget-exceeded', exceeded);
      kpis[1].classList.toggle('budget-ok', !exceeded);
      kpis[1].querySelector('.kpi-sub') && (kpis[1].querySelector('.kpi-sub').innerHTML = exceeded
        ? `<svg xmlns="http://www.w3.org/2000/svg" width="12" height="12" viewBox="0 0 24 24" fill="currentColor" style="vertical-align:middle;margin-right:3px"><path d="M12 2L1 21h22L12 2zm0 3.5L20.5 19h-17L12 5.5zM11 10v4h2v-4h-2zm0 6v2h2v-2h-2z"/></svg> exceeds ${fmtB(rb)} budget by ${fmtB(ramBytes - rb)}`
        : `<svg xmlns="http://www.w3.org/2000/svg" width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round" style="vertical-align:middle;margin-right:3px"><polyline points="20 6 9 17 4 12"/></svg> ${fmtB(rb - ramBytes)} under budget`);
    }
    setBar(kpis[1], ramBytes, rb, '.kpi-bar-ram');
  }
}

function _budgetKey(proj) {
  return proj ? `memprobe-budget-${proj}` : 'memprobe-budget-snapshot';
}

function saveBudgetForProject(proj) {
  // Save current budget inputs to localStorage under the current project key
  // before the caller switches _selectedProject to the new one. This prevents
  // in-progress edits from being lost when the user clicks a different project.
  saveBudget();
}

async function loadBudgetForProject(proj) {
  const key = _budgetKey(proj === '__new__' ? '__new__' : proj);
  let saved = null;
  try { saved = JSON.parse(localStorage.getItem(key) || 'null'); } catch (_) {}
  document.getElementById('budget-flash').value = saved?.flash || '';
  document.getElementById('budget-ram').value   = saved?.ram   || '';

  // For real projects, server-side settings win over local cache.
  if (typeof proj === 'string' && proj && proj !== '__new__') {
    try {
      const r = await fetch(`/api/project/${encodeURIComponent(proj)}`);
      if (r.ok) {
        const s = await r.json();
        if (s.flash_budget_bytes) {
          document.getElementById('budget-flash').value = Math.round(s.flash_budget_bytes / 1024);
        }
        if (s.ram_budget_bytes) {
          document.getElementById('budget-ram').value = Math.round(s.ram_budget_bytes / 1024);
        }
      }
    } catch (e) { /* keep local cache */ }
  }
}

function saveBudget() {
  const proj = _selectedProject === '__new__'
    ? (document.getElementById('proj-new-name')?.value.trim() || '__new__')
    : _selectedProject;
  const key = _budgetKey(proj);
  const fv = document.getElementById('budget-flash').value;
  const rv = document.getElementById('budget-ram').value;
  localStorage.setItem(key, JSON.stringify({ flash: fv, ram: rv }));
}

function loadBudget() {
  loadBudgetForProject(_selectedProject);
}
