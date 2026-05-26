function showTab(name, btn) {
  document.querySelectorAll('.page').forEach(p => p.classList.remove('visible'));
  document.querySelectorAll('.nav-btn').forEach(b => b.classList.remove('active'));
  document.getElementById('tab-' + name).classList.add('visible');
  btn.classList.add('active');
  if (name === 'history') loadHist();
  if (name === 'projects') loadProjects();
  if (name === 'analyze') loadProjectPicker();
}

function showAnalysisTab(name, btn) {
  document.querySelectorAll('.atab-panel').forEach(p => p.classList.remove('active'));
  document.querySelectorAll('.atab-btn').forEach(b => b.classList.remove('active'));
  document.getElementById('atab-' + name).classList.add('active');
  btn.classList.add('active');
  // Re-fit treemap SVG when switching to its tab (SVG width may be stale)
  if (name === 'treemap' && typeof renderTreemap === 'function' && _lastAnalysis?.treemap) {
    renderTreemap(_lastAnalysis.treemap);
  }
}
