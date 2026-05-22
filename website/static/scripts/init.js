document.addEventListener('DOMContentLoaded', () => {
  const isDarkInit = document.documentElement.dataset.theme === 'dark';
  const moonI = document.getElementById('theme-icon-moon');
  const sunI  = document.getElementById('theme-icon-sun');
  if (moonI) moonI.style.display = isDarkInit ? 'block' : 'none';
  if (sunI)  sunI.style.display  = isDarkInit ? 'none' : 'block';
  if (typeof _IS_GUEST === 'undefined' || !_IS_GUEST) {
    loadProjectPicker();
    initFromHash();
  } else {
    // Guests: no project picker, no hash restore - just enable the upload button
    _selectedProject = null;
    updateBtns();
    if (typeof updateAnalyzeBtn === 'function') updateAnalyzeBtn();
  }
});
