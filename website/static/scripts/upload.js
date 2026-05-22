function onPick(key, inp) {
  const f = inp.files[0]; if (!f) return;
  const dz = document.getElementById('dz-' + key);
  dz.classList.add('has-file');
  document.getElementById('fn-' + key).textContent = f.name;
  updateBtns();
  if (key === 'a') updateAnalyzeBtn();
}

function updateBtns() {
  // Analyze button managed by updateAnalyzeBtn() in project.js
  // Diff is now handled entirely within compare.js
}

function clearFile(key) {
  const inp = document.getElementById('fi-' + key);
  if (inp) inp.value = '';
  const dz = document.getElementById('dz-' + key);
  if (dz) dz.classList.remove('has-file');
  const fn = document.getElementById('fn-' + key);
  if (fn) fn.textContent = '';
  updateBtns();
  if (key === 'a') updateAnalyzeBtn();
}

['dz-a'].forEach(id => {
  const dz = document.getElementById(id);
  if (!dz) return;
  dz.addEventListener('dragover', e => { e.preventDefault(); dz.classList.add('drag-over'); });
  dz.addEventListener('dragleave', () => dz.classList.remove('drag-over'));
  dz.addEventListener('drop', e => {
    e.preventDefault(); dz.classList.remove('drag-over');
    const f = e.dataTransfer.files[0]; if (!f) return;
    const key = id.replace('dz-','');
    const inp = document.getElementById('fi-' + key);
    const dt = new DataTransfer(); dt.items.add(f); inp.files = dt.files;
    onPick(key, inp);
  });
});
