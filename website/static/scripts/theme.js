(function() {
  const saved = localStorage.getItem('memprobe-theme') || 'dark';
  document.documentElement.dataset.theme = saved;
})();

function toggleTheme() {
  const html = document.documentElement;
  const isDark = html.dataset.theme === 'dark';
  html.dataset.theme = isDark ? 'light' : 'dark';
  const moonIcon = document.getElementById('theme-icon-moon');
  const sunIcon  = document.getElementById('theme-icon-sun');
  if (moonIcon) moonIcon.style.display = isDark ? 'none' : 'block';
  if (sunIcon)  sunIcon.style.display  = isDark ? 'block' : 'none';
  localStorage.setItem('memprobe-theme', isDark ? 'light' : 'dark');
}
