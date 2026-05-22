// Apply saved theme before first paint to avoid flash-of-wrong-theme.
// Used by all public pages (login, delete_account, share). The /app page
// uses theme.js instead because it has its own localStorage key.
(function () {
  const t = localStorage.getItem('theme') || 'dark';
  document.documentElement.setAttribute('data-theme', t);
})();
