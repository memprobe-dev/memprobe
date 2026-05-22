// User-menu dropdown behavior.
// Safe to load on every page — checks the menu exists before acting.

function toggleUserMenu() {
  const dd = document.getElementById('user-dropdown');
  if (dd) dd.classList.toggle('open');
}

document.addEventListener('click', e => {
  if (!e.target.closest('#user-menu')) {
    document.getElementById('user-dropdown')?.classList.remove('open');
  }
});
