// Read the server-injected authentication state from the JSON island
// emitted by Django's {{ value|json_script:"auth-state" }} and expose
// it as the legacy global _IS_GUEST that init.js / analyze.js consume.
//
// Must load BEFORE init.js and analyze.js (see template script order).

(function () {
  const el = document.getElementById('auth-state');
  const isAuthenticated = el ? JSON.parse(el.textContent) : false;
  window._IS_GUEST = !isAuthenticated;
})();
