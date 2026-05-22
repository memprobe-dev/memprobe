// Landing page: theme handling + scroll-driven animations.
// Pure DOM, no libraries.

// ── Theme ──────────────────────────────────────────────────────────────────────
(function () {
  const saved = localStorage.getItem('theme') || 'dark';
  document.documentElement.setAttribute('data-theme', saved);
  _applyThemeIcons(saved);
})();

function _applyThemeIcons(t) {
  const moon = document.getElementById('lnav-moon');
  const sun  = document.getElementById('lnav-sun');
  if (!moon || !sun) return;
  moon.style.display = t === 'dark' ? '' : 'none';
  sun.style.display  = t === 'light' ? '' : 'none';
}

function toggleTheme() {
  const cur  = document.documentElement.getAttribute('data-theme') || 'dark';
  const next = cur === 'dark' ? 'light' : 'dark';
  document.documentElement.setAttribute('data-theme', next);
  localStorage.setItem('theme', next);
  _applyThemeIcons(next);
}

// ── Demo animations ─────────────────────────────────────────────────────────
const _PREFERS_REDUCED_MOTION =
  window.matchMedia('(prefers-reduced-motion: reduce)').matches;

function _countTo(el, target, { duration = 1200, comma = false, suffix = '' } = {}) {
  if (_PREFERS_REDUCED_MOTION) {
    el.textContent = (comma ? target.toLocaleString() : String(target)) + suffix;
    return;
  }
  const startTs = performance.now();
  function step(now) {
    const t = Math.min(1, (now - startTs) / duration);
    const eased = 1 - Math.pow(1 - t, 3);
    const v = Math.round(target * eased);
    el.textContent = (comma ? v.toLocaleString() : String(v)) + suffix;
    if (t < 1) requestAnimationFrame(step);
  }
  requestAnimationFrame(step);
}

function _playDemo() {
  const demo = document.getElementById('demo-window');
  if (!demo) return;

  demo.classList.remove('is-playing');
  demo.querySelectorAll('[data-bar]').forEach(b => { b.style.width = '0%'; });
  demo.querySelectorAll('[data-count-to]').forEach(v => {
    v.textContent = '0' + (v.dataset.suffix || '');
  });
  void demo.offsetWidth;

  requestAnimationFrame(() => {
    demo.classList.add('is-playing');
    demo.querySelectorAll('[data-bar]').forEach(b => {
      b.style.width = b.dataset.bar + '%';
    });
    demo.querySelectorAll('[data-count-to]').forEach(v => {
      const target = parseInt(v.dataset.countTo, 10);
      _countTo(v, target, {
        comma:  v.dataset.comma === 'true',
        suffix: v.dataset.suffix || '',
      });
    });
  });
}

function _watchDemo() {
  const demo = document.getElementById('demo-window');
  if (!demo) return;
  if (!('IntersectionObserver' in window)) { _playDemo(); return; }

  const io = new IntersectionObserver((entries) => {
    for (const entry of entries) {
      if (entry.isIntersecting) {
        _playDemo();
        io.disconnect();
        break;
      }
    }
  }, { threshold: 0.3 });
  io.observe(demo);
}

// ── Feature-card scroll fade ───────────────────────────────────────────────
// Sets a CSS custom property `--p` (0..1) on each [data-reveal] element based
// on its proximity to the viewport center. The CSS uses it to drive opacity
// and translateY, so cards fade IN as they enter and OUT as they leave.
function _wireScrollReveal() {
  const els = Array.from(document.querySelectorAll('[data-reveal]'));
  if (!els.length) return;

  if (_PREFERS_REDUCED_MOTION) {
    els.forEach(el => el.style.setProperty('--p', '1'));
    return;
  }

  let ticking = false;
  function update() {
    ticking = false;
    const vh = window.innerHeight;
    // Element is fully visible while its center is within this many px of the
    // viewport center. Beyond that, it fades toward 0 over `fadeRange` px.
    const plateau = vh * 0.30;
    const fadeRange = vh * 0.55;

    for (const el of els) {
      const rect = el.getBoundingClientRect();
      // Fast cull: well off-screen → just set 0 and skip.
      if (rect.bottom < -100 || rect.top > vh + 100) {
        el.style.setProperty('--p', '0');
        continue;
      }
      const elCenter = rect.top + rect.height / 2;
      const dist = Math.abs(elCenter - vh / 2);
      let p;
      if (dist <= plateau) {
        p = 1;
      } else {
        p = 1 - (dist - plateau) / fadeRange;
        if (p < 0) p = 0;
        if (p > 1) p = 1;
      }
      el.style.setProperty('--p', p.toFixed(3));
    }
  }
  function onScroll() {
    if (!ticking) {
      ticking = true;
      requestAnimationFrame(update);
    }
  }

  // Start cards invisible so the first paint matches the scroll state.
  els.forEach(el => el.style.setProperty('--p', '0'));
  update();
  window.addEventListener('scroll',  onScroll, { passive: true });
  window.addEventListener('resize',  onScroll, { passive: true });
}

// ── Boot ─────────────────────────────────────────────────────────────────────
document.addEventListener('DOMContentLoaded', () => {
  _watchDemo();
  _wireScrollReveal();
});
