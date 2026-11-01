// Визуальные эффекты: плавающая подсветка активного раздела.
// Стили задаются через CSSOM (el.style.*), а не атрибутом style, поэтому CSP `style-src 'self'` это допускает.


export function initNavPill(nav) {
  const pill = nav.querySelector('.nav-pill');
  if (!pill) return { sync() {} };
  let first = true;
  const sync = () => {
    const a = nav.querySelector('.tab.active');
    if (!a) return;
    pill.style.width = `${a.offsetWidth}px`;
    pill.style.height = `${a.offsetHeight}px`;
    pill.style.setProperty('--px', `${a.offsetLeft}px`);
    pill.style.setProperty('--py', `${a.offsetTop}px`);
    if (first) {
      first = false;
      // первый показ без «пролёта» из угла
      const raf = window.requestAnimationFrame ? (f) => window.requestAnimationFrame(f) : (f) => setTimeout(f, 16);
      raf(() => raf(() => pill.classList.add('ready')));
    }
  };
  window.addEventListener('resize', sync);
  if (document.fonts && document.fonts.ready) document.fonts.ready.then(sync).catch(() => {});
  return { sync };
}
