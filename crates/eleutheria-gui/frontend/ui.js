// Свой выпадающий список вместо системного: нативный <select> остаётся в DOM (значение, disabled, событие change
// работают как раньше), но скрыт, а показывается стилизованная кнопка и список в стекле.
// Стили задаются через CSSOM (el.style.*), а не атрибутом style, поэтому CSP `style-src 'self'` это допускает.

const SVG = 'http://www.w3.org/2000/svg';

function icon(cls, d) {
  const svg = document.createElementNS(SVG, 'svg');
  svg.setAttribute('viewBox', '0 0 24 24');
  svg.setAttribute('aria-hidden', 'true');
  svg.setAttribute('class', cls);
  const p = document.createElementNS(SVG, 'path');
  p.setAttribute('d', d);
  svg.append(p);
  return svg;
}
const chevron = () => icon('sel-chevron', 'm6 9 6 6 6-6');
const tick = () => icon('sel-tick', 'm5 12.5 4.5 4.5L19 7.5');

let openClose = null; // закрыватель единственного открытого списка

export function initSelects(root = document) {
  for (const s of root.querySelectorAll('select')) enhance(s);
}

function enhance(native) {
  if (native.dataset.enhanced) return;
  native.dataset.enhanced = '1';

  const wrap = document.createElement('div');
  wrap.className = 'select';
  native.replaceWith(wrap);
  native.classList.add('select-native');
  native.tabIndex = -1;
  native.setAttribute('aria-hidden', 'true');

  const trigger = document.createElement('button');
  trigger.type = 'button';
  trigger.className = 'sel-trigger';
  trigger.setAttribute('aria-haspopup', 'listbox');
  trigger.setAttribute('aria-expanded', 'false');
  const label = native.closest ? wrap.closest('label') : null;
  if (label && label.firstChild && label.firstChild.nodeType === 3) trigger.setAttribute('aria-label', label.firstChild.textContent.trim());
  const text = document.createElement('span');
  text.className = 'sel-text';
  trigger.append(text, chevron());
  wrap.append(native, trigger);

  let pop = null;
  let active = -1;
  let sig = '';
  let typed = '';
  let typedAt = 0;
  const opts = () => [...native.options];
  const enabled = (i) => i >= 0 && i < native.options.length && !native.options[i].disabled;

  function sync() {
    const o = native.options[native.selectedIndex];
    text.textContent = o ? o.textContent : '';
    trigger.disabled = native.disabled;
    if (native.disabled && pop) close();
    if (pop) {
      const now = signature();
      if (now !== sig) build();
      else markSelected();
    }
  }
  const signature = () => opts().map((o) => `${o.value}\u0001${o.textContent}\u0001${o.disabled ? 1 : 0}`).join('\u0002');

  // свойство value меняется кодом без события: перехватываем, чтобы подпись на кнопке не отставала
  const d = Object.getOwnPropertyDescriptor(Object.getPrototypeOf(native), 'value');
  if (d && d.get && d.set) {
    Object.defineProperty(native, 'value', {
      configurable: true,
      get() { return d.get.call(this); },
      set(v) { d.set.call(this, v); sync(); },
    });
  }
  if (window.MutationObserver) {
    new window.MutationObserver(sync).observe(native, { childList: true, subtree: true, characterData: true, attributes: true, attributeFilter: ['disabled', 'label'] });
  }
  native.addEventListener('change', sync);
  // клик по подписи <label> фокусирует нативный select — переводим фокус на кнопку
  native.addEventListener('focus', () => { if (!native.disabled) trigger.focus(); });

  function build() {
    sig = signature();
    pop.replaceChildren();
    opts().forEach((o, i) => {
      const it = document.createElement('div');
      it.className = 'sel-item';
      it.id = `${native.id || 'sel'}-opt-${i}`;
      it.setAttribute('role', 'option');
      it.dataset.index = String(i);
      if (o.disabled) it.setAttribute('aria-disabled', 'true');
      const t = document.createElement('span');
      t.textContent = o.textContent;
      it.append(t, tick());
      pop.append(it);
    });
    markSelected();
    place();
  }

  function markSelected() {
    const items = [...pop.children];
    items.forEach((it, i) => {
      const sel = i === native.selectedIndex;
      it.classList.toggle('selected', sel);
      it.setAttribute('aria-selected', sel ? 'true' : 'false');
      it.classList.toggle('active', i === active);
    });
    const cur = items[active];
    if (cur) {
      trigger.setAttribute('aria-activedescendant', cur.id);
      if (cur.scrollIntoView) cur.scrollIntoView({ block: 'nearest' });
    } else trigger.removeAttribute('aria-activedescendant');
  }

  function place() {
    const r = trigger.getBoundingClientRect();
    const gap = 8;
    pop.style.minWidth = `${r.width}px`;
    pop.style.maxHeight = '';
    const h = pop.offsetHeight;
    const below = window.innerHeight - r.bottom - gap - 10;
    const above = r.top - gap - 10;
    const up = h > below && above > below;
    const room = Math.max(120, up ? above : below);
    pop.style.maxHeight = `${room}px`;
    const real = Math.min(h, room);
    pop.style.left = `${Math.max(8, Math.min(r.left, window.innerWidth - Math.max(r.width, pop.offsetWidth) - 8))}px`;
    pop.style.top = `${up ? r.top - gap - real : r.bottom + gap}px`;
    pop.classList.toggle('up', up);
  }

  function open() {
    if (pop || native.disabled) return;
    if (openClose) openClose();
    pop = document.createElement('div');
    pop.className = 'sel-pop';
    pop.setAttribute('role', 'listbox');
    active = enabled(native.selectedIndex) ? native.selectedIndex : opts().findIndex((o) => !o.disabled);
    document.body.append(pop);
    build();
    wrap.classList.add('open');
    trigger.setAttribute('aria-expanded', 'true');
    pop.addEventListener('mousedown', (e) => e.preventDefault()); // фокус остаётся на кнопке
    pop.addEventListener('click', (e) => {
      const it = e.target.closest && e.target.closest('.sel-item');
      if (it && it.getAttribute('aria-disabled') !== 'true') choose(Number(it.dataset.index));
    });
    pop.addEventListener('mousemove', (e) => {
      const it = e.target.closest && e.target.closest('.sel-item');
      if (!it || it.getAttribute('aria-disabled') === 'true') return;
      const i = Number(it.dataset.index);
      if (i !== active) { active = i; markActive(); }
    });
    document.addEventListener('pointerdown', onOutside, true);
    document.addEventListener('scroll', onScroll, true);
    window.addEventListener('resize', close);
    window.addEventListener('blur', close);
    openClose = close;
  }

  function markActive() {
    [...pop.children].forEach((it, i) => it.classList.toggle('active', i === active));
    const cur = pop.children[active];
    if (cur) trigger.setAttribute('aria-activedescendant', cur.id);
  }

  function onOutside(e) {
    if (pop && !pop.contains(e.target) && !trigger.contains(e.target)) close();
  }
  function onScroll(e) {
    if (pop && !pop.contains(e.target)) close();
  }

  function close() {
    if (!pop) return;
    pop.remove();
    pop = null;
    wrap.classList.remove('open');
    trigger.setAttribute('aria-expanded', 'false');
    trigger.removeAttribute('aria-activedescendant');
    document.removeEventListener('pointerdown', onOutside, true);
    document.removeEventListener('scroll', onScroll, true);
    window.removeEventListener('resize', close);
    window.removeEventListener('blur', close);
    if (openClose === close) openClose = null;
  }

  function choose(i) {
    if (!enabled(i)) return;
    const changed = native.selectedIndex !== i;
    native.selectedIndex = i;
    sync();
    close();
    trigger.focus();
    if (changed) native.dispatchEvent(new window.Event('change', { bubbles: true }));
  }

  function move(step) {
    const n = native.options.length;
    if (!n) return;
    let i = active;
    for (let k = 0; k < n; k++) {
      i = (i + step + n) % n;
      if (enabled(i)) { active = i; markSelected(); return; }
    }
  }

  trigger.addEventListener('click', () => (pop ? close() : open()));
  trigger.addEventListener('keydown', (e) => {
    const k = e.key;
    if (!pop) {
      if (k === 'ArrowDown' || k === 'ArrowUp' || k === 'Enter' || k === ' ') { e.preventDefault(); open(); }
      return;
    }
    if (k === 'ArrowDown') { e.preventDefault(); move(1); }
    else if (k === 'ArrowUp') { e.preventDefault(); move(-1); }
    else if (k === 'Home') { e.preventDefault(); active = -1; move(1); }
    else if (k === 'End') { e.preventDefault(); active = 0; move(-1); }
    else if (k === 'Enter' || k === ' ') { e.preventDefault(); choose(active); }
    else if (k === 'Escape') { e.preventDefault(); e.stopPropagation(); close(); }
    else if (k === 'Tab') close();
    else if (k.length === 1 && !e.ctrlKey && !e.metaKey && !e.altKey) {
      const now = Date.now();
      typed = now - typedAt > 700 ? k.toLowerCase() : typed + k.toLowerCase();
      typedAt = now;
      const i = opts().findIndex((o, j) => !o.disabled && o.textContent.trim().toLowerCase().startsWith(typed));
      if (i >= 0) { active = i; markSelected(); }
    }
  });

  sync();
}
