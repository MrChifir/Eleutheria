// Гид: вкладка со справкой и пошаговый тур с подсветкой элементов. Тексты и расчёты живут в guidemodel.js.
// Стили задаются через CSSOM (el.style.*), а не атрибутом style, поэтому CSP `style-src 'self'` это допускает.
import * as gm from './guidemodel.js';

const $ = (id) => document.getElementById(id);

function seen() {
  try { return window.localStorage.getItem(gm.TOUR_KEY) === '1'; } catch (_) { return false; }
}
function markSeen() {
  try { window.localStorage.setItem(gm.TOUR_KEY, '1'); } catch (_) { /* хранилище недоступно: тур просто покажется снова */ }
}

function el(tag, cls, text) {
  const e = document.createElement(tag);
  if (cls) e.className = cls;
  if (text != null) e.textContent = text;
  return e;
}

/** Рисует справку во вкладке «Гид». */
function renderGuide(root) {
  root.replaceChildren();
  for (const s of gm.SECTIONS) {
    const card = el('section', 'card guide-card');
    card.append(el('h2', null, s.title));
    if (s.items) {
      const list = el(s.ordered ? 'ol' : 'ul', 'guide-list');
      for (const t of s.items) list.append(el('li', null, t));
      card.append(list);
    }
    if (s.faq) {
      for (const f of s.faq) {
        const d = el('details', 'faq');
        d.append(el('summary', null, f.q), el('div', 'muted faq-a', f.a));
        card.append(d);
      }
    }
    root.append(card);
  }
}

/** ctx: { showTab(name) }. Возвращает { start(), maybeAutoStart(overview), isOpen() }. */
export function initGuide(ctx) {
  const body = $('guide-body');
  if (body) renderGuide(body);

  let layer = null;
  let hole = null;
  let card = null;
  let titleEl = null;
  let textEl = null;
  let countEl = null;
  let backBtn = null;
  let nextBtn = null;
  let skipBtn = null;
  let idx = 0;
  let auto = false;
  let origin = 'main';
  let settleTimer = null;

  const open = () => !!layer;

  function build() {
    layer = el('div', 'tour-layer');
    layer.setAttribute('role', 'dialog');
    layer.setAttribute('aria-modal', 'true');
    layer.setAttribute('aria-label', 'Тур по приложению');
    hole = el('div', 'tour-hole');
    card = el('div', 'tour-card');
    countEl = el('div', 'tour-count');
    titleEl = el('h3', 'tour-title');
    textEl = el('div', 'tour-text');
    const actions = el('div', 'tour-actions');
    skipBtn = el('button', 'tour-skip', 'Пропустить');
    skipBtn.type = 'button';
    backBtn = el('button', 'small', 'Назад');
    backBtn.type = 'button';
    nextBtn = el('button', 'small tour-next', 'Далее');
    nextBtn.type = 'button';
    const right = el('div', 'tour-right');
    right.append(backBtn, nextBtn);
    actions.append(skipBtn, right);
    card.append(countEl, titleEl, textEl, actions);
    layer.append(hole, card);
    document.body.append(layer);

    skipBtn.addEventListener('click', close);
    backBtn.addEventListener('click', () => go(gm.prevIndex(idx)));
    nextBtn.addEventListener('click', () => {
      if (gm.isLast(idx, gm.STEPS.length)) close();
      else go(gm.nextIndex(idx, gm.STEPS.length));
    });
    document.addEventListener('keydown', onKey, true);
    window.addEventListener('resize', place);
  }

  function onKey(e) {
    if (!open()) return;
    if (e.key === 'Escape') { e.preventDefault(); e.stopPropagation(); close(); }
    else if (e.key === 'ArrowRight') { e.preventDefault(); nextBtn.click(); }
    else if (e.key === 'ArrowLeft') { e.preventDefault(); backBtn.click(); }
  }

  function targetEl(step) {
    if (!step.target) return null;
    const t = document.querySelector(step.target);
    if (!t) return null;
    return step.card ? (t.closest('.card') || t) : t;
  }

  function place() {
    if (!open()) return;
    const step = gm.STEPS[idx];
    const t = targetEl(step);
    const r = t ? t.getBoundingClientRect() : null;
    const h = r ? gm.holeRect({ left: r.left, top: r.top, width: r.width, height: r.height }) : null;
    layer.classList.toggle('no-target', !h);
    hole.classList.toggle('hidden', !h);
    if (h) {
      hole.style.left = `${h.left}px`;
      hole.style.top = `${h.top}px`;
      hole.style.width = `${h.width}px`;
      hole.style.height = `${h.height}px`;
    }
    const cw = Math.min(380, window.innerWidth - 28);
    card.style.width = `${cw}px`;
    const pos = gm.placeCard(h, { width: cw, height: card.offsetHeight || 220 }, { width: window.innerWidth, height: window.innerHeight });
    card.style.left = `${pos.left}px`;
    card.style.top = `${pos.top}px`;
    card.dataset.side = pos.side;
  }

  function go(i) {
    idx = i;
    const step = gm.STEPS[idx];
    ctx.showTab(step.tab);
    countEl.textContent = gm.counter(idx, gm.STEPS.length);
    titleEl.textContent = step.title;
    textEl.textContent = step.text;
    backBtn.disabled = idx === 0;
    const last = gm.isLast(idx, gm.STEPS.length);
    nextBtn.textContent = last ? 'Закончить' : 'Далее';
    skipBtn.classList.toggle('hidden', last);
    const t = targetEl(step);
    // вкладка могла только что показаться: даём разметке обновиться, затем прокручиваем к элементу и ставим подсветку
    const raf = window.requestAnimationFrame ? (f) => window.requestAnimationFrame(f) : (f) => setTimeout(f, 16);
    const align = () => {
      if (!open() || idx !== i) return;
      if (t && t.scrollIntoView) t.scrollIntoView({ block: 'center', inline: 'nearest' });
      place();
    };
    raf(() => { align(); if (open()) nextBtn.focus({ preventScroll: true }); });
    // карточки раздела 0,7 с «выезжают» анимацией: после неё подсветку нужно выровнять ещё раз
    clearTimeout(settleTimer);
    settleTimer = setTimeout(align, 820);
    place();
  }

  function close() {
    if (!open()) return;
    clearTimeout(settleTimer);
    document.removeEventListener('keydown', onKey, true);
    window.removeEventListener('resize', place);
    layer.remove();
    layer = hole = card = null;
    markSeen();
    ctx.showTab(origin);
  }

  function start() {
    if (open()) return;
    const active = document.querySelector('.nav .tab.active');
    origin = active && active.id ? active.id.replace('tab-btn-', '') : 'main';
    build();
    go(0);
  }

  const btn = $('tour-btn');
  if (btn) btn.addEventListener('click', start);

  return {
    start,
    isOpen: open,
    /** Первый запуск: если тур ещё не показывали и серверов нет, предлагаем его сразу. */
    maybeAutoStart(ov) {
      if (auto || !ov) return;
      auto = true;
      if (!seen() && (!ov.servers || ov.servers.length === 0)) setTimeout(start, 500);
    },
  };
}
