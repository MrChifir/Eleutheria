// Модель гида: шаги тура, текст справки и расчёт положения подсказки. Чистые функции без DOM (проверяются в Node).

import { t, tl } from './i18n.js';

/** Шаг тура: структура здесь, тексты берутся из словаря по текущему языку (геттеры). */
function step({ id, tab, target, card }) {
  const o = { id, tab, target };
  if (card) o.card = true;
  Object.defineProperty(o, 'title', { enumerable: true, get: () => t(`step.${id}.title`) });
  Object.defineProperty(o, 'text', { enumerable: true, get: () => t(`step.${id}.text`) });
  return o;
}

function section(id, ordered, kind) {
  const o = { id };
  if (ordered) o.ordered = true;
  Object.defineProperty(o, 'title', { enumerable: true, get: () => t(`sec.${id}.title`) });
  Object.defineProperty(o, kind, { enumerable: true, get: () => tl(`sec.${id}.items`) });
  return o;
}

export const TOUR_KEY = 'eleutheria.tour.v1';

/**
 * Шаги тура. tab: раздел, который нужно открыть; target: CSS-селектор подсвечиваемого элемента (null = без подсветки);
 * card: подсветить всю карточку, в которой лежит target.
 */
export const STEPS = [
  step({id: "welcome", tab: "main", target: null, card: false}),
  step({id: "nav", tab: "main", target: ".nav", card: false}),
  step({id: "main-btn", tab: "main", target: "#main-btn", card: false}),
  step({id: "mode", tab: "main", target: "#mode", card: true}),
  step({id: "server", tab: "main", target: "#server", card: false}),
  step({id: "ru", tab: "main", target: "#ru", card: false}),
  step({id: "servers", tab: "main", target: "#servers", card: true}),
  step({id: "cats", tab: "main", target: "#cats", card: true}),
  step({id: "import", tab: "main", target: ".add-card", card: false}),
  step({id: "partners", tab: "server", target: ".partners", card: false}),
  step({id: "access", tab: "server", target: "#s-host", card: true}),
  step({id: "install", tab: "server", target: "#p-port", card: true}),
  step({id: "users", tab: "server", target: "#users-btn", card: true}),
  step({id: "protocols", tab: "server", target: "#protocols", card: true}),
  step({id: "updates", tab: "updates", target: "#upd-check-btn", card: true}),
  step({id: "status", tab: "main", target: ".side-status", card: false}),
  step({id: "done", tab: "main", target: null, card: false}),
];

/** Справка для вкладки «Гид». items: строки; ordered: нумерованный список; faq: пары вопрос-ответ. */
export const SECTIONS = [
  section('start', true, 'items'),
  section('main', false, 'items'),
  section('modes', false, 'items'),
  section('cats', false, 'items'),
  section('server', false, 'items'),
  section('updates', false, 'items'),
  section('safety', false, 'items'),
  section('faq', false, 'faq'),
];

export function nextIndex(i, n) {
  return Math.min(Math.max(i, 0) + 1, n);
}

export function prevIndex(i) {
  return Math.max(i - 1, 0);
}

export function isLast(i, n) {
  return i >= n - 1;
}

/** Подпись счётчика: «3 из 17» / «3 of 17». */
export function counter(i, n) {
  return t('tour.counter', { i: i + 1, n });
}

/**
 * Где поставить карточку подсказки рядом с подсвеченным прямоугольником.
 * rect: {left, top, width, height} или null; card: {width, height}; vp: {width, height}.
 * Порядок: справа, слева, снизу, сверху; если нигде не помещается или цели нет, по центру.
 * Результат всегда лежит внутри окна.
 */
export function placeCard(rect, card, vp, gap = 18, margin = 14) {
  const clamp = (v, lo, hi) => Math.max(lo, Math.min(v, Math.max(lo, hi)));
  const inside = (x, y) => x >= margin && y >= margin && x + card.width <= vp.width - margin && y + card.height <= vp.height - margin;
  const center = () => ({
    left: clamp((vp.width - card.width) / 2, margin, vp.width - card.width - margin),
    top: clamp((vp.height - card.height) / 2, margin, vp.height - card.height - margin),
    side: 'center',
  });
  if (!rect) return center();
  const midY = rect.top + rect.height / 2 - card.height / 2;
  const midX = rect.left + rect.width / 2 - card.width / 2;
  const tries = [
    { side: 'right', x: rect.left + rect.width + gap, y: midY },
    { side: 'left', x: rect.left - gap - card.width, y: midY },
    { side: 'bottom', x: midX, y: rect.top + rect.height + gap },
    { side: 'top', x: midX, y: rect.top - gap - card.height },
  ];
  for (const t of tries) {
    const horizontal = t.side === 'right' || t.side === 'left';
    const x = horizontal ? t.x : clamp(t.x, margin, vp.width - card.width - margin);
    const y = horizontal ? clamp(t.y, margin, vp.height - card.height - margin) : t.y;
    if (inside(x, y)) return { left: Math.round(x), top: Math.round(y), side: t.side };
  }
  return center();
}

/** Прямоугольник подсветки с полем вокруг элемента. Нулевой размер (элемент скрыт) даёт null. */
export function holeRect(r, pad = 8) {
  if (!r || !(r.width > 0) || !(r.height > 0)) return null;
  return { left: r.left - pad, top: r.top - pad, width: r.width + pad * 2, height: r.height + pad * 2 };
}
