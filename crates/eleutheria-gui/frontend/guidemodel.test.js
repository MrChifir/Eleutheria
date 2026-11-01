import test from 'node:test';
import assert from 'node:assert/strict';
import { STEPS, SECTIONS, nextIndex, prevIndex, isLast, counter, placeCard, holeRect } from './guidemodel.js';

const VP = { width: 1280, height: 800 };
const CARD = { width: 380, height: 220 };
const inside = (p, card = CARD, vp = VP) => p.left >= 0 && p.top >= 0 && p.left + card.width <= vp.width && p.top + card.height <= vp.height;

test('шаги тура: у каждого есть заголовок, текст, известный раздел и уникальный id', () => {
  const ids = new Set();
  for (const s of STEPS) {
    assert.ok(s.title.length > 0 && s.text.length > 0, s.id);
    assert.ok(['main', 'server', 'updates', 'guide'].includes(s.tab), s.id);
    assert.ok(!ids.has(s.id), `повтор id ${s.id}`);
    ids.add(s.id);
  }
  assert.equal(STEPS[0].target, null, 'тур начинается с приветствия без подсветки');
  assert.equal(STEPS.at(-1).target, null, 'и заканчивается итогом без подсветки');
});

test('справка: у разделов есть заголовок и либо пункты, либо вопросы', () => {
  for (const s of SECTIONS) {
    assert.ok(s.title.length > 0);
    assert.ok((s.items && s.items.length > 0) || (s.faq && s.faq.length > 0), s.id);
    for (const f of s.faq || []) assert.ok(f.q && f.a, s.id);
  }
});

test('навигация по шагам не выходит за границы', () => {
  const n = STEPS.length;
  assert.equal(prevIndex(0), 0);
  assert.equal(prevIndex(5), 4);
  assert.equal(nextIndex(0, n), 1);
  assert.equal(nextIndex(n - 1, n), n);
  assert.equal(isLast(n - 1, n), true);
  assert.equal(isLast(0, n), false);
  assert.equal(counter(2, 17), '3 из 17');
});

test('placeCard: справа от цели, если там есть место', () => {
  const p = placeCard({ left: 100, top: 300, width: 200, height: 60 }, CARD, VP);
  assert.equal(p.side, 'right');
  assert.ok(p.left >= 100 + 200);
  assert.ok(inside(p));
});

test('placeCard: у правого края уходит влево, у низа и сверху ищет другую сторону', () => {
  const left = placeCard({ left: 1000, top: 300, width: 250, height: 60 }, CARD, VP);
  assert.equal(left.side, 'left');
  assert.ok(inside(left));
  const wide = placeCard({ left: 20, top: 20, width: 1240, height: 100 }, CARD, VP);
  assert.equal(wide.side, 'bottom');
  assert.ok(inside(wide));
  const tall = placeCard({ left: 20, top: 400, width: 1240, height: 380 }, CARD, VP);
  assert.equal(tall.side, 'top');
  assert.ok(inside(tall));
});

test('placeCard: без цели или если нигде не помещается, по центру и в пределах окна', () => {
  const none = placeCard(null, CARD, VP);
  assert.equal(none.side, 'center');
  assert.ok(inside(none));
  const cover = placeCard({ left: 0, top: 0, width: 1280, height: 800 }, CARD, VP);
  assert.equal(cover.side, 'center');
  assert.ok(inside(cover));
  const small = placeCard(null, { width: 300, height: 200 }, { width: 320, height: 240 });
  assert.ok(small.left >= 0 && small.top >= 0);
});

test('holeRect: поле вокруг элемента; скрытый элемент даёт null', () => {
  assert.deepEqual(holeRect({ left: 10, top: 20, width: 100, height: 50 }, 8), { left: 2, top: 12, width: 116, height: 66 });
  assert.equal(holeRect({ left: 10, top: 20, width: 0, height: 0 }), null);
  assert.equal(holeRect(null), null);
});
