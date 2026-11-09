import test from 'node:test';
import assert from 'node:assert/strict';
import { rowState, rowText, rows, classText, eventsText } from './probermodel.js';

const p = (o) => ({ category: 'video', server: 'main', health: 'healthy', class: null, degraded: false, ms: null, reason: '', ...o });

test('rowState: все failed = bad, часть = warn, suspect и медленно = warn, пусто = unknown', () => {
  assert.equal(rowState([]), 'unknown');
  assert.equal(rowState(null), 'unknown');
  assert.equal(rowState([p({}), p({})]), 'ok');
  assert.equal(rowState([p({ health: 'failed' }), p({})]), 'warn');
  assert.equal(rowState([p({ health: 'failed' }), p({ health: 'failed' })]), 'bad');
  assert.equal(rowState([p({ health: 'suspect' })]), 'warn');
  assert.equal(rowState([p({ degraded: true })]), 'warn');
});

test('rowText: лучшая задержка, причина отказа по классу, подозрение, медленно', () => {
  assert.equal(rowText([p({ ms: 300 }), p({ ms: 120 })], 'ok'), 'работает, 120 мс');
  assert.equal(rowText([p({})], 'ok'), 'работает');
  const t = rowText([p({ health: 'failed', class: 'EXIT_BLOCKED_BY_SITE' })], 'bad');
  assert.match(t, /main: недоступно, сайт не пускает выходной IP/);
  assert.match(rowText([p({ health: 'suspect' })], 'warn'), /проверяю/);
  assert.match(rowText([p({ degraded: true })], 'warn'), /медленно/);
  assert.equal(rowText([], 'unknown'), 'нет данных');
  assert.equal(classText('что-то новое'), '', 'неизвестный класс не ломает текст');
});

test('rows: туннель первым, выключенная категория объясняется, без данных пробера туннеля нет', () => {
  const cats = [{ id: 'video', title: 'Видео', enabled: true }, { id: 'ai', title: 'ИИ-сервисы', enabled: false }];
  const pr = { pairs: [p({ category: 'canary', ms: 50 }), p({ category: 'video', health: 'failed', class: 'PROTOCOL_BLOCKED' })], events: [] };
  const r = rows(cats, pr);
  assert.deepEqual(r.map((x) => x.id), ['canary', 'video', 'ai']);
  assert.equal(r[0].state, 'ok');
  assert.equal(r[1].state, 'bad');
  assert.equal(r[2].enabled, false);
  assert.match(r[2].text, /выключено/);
  assert.deepEqual(rows(cats, null).map((x) => x.id), ['video', 'ai']);
  assert.equal(rows(cats, null)[0].state, 'unknown');
});

test('eventsText: последние N, время HH:MM', () => {
  const ev = Array.from({ length: 12 }, (_, i) => ({ at: 3600 * 5 + 60 * i, text: `e${i}` }));
  const t = eventsText({ events: ev }, 3, 'utc');
  assert.deepEqual(t.split('\n'), ['05:09  e9', '05:10  e10', '05:11  e11']);
  assert.equal(eventsText(null), '');
  assert.equal(eventsText({ events: [] }), '');
});
