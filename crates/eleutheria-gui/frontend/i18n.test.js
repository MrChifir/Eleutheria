import test from 'node:test';
import assert from 'node:assert/strict';
import { DICT } from './locales.js';
import { t, tl, setLang, getLang, LANGS } from './i18n.js';
import * as m from './model.js';
import { STEPS, SECTIONS, counter } from './guidemodel.js';
import { rows } from './probermodel.js';
import { serverUpdateView } from './updatemodel.js';

const cyr = /[А-Яа-яЁё]/;
const flat = (v) => (Array.isArray(v) ? v.flatMap(flat) : v && typeof v === 'object' ? Object.values(v).flatMap(flat) : [v]);

test('словари: одинаковые ключи, плейсхолдеры и формы значений', () => {
  assert.deepEqual(Object.keys(DICT.ru).sort(), Object.keys(DICT.en).sort());
  for (const k of Object.keys(DICT.ru)) {
    const [a, b] = [DICT.ru[k], DICT.en[k]];
    assert.equal(Array.isArray(a), Array.isArray(b), k);
    if (Array.isArray(a)) assert.equal(a.length, b.length, k);
    const ph = (v) => flat(v).join('\n').match(/\{\w+\}/g)?.sort().join() ?? '';
    assert.equal(ph(a), ph(b), `плейсхолдеры ${k}`);
  }
});

test('английский словарь без кириллицы (кроме примеров доменов .рф)', () => {
  for (const [k, v] of Object.entries(DICT.en)) {
    for (const s of flat(v)) {
      const clean = String(s).replace(/\.рф/g, '').replace(/Русский/g, '');
      assert.ok(!cyr.test(clean), `${k}: ${s}`);
    }
  }
});

test('смена языка переключает модели и гид', () => {
  setLang('en', { persist: false });
  assert.equal(getLang(), 'en');
  assert.equal(m.statusText(null), 'Loading…');
  assert.equal(m.statusText({ connection: { mode: 'proxy', listenPort: 7890 } }), 'Connected: local proxy 127.0.0.1:7890');
  assert.equal(m.buttonState({ servers: [{}] }, false).label, 'Connect');
  assert.equal(m.formatDelay({ delayMs: 5 }), '5 ms');
  assert.equal(m.RU_LEVELS[0].label, 'Everything through VPN');
  assert.equal(counter(2, 17), '3 of 17');
  assert.equal(STEPS[0].title, 'Welcome to Eleutheria');
  assert.ok(SECTIONS.every((s) => s.title && (s.items || s.faq)));
  assert.equal(rows([{ id: 'video', title: 'Video', enabled: false }], null)[0].text, 'off: uses the common route');
  assert.match(serverUpdateView({ status: 'upToDate', installed: '1.0' }).text, /up to date/);
  setLang('ru', { persist: false });
  assert.equal(m.statusText(null), 'Загрузка…');
  assert.equal(t('нет-ключа'), 'нет-ключа');
  assert.deepEqual(LANGS, ['ru', 'en']);
  assert.ok(Array.isArray(tl('sec.start.items')));
});
