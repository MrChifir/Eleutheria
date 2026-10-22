import test from 'node:test';
import assert from 'node:assert/strict';
import * as m from './model.js';

const srv = (name) => ({ name, host: 'h', port: 443, security: 'reality' });
const ov = (o = {}) => ({ servers: [srv('a')], connection: null, helper: { running: false, version: null }, ...o });

test('кнопка: отключено, нет серверов, занято, подключено', () => {
  assert.deepEqual(m.buttonState(ov(), false), { label: 'Подключить', action: 'connect', disabled: false });
  assert.equal(m.buttonState(ov({ servers: [] }), false).disabled, true);
  assert.equal(m.buttonState(ov(), true).action, 'none');
  assert.equal(m.buttonState(null, false).disabled, true);
  const on = ov({ connection: { mode: 'proxy', pid: 1, listenPort: 7890 } });
  assert.deepEqual(m.buttonState(on, false), { label: 'Отключить', action: 'disconnect', disabled: false });
  // во время операции отключить нельзя повторно
  assert.equal(m.buttonState(on, true).disabled, true);
});

test('TUN недоступен без helper, режим по умолчанию подстраивается', () => {
  assert.match(m.tunDisabledReason(ov()), /helper/);
  const withHelper = ov({ helper: { running: true, version: '0.1.0' } });
  assert.equal(m.tunDisabledReason(withHelper), null);
  assert.equal(m.pickMode(withHelper, undefined), 'tun');
  assert.equal(m.pickMode(withHelper, 'proxy'), 'proxy');
  assert.equal(m.pickMode(ov(), 'tun'), 'proxy'); // запрошенный TUN без helper заменяется
  assert.equal(m.pickMode(ov(), undefined), 'proxy');
});

test('тексты статуса', () => {
  assert.equal(m.statusText(null), 'Загрузка…');
  assert.equal(m.statusText(ov()), 'Отключено');
  assert.match(m.statusText(ov({ connection: { mode: 'tun', pid: 1, listenPort: null } })), /весь трафик/);
  assert.match(m.statusText(ov({ connection: { mode: 'proxy', pid: 1, listenPort: 7890 } })), /127\.0\.0\.1:7890/);
});

test('задержки: формат и сортировка', () => {
  assert.equal(m.formatDelay({ delayMs: 42 }), '42 мс');
  assert.equal(m.formatDelay({ delayMs: null, error: 'x' }), 'недоступен');
  assert.equal(m.formatDelay({ delayMs: null, error: null }), '—');
  const sorted = m.sortLatency([
    { name: 'dead', delayMs: null }, { name: 'slow', delayMs: 300 }, { name: 'fast', delayMs: 20 }, { name: 'b', delayMs: 20 },
  ]);
  assert.deepEqual(sorted.map((s) => s.name), ['b', 'fast', 'slow', 'dead']);
});

test('запрос подключения и итоговый текст', () => {
  assert.deepEqual(m.buildConnectRequest({ mode: 'tun', server: '', ruDirect: 'minimal' }), { mode: 'tun', server: null, ruDirect: 'minimal' });
  assert.equal(m.buildConnectRequest({ mode: 'proxy', server: 's1', ruDirect: 'off' }).server, 's1');
  assert.equal(m.connectSummary({ mode: 'tun' }), 'Туннель поднят.');
  assert.match(m.connectSummary({ mode: 'proxy', delayMs: 55 }), /55 мс/);
  assert.match(m.connectSummary({ mode: 'proxy', delayMs: null, warning: 'timeout' }), /timeout/);
  assert.deepEqual(m.RU_LEVELS.map((l) => l.value), ['off', 'minimal', 'rulesets']);
});
