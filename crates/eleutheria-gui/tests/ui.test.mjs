// UI-тест: настоящие index.html + app.js + server.js в jsdom, бэкенд Tauri подменён моком.
// Проверяет связку DOM, модели и вызовов команд. Это не WebView: CSP и движок WebKit здесь не участвуют.
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { JSDOM } from 'jsdom';

const root = path.join(path.dirname(fileURLToPath(import.meta.url)), '..', 'frontend');
const html = fs.readFileSync(path.join(root, 'index.html'), 'utf8').replace(/<script[^>]*><\/script>/, '').replace(/<link[^>]*>/, '');
const dom = new JSDOM(html, { url: 'http://localhost/' });
const { window } = dom;
const doc = window.document;
const $ = (id) => doc.getElementById(id);

const be = {
  servers: [{ name: 'main', host: '203.0.113.5', port: 443, security: 'reality' }],
  connection: null,
  helper: { running: false, version: null },
  probe: { fingerprint: 'SHA256:abc', status: { kind: 'unknown' } },
  users: ['default'],
  appVersion: '0.2.0',
  updateDue: false,
  startReport: { updatedTo: null, rolledBackFrom: '0.3.0' },
  updateOutcome: { kind: 'upToDate' },
  downloadFails: false,
  srv: { installed: '1.0.0', bundled: '1.14.3', status: 'outdated' },
  calls: [],
  listeners: {},
};
const link = (n) => `vless://uuid-${n}@203.0.113.5:443#${n}`;
const view = () => ({ users: [...be.users], links: be.users.map((n) => ({ name: n, link: link(n), qrSvg: '<svg xmlns="http://www.w3.org/2000/svg"><rect/></svg>' })) });

window.__TAURI__ = {
  core: {
    invoke: async (cmd, args) => {
      be.calls.push([cmd, args]);
      switch (cmd) {
        case 'overview': return { servers: be.servers, connection: be.connection, helper: be.helper, appVersion: be.appVersion };
        case 'connect':
          be.connection = { mode: args.req.mode, pid: 42, listenPort: args.req.mode === 'proxy' ? 7890 : null };
          return { mode: args.req.mode, pid: 42, listenPort: 7890, delayMs: 55, warning: null };
        case 'latency': return { route: 'авто', servers: [{ name: 'main', delayMs: 55, error: null, active: true }] };
        case 'disconnect': be.connection = null; return true;
        case 'probe_host_key': return be.probe;
        case 'provision':
          be.listeners.progress?.({ payload: 'Генерирую ключи Reality…' });
          be.probe = { fingerprint: 'SHA256:abc', status: { kind: 'known' } };
          return { notes: [{ ok: true, text: 'BBR включён' }, { ok: false, text: 'ufw не включал' }], savedAs: 't', links: [view().links[0]] };
        case 'import_servers': return { added: ['x'], skipped: [] };
        case 'list_users': return view();
        case 'add_user': be.users.push(args.name); return view();
        case 'remove_user': be.users = be.users.filter((u) => u !== args.name); return view();
        case 'install_helper': be.helper = { running: true, version: '0.1.0' }; return null;
        case 'update_due': return be.updateDue;
        case 'check_update': return be.updateOutcome;
        case 'download_update':
          if (be.downloadFails) throw new Error('подпись не совпала');
          be.listeners['update-progress']?.({ payload: { done: 50, total: 200 } });
          return null;
        case 'install_update': return null;
        case 'import_update':
          if (be.importFails) throw new Error('подпись не совпадает');
          return { version: '0.2.0', restarting: true };
        case 'confirm_started': return be.startReport ?? { updatedTo: null, rolledBackFrom: null };
        case 'server_update_status': return be.srv;
        case 'update_server': be.srv = { installed: '1.14.3', bundled: '1.14.3', status: 'upToDate' }; return be.srv;
        default: throw new Error(`неизвестная команда ${cmd}`);
      }
    },
  },
  event: { listen: async (ev, cb) => { be.listeners[ev] = cb; } },
};

Object.assign(globalThis, { window, document: doc, Option: window.Option });
globalThis.setInterval = () => 0; // опрос по таймеру в тесте не нужен: обновление идёт после действий
window.confirm = () => true;

const settle = async () => { for (let i = 0; i < 8; i++) await new Promise((r) => setTimeout(r, 0)); };
const click = async (el) => { el.dispatchEvent(new window.Event('click', { bubbles: true })); await settle(); };
const type = async (id, v) => { $(id).value = v; $(id).dispatchEvent(new window.Event('input', { bubbles: true })); await settle(); };
const called = (cmd) => be.calls.filter(([c]) => c === cmd);

await import(pathToFileURL(path.join(root, 'app.js')).href);
await settle();

test('главный экран: отключено, TUN недоступен без helper', () => {
  assert.equal($('status').textContent, 'Отключено');
  assert.equal($('main-btn').textContent, 'Подключить');
  assert.equal($('main-btn').disabled, false);
  assert.equal($('mode').value, 'proxy');
  assert.equal($('mode').querySelector('option[value="tun"]').disabled, true);
  assert.equal($('helper-btn').classList.contains('hidden'), false);
  assert.equal($('tun-hint').classList.contains('hidden'), false);
  assert.deepEqual([...$('ru').options].map((o) => o.value), ['off', 'minimal', 'rulesets']);
  assert.equal($('ru').value, 'minimal');
});

test('при старте приложение подтверждает запуск и сообщает об откате прошлого обновления', () => {
  assert.equal(called('confirm_started').length, 1);
  assert.match($('msg').textContent, /0\.3\.0.*не запустилось.*вернули прежнюю/);
  assert.equal($('msg').className, 'msg err');
});

test('подключение через прокси и замер задержек', async () => {
  await click($('main-btn'));
  assert.deepEqual(called('connect')[0][1], { req: { mode: 'proxy', server: null, ruDirect: 'minimal' } });
  assert.equal($('status').textContent, 'Подключено: локальный прокси 127.0.0.1:7890');
  assert.equal($('main-btn').textContent, 'Отключить');
  assert.equal($('mode').disabled, true, 'во время подключения режим менять нельзя');
  assert.match($('servers').textContent, /55 мс/);
  assert.equal($('dot').className, 'dot on');
});

test('отключение; после появления helper режим по умолчанию TUN', async () => {
  be.helper = { running: true, version: '0.1.0' };
  await click($('main-btn'));
  assert.equal($('status').textContent, 'Отключено');
  assert.equal($('mode').value, 'tun');
  assert.equal($('mode').querySelector('option[value="tun"]').disabled, false);
  assert.equal($('helper-btn').classList.contains('hidden'), true);
});

test('имя сервера с HTML выводится как текст (нет XSS)', async () => {
  be.servers = [{ name: '<img src=x onerror=alert(1)>', host: 'h', port: 1, security: 'reality' }];
  await type('source', 'vless://x#y');
  await click($('import-btn')); // после действия список перечитывается из overview
  assert.equal(called('import_servers').length, 1);
  assert.ok($('servers').textContent.includes('<img src=x onerror=alert(1)>'), 'имя показано буквально');
  assert.equal($('servers').querySelector('img'), null, 'HTML из имени не разобран');
});

test('вкладка «Сервер»: ключ хоста, подтверждение, установка, прогресс', async () => {
  await click($('tab-btn-server'));
  assert.equal($('tab-server').classList.contains('hidden'), false);
  assert.equal($('tab-main').classList.contains('hidden'), true);
  assert.equal($('probe-btn').disabled, true, 'без адреса проверять нечего');

  await type('s-host', '203.0.113.5');
  await type('s-pass', 'pw');
  assert.equal($('probe-btn').disabled, false);
  assert.equal($('provision-btn').disabled, true, 'ключ ещё не проверен');

  await click($('probe-btn'));
  assert.match($('hostkey').textContent, /SHA256:abc/);
  assert.equal($('trust-row').classList.contains('hidden'), false);
  assert.equal($('provision-btn').disabled, true, 'новый ключ без подтверждения: нельзя');

  $('trust').checked = true;
  $('trust').dispatchEvent(new window.Event('change', { bubbles: true }));
  assert.equal($('provision-btn').disabled, false);

  await click($('provision-btn'));
  const [, a] = called('provision')[0];
  assert.equal(a.conn.trustedFingerprint, 'SHA256:abc');
  assert.equal(a.conn.password, 'pw');
  assert.deepEqual(a.req, { port: null, sni: null, profile: 'Eleutheria', userName: 'default', hardenSsh: true, bbr: true, firewall: true });
  assert.match($('log').textContent, /Генерирую ключи Reality/);
  assert.equal($('s-pass').value, '', 'пароль очищен после установки');
  assert.equal($('result').classList.contains('hidden'), false);
  assert.match($('result').textContent, /✓ BBR включён/);
  assert.match($('result').textContent, /⚠ ufw не включал/);
  assert.equal($('result').querySelector('input').value, link('default'));
  assert.match($('result').querySelector('img.qr').src, /^data:image\/svg\+xml/);
  assert.match($('s-msg').textContent, /«t»/);
  // после установки ключ хоста перепроверен: пароль не нужен, кнопки пользователей доступны
  assert.equal(called('probe_host_key').length, 2);
  assert.equal($('trust-row').classList.contains('hidden'), true);
  assert.equal($('users-btn').disabled, false);
});

test('пользователи: список, ссылка с QR по нажатию, добавление, удаление', async () => {
  await click($('users-btn'));
  assert.equal($('users').children.length, 1);
  assert.equal($('users').querySelector('button.danger').disabled, true, 'единственного пользователя удалить нельзя');

  const linkBtn = [...$('users').querySelectorAll('button')].find((b) => b.textContent === 'Ссылка');
  assert.equal($('users').querySelector('.linkrow'), null, 'ссылка по умолчанию скрыта');
  await click(linkBtn);
  assert.equal($('users').querySelector('.linkrow input').value, link('default'));
  assert.ok($('users').querySelector('img.qr'));
  await click(linkBtn);
  assert.equal($('users').querySelector('.linkrow'), null);

  await type('new-user', 'bad name');
  await click($('add-user-btn'));
  assert.equal(called('add_user').length, 0, 'неверное имя не уходит на сервер');
  assert.match($('s-msg').textContent, /латиница/);

  await type('new-user', 'anna');
  await click($('add-user-btn'));
  assert.deepEqual(called('add_user')[0][1].name, 'anna');
  assert.equal($('users').children.length, 2);
  assert.equal($('new-user').value, '');

  const del = [...$('users').querySelectorAll('li')].find((li) => li.textContent.includes('anna')).querySelector('button.danger');
  assert.equal(del.disabled, false);
  await click(del);
  assert.equal(called('remove_user')[0][1].name, 'anna');
  assert.equal($('users').children.length, 1);
});

test('смена адреса сбрасывает проверку ключа и список пользователей', async () => {
  await type('s-host', '198.51.100.7');
  assert.equal($('hostkey').classList.contains('hidden'), true);
  assert.equal($('users').children.length, 0);
  assert.equal($('provision-btn').disabled, true);
});

test('установка helper из интерфейса', async () => {
  await click($('tab-btn-main'));
  be.helper = { running: false, version: null };
  be.servers = [{ name: 'main', host: 'h', port: 1, security: 'reality' }];
  await click($('helper-btn'));
  assert.equal(called('install_helper').length, 1);
  assert.equal($('helper-btn').classList.contains('hidden'), true);
  assert.match($('msg').textContent, /Helper установлен/);
});

test('стили: .hidden не перебивается display у .tabpane, label.check и др. (найдено в реальном WebKit)', () => {
  const css = fs.readFileSync(path.join(root, 'style.css'), 'utf8');
  assert.match(css, /\.hidden\s*\{[^}]*display:\s*none\s*!important/);
  // каждый элемент, который скрывается классом hidden, не должен терять скрытие из-за собственного display
  const hiddenIds = [...new Set([...html.matchAll(/id="([^"]+)"[^>]*class="[^"]*\bhidden\b/g)].map((m) => m[1]))];
  assert.ok(hiddenIds.length >= 4, hiddenIds.join(','));
});

test('обновления приложения: проверка по кнопке, changelog как текст, скачивание до установки', async () => {
  await click($('tab-btn-main'));
  assert.match($('upd-version').textContent, /0\.2\.0/);
  assert.equal($('upd-install-btn').classList.contains('hidden'), true, 'пока ничего не найдено, кнопки установки нет');

  be.updateOutcome = { kind: 'available', info: { version: '0.3.0', current: '0.2.0', notes: '<img src=x onerror=alert(1)> что нового', date: '2026-10-22' } };
  await click($('upd-check-btn'));
  assert.match($('upd-status').textContent, /Доступна версия 0\.3\.0/);
  assert.equal($('upd-install-btn').classList.contains('hidden'), false);
  assert.ok($('upd-notes').textContent.includes('<img src=x'), 'changelog показан буквально');
  assert.equal($('upd-notes').querySelector('img'), null, 'HTML из changelog не разобран (нет XSS)');

  be.calls.length = 0;
  await click($('upd-install-btn'));
  assert.deepEqual(be.calls.map(([c]) => c).filter((c) => ['download_update', 'install_update'].includes(c)), ['download_update', 'install_update'], 'сначала скачивание и проверка, потом установка');
  assert.equal($('upd-progress').value, 25, 'прогресс 50/200');
});

test('обновление: ошибка скачивания не доходит до установки', async () => {
  be.downloadFails = true;
  be.calls.length = 0;
  await click($('upd-install-btn'));
  assert.equal(called('install_update').length, 0, 'без скачанного и проверенного пакета ставить нельзя');
  assert.match($('msg').textContent, /подпись не совпала/);
  assert.equal($('msg').className, 'msg err');
  assert.equal($('upd-install-btn').disabled, false, 'после ошибки можно повторить');
  be.downloadFails = false;
});

test('обновления выключены или не поддерживаются: кнопки установки нет, причина видна', async () => {
  be.updateOutcome = { kind: 'disabled' };
  await click($('upd-check-btn'));
  assert.match($('upd-status').textContent, /не задан ключ/);
  assert.equal($('upd-install-btn').classList.contains('hidden'), true);
  be.updateOutcome = { kind: 'unsupported', reason: 'Нужна сборка AppImage.' };
  await click($('upd-check-btn'));
  assert.equal($('upd-status').textContent, 'Нужна сборка AppImage.');
  assert.equal($('upd-install-btn').classList.contains('hidden'), true);
});

test('ошибка проверки (зеркала недоступны) показана, не ломает экран', async () => {
  const orig = window.__TAURI__.core.invoke;
  window.__TAURI__.core.invoke = async (cmd, args) => { if (cmd === 'check_update') throw new Error('нет сети'); return orig(cmd, args); };
  await click($('upd-check-btn'));
  assert.match($('upd-status').textContent, /Не удалось проверить обновления: Error: нет сети|нет сети/);
  assert.equal($('upd-check-btn').disabled, false);
  window.__TAURI__.core.invoke = orig;
});

test('helper старее приложения: появляется кнопка обновления, после неё скрывается', async () => {
  be.helper = { running: true, version: '0.1.0' }; // приложение 0.2.0
  be.connection = null;
  await click($('tab-btn-main'));
  await click($('main-btn')); // подключение гасит/запускает refresh; нужен свежий overview
  await click($('main-btn'));
  assert.equal($('helper-upd').classList.contains('hidden'), false);
  be.calls.length = 0;
  await click($('helper-upd-btn'));
  assert.equal(called('install_helper').length, 1);
  assert.match($('msg').textContent, /Helper обновлён/);
});

test('helper той же версии: кнопки обновления нет', async () => {
  be.helper = { running: true, version: '0.2.0' };
  await click($('latency-btn')); // любое действие перечитывает overview
  await click($('tab-btn-main'));
  assert.equal($('helper-upd').classList.contains('hidden'), true);
});

test('обновление сервера: проверка версии, подтверждение, обновление, статус «актуально»', async () => {
  await click($('tab-btn-server'));
  await type('s-host', '203.0.113.5');
  await type('s-pass', 'pw');
  await click($('probe-btn'));
  $('trust').checked = true;
  $('trust').dispatchEvent(new window.Event('change', { bubbles: true }));
  assert.equal($('su-check-btn').disabled, false);
  assert.equal($('su-update-btn').classList.contains('hidden'), true, 'до проверки версии обновлять нечего');

  await click($('su-check-btn'));
  const sent = called('server_update_status').at(-1)[1].conn;
  assert.equal(sent.host, '203.0.113.5');
  assert.equal(sent.password, 'pw');
  assert.match($('su-status').textContent, /1\.0\.0.*1\.14\.3/);
  assert.equal($('su-update-btn').classList.contains('hidden'), false);

  let asked = 0;
  window.confirm = () => { asked++; return false; };
  await click($('su-update-btn'));
  assert.equal(asked, 1);
  assert.equal(called('update_server').length, 0, 'отказ в подтверждении: сервер не трогаем');

  window.confirm = () => true;
  await click($('su-update-btn'));
  assert.equal(called('update_server').length, 1);
  assert.match($('s-msg').textContent, /Готово: sing-box 1\.14\.3/);
  assert.match($('su-status').textContent, /актуальна/);
  assert.equal($('su-update-btn').classList.contains('hidden'), true);
});

test('смена адреса сбрасывает статус обновления сервера', async () => {
  be.srv = { installed: '1.0.0', bundled: '1.14.3', status: 'outdated' };
  await click($('su-check-btn'));
  assert.equal($('su-update-btn').classList.contains('hidden'), false);
  await type('s-host', '198.51.100.9');
  assert.equal($('su-status').textContent, '');
  assert.equal($('su-update-btn').classList.contains('hidden'), true);
  assert.equal($('su-check-btn').disabled, true, 'новый адрес: ключ хоста не проверен');
});

test('обновление из файла: пустые пути не вызывают команду, ошибка подписи показана, успех сообщён', async () => {
  const before = called('import_update').length;
  await click($('upd-file-btn'));
  assert.equal(called('import_update').length, before, 'без путей команда не вызывается');
  assert.match($('msg').textContent, /Укажи путь/);
  await type('upd-file', '/tmp/Eleutheria.AppImage');
  await type('upd-sig', '/tmp/Eleutheria.AppImage.sig');
  be.importFails = true;
  await click($('upd-file-btn'));
  assert.match($('msg').textContent, /Обновить из файла не удалось.*подпись не совпадает/);
  assert.equal($('msg').className, 'msg err');
  be.importFails = false;
  await click($('upd-file-btn'));
  assert.deepEqual(called('import_update').at(-1)[1], { file: '/tmp/Eleutheria.AppImage', sig: '/tmp/Eleutheria.AppImage.sig' });
  assert.match($('msg').textContent, /0\.2\.0 проверен и установлен/);
  assert.equal($('upd-file-btn').disabled, false);
});
