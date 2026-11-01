import * as m from './model.js';
import { initServer } from './server.js';
import { initUpdates } from './update.js';
import { initProber } from './prober.js';
import { initNavPill } from './fx.js';
import { initSelects } from './ui.js';
import { initGuide } from './guide.js';

const invoke = (cmd, args) => window.__TAURI__.core.invoke(cmd, args);
const $ = (id) => document.getElementById(id);

let ov = null;
let latency = null; // { route, servers }
let busy = false;
let userMode; // выбор пользователя; undefined = по умолчанию

function say(text, isErr = false) {
  const el = $('msg');
  el.textContent = text || '';
  el.className = isErr ? 'msg err' : 'msg';
}

function form() {
  return { mode: $('mode').value, server: $('server').value, ruDirect: $('ru').value };
}

function renderServers() {
  const ul = $('servers');
  ul.replaceChildren();
  const live = new Map((latency ? latency.servers : []).map((s) => [s.name, s]));
  for (const s of ov.servers) {
    const li = document.createElement('li');
    const name = document.createElement('span');
    const l = live.get(s.name);
    name.className = 'name' + (l && l.active ? ' active' : '');
    name.textContent = s.name;
    name.title = `${s.host}:${s.port} (${s.kind && s.kind !== 'vless' ? s.kind : s.security})`;
    const delay = document.createElement('span');
    delay.className = 'delay';
    delay.textContent = l ? m.formatDelay(l) : '';
    const del = document.createElement('button');
    del.className = 'danger';
    del.textContent = 'Удалить';
    del.disabled = busy;
    del.addEventListener('click', () => removeServer(s.name));
    li.append(name, delay, del);
    ul.append(li);
  }
  $('empty').classList.toggle('hidden', ov.servers.length > 0);
}

function renderServerSelect() {
  const sel = $('server');
  const keep = sel.value;
  sel.replaceChildren(new Option('Авто (по задержке)', ''));
  for (const s of ov.servers) sel.append(new Option(s.name, s.name));
  sel.value = ov.servers.some((s) => s.name === keep) ? keep : '';
}

function render() {
  if (!ov) return;
  const on = m.isConnected(ov);
  $('dot').className = 'dot ' + (on ? 'on' : 'off');
  $('status').textContent = m.statusText(ov);
  $('side-dot').className = 'dot ' + (on ? 'on' : 'off');
  $('side-status').textContent = m.statusText(ov);
  $('sub').textContent = on ? `pid ${ov.connection.pid}` : '';

  const b = m.buttonState(ov, busy);
  const btn = $('main-btn');
  btn.textContent = b.label;
  btn.disabled = b.disabled;
  btn.dataset.action = b.action;

  const reason = m.tunDisabledReason(ov);
  const modeSel = $('mode');
  modeSel.querySelector('option[value="tun"]').disabled = reason !== null;
  modeSel.value = m.pickMode(ov, userMode);
  modeSel.disabled = on || busy;
  $('server').disabled = on || busy;
  $('ru').disabled = on || busy;
  $('tun-hint').textContent = reason || '';
  $('tun-hint').classList.toggle('hidden', reason === null);
  $('helper-btn').classList.toggle('hidden', reason === null);
  $('helper-btn').disabled = busy;

  renderServerSelect();
  renderServers();
  $('latency-btn').disabled = !on || busy;
  updates.render();
}

async function refresh() {
  try {
    ov = await invoke('overview');
    if (!m.isConnected(ov)) latency = null;
    render();
    guide.maybeAutoStart(ov);
  } catch (e) {
    say(String(e), true);
  }
}

async function guarded(fn) {
  if (busy) return;
  busy = true;
  render();
  try {
    await fn();
  } catch (e) {
    say(String(e), true);
  } finally {
    busy = false;
    await refresh();
  }
}

async function onMain() {
  const action = $('main-btn').dataset.action;
  if (action === 'connect') {
    await guarded(async () => {
      say('Подключаюсь…');
      const r = await invoke('connect', { req: m.buildConnectRequest(form()) });
      say(m.connectSummary(r));
      if (r.mode === 'proxy') await loadLatency();
    });
  } else if (action === 'disconnect') {
    await guarded(async () => {
      const was = await invoke('disconnect');
      latency = null;
      say(was ? 'Отключено.' : 'Подключения не было.');
    });
  }
}

async function loadLatency() {
  latency = await invoke('latency');
  render();
}

async function removeServer(name) {
  await guarded(async () => {
    await invoke('remove_server', { name });
    say(`Удалён: ${name}`);
  });
}

async function onImport() {
  const source = $('source').value;
  if (!source.trim()) return say('Вставь ссылку vless:// или URL подписки.', true);
  await guarded(async () => {
    const r = await invoke('import_servers', { source, name: $('name').value || null });
    $('source').value = '';
    $('name').value = '';
    say(`Добавлено: ${r.added.join(', ') || 'ничего'}${r.skipped.length ? `; пропущено: ${r.skipped.length}` : ''}`);
  });
}

async function onInstallHelper() {
  await guarded(async () => {
    say('Устанавливаю helper: подтверди запрос прав администратора…');
    await invoke('install_helper');
    say('Helper установлен.');
  });
}

const TABS = ['main', 'server', 'updates', 'guide'];
let navPill = null;

function showTab(name) {
  for (const t of TABS) {
    $(`tab-${t}`).classList.toggle('hidden', t !== name);
    $(`tab-btn-${t}`).classList.toggle('active', t === name);
  }
  if (navPill) navPill.sync();
}

for (const l of m.RU_LEVELS) $('ru').append(new Option(l.label, l.value));
$('ru').value = 'minimal';
$('mode').addEventListener('change', () => { userMode = $('mode').value; });
$('main-btn').addEventListener('click', onMain);
$('helper-btn').addEventListener('click', onInstallHelper);
for (const t of TABS) $(`tab-btn-${t}`).addEventListener('click', () => showTab(t));
initServer();
initSelects();
navPill = initNavPill(document.querySelector('.nav'));
navPill.sync();
const guide = initGuide({ showTab });
const updates = initUpdates({ overview: () => ov, busy: () => busy, guarded, say });
const prober = initProber({ overview: () => ov, busy: () => busy, say });
$('import-btn').addEventListener('click', onImport);
$('latency-btn').addEventListener('click', () => guarded(async () => { say('Измеряю задержки…'); await loadLatency(); say(''); }));

refresh();
setInterval(() => { if (!busy) refresh(); }, 2500);
setInterval(() => { if (!busy && m.isConnected(ov)) loadLatency().catch(() => {}); }, 20000);
setInterval(() => { if (!busy && m.isConnected(ov)) prober.poll(); else prober.render(); }, 5000);
