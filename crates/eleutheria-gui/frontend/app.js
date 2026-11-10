import * as m from './model.js';
import { initServer, rerender as rerenderServer } from './server.js';
import { t, initLang, setLang, toggleLang, onLangChange, hasChosen, getLang, detectLang } from './i18n.js';
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
let langReady = false; // пока не выбран язык, тур не стартует

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
    del.textContent = t('servers.delete');
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
  sel.replaceChildren(new Option(t('conn.server.auto'), ''));
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
    if (langReady) guide.maybeAutoStart(ov);
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
      say(t('msg.connecting'));
      const r = await invoke('connect', { req: m.buildConnectRequest(form()) });
      say(m.connectSummary(r));
      if (r.mode === 'proxy') await loadLatency();
    });
  } else if (action === 'disconnect') {
    await guarded(async () => {
      const was = await invoke('disconnect');
      latency = null;
      say(was ? t('msg.disconnected') : t('msg.noconn'));
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
    say(t('msg.removed', { name }));
  });
}

async function onImport() {
  const source = $('source').value;
  if (!source.trim()) return say(t('msg.importEmpty'), true);
  await guarded(async () => {
    const r = await invoke('import_servers', { source, name: $('name').value || null });
    $('source').value = '';
    $('name').value = '';
    say(t('msg.added', { list: r.added.join(', ') || t('msg.added.none') }) + (r.skipped.length ? t('msg.skipped', { n: r.skipped.length }) : ''));
  });
}

async function onInstallHelper() {
  await guarded(async () => {
    say(t('msg.helper.installing'));
    await invoke('install_helper');
    say(t('msg.helper.installed'));
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

initLang();
function fillRuLevels() {
  const keep = $('ru').value || 'minimal';
  $('ru').replaceChildren(...m.RU_LEVELS.map((l) => new Option(l.label, l.value)));
  $('ru').value = keep;
}
fillRuLevels();
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
$('latency-btn').addEventListener('click', () => guarded(async () => { say(t('msg.latency')); await loadLatency(); say(''); }));

// — язык: окно первого запуска, кнопка RU/EN, перевод всего интерфейса на лету —
const backendLang = () => invoke('set_language', { lang: getLang() }).catch(() => { /* старый бэкенд без команды */ });

onLangChange(async () => {
  await backendLang(); // сообщения бэкенда (ошибки, категории) тоже сменят язык
  fillRuLevels();
  say('');
  if (ov) render();
  rerenderServer();
  prober.loadCats();
  guide.relang();
});

$('lang-btn').addEventListener('click', toggleLang);

function chooseLanguage() {
  const overlay = $('lang-overlay');
  overlay.classList.remove('hidden');
  const pre = detectLang();
  const btns = [...overlay.querySelectorAll('[data-choose]')];
  for (const b of btns) {
    b.addEventListener('click', () => {
      setLang(b.dataset.choose);
      overlay.classList.add('hidden');
      langReady = true;
      if (ov) guide.maybeAutoStart(ov);
    });
  }
  (btns.find((b) => b.dataset.choose === pre) || btns[0]).focus();
}

if (hasChosen()) langReady = true;
else chooseLanguage();
backendLang();

refresh();
setInterval(() => { if (!busy) refresh(); }, 2500);
setInterval(() => { if (!busy && m.isConnected(ov)) loadLatency().catch(() => {}); }, 20000);
setInterval(() => { if (!busy && m.isConnected(ov)) prober.poll(); else prober.render(); }, 5000);
