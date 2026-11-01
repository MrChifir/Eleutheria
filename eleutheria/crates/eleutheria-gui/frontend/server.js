import * as sm from './servermodel.js';
import * as um from './updatemodel.js';
import { initPartners } from './partners.js';

const invoke = (cmd, args) => window.__TAURI__.core.invoke(cmd, args);
const listen = (ev, cb) => window.__TAURI__.event.listen(ev, cb);
const $ = (id) => document.getElementById(id);

let probe = null;
let busy = false;
let users = null; // { users, links }
let srvUpdate = null; // ответ server_update_status / update_server

function say(text, isErr = false) {
  $('s-msg').textContent = text || '';
  $('s-msg').className = isErr ? 'msg err' : 'msg';
}

function form() {
  return { host: $('s-host').value, user: $('s-user').value, sshPort: $('s-sshport').value, password: $('s-pass').value, keyPath: $('s-key').value };
}

function logLine(text) {
  const el = $('log');
  el.classList.remove('hidden');
  el.textContent += `• ${text}\n`;
  el.scrollTop = el.scrollHeight;
}

function ready() {
  return sm.canRun(form(), probe, $('trust').checked);
}

function render() {
  const v = sm.hostKeyView(probe);
  const box = $('hostkey');
  box.classList.toggle('hidden', !v);
  if (v) {
    box.className = `hostkey ${v.tone}`;
    box.textContent = v.text;
  }
  $('trust-row').classList.toggle('hidden', !(v && v.needsConfirm));
  const ok = ready() && !busy;
  $('provision-btn').disabled = !ok;
  $('users-btn').disabled = !ok;
  $('add-user-btn').disabled = !ok || !users;
  $('probe-btn').disabled = busy || !sm.canProbe(form());
  $('su-check-btn').disabled = !ok;
  const su = um.serverUpdateView(srvUpdate);
  $('su-status').textContent = su.text;
  $('su-update-btn').classList.toggle('hidden', !su.canUpdate);
  $('su-update-btn').disabled = !ok;
  renderUsers();
  renderProtocols();
}

function renderProtocols() {
  const ul = $('protocols');
  ul.replaceChildren();
  if (!users) return;
  for (const row of sm.protocolRows(users.protocols)) {
    const li = document.createElement('li');
    li.className = 'line';
    const n = document.createElement('span');
    n.className = 'name';
    n.textContent = `${row.label}${row.on ? ' · включён' : ''}`;
    n.title = row.hint;
    const btn = document.createElement('button');
    btn.className = row.on ? 'small danger' : 'small';
    btn.textContent = row.on ? 'Выключить' : 'Включить';
    btn.disabled = busy || !ready();
    btn.addEventListener('click', () => setProtocol(row.id, row.action));
    li.append(n, btn);
    ul.append(li);
  }
}

async function setProtocol(id, action) {
  await guarded(async () => {
    $('log').textContent = '';
    say(action === 'enable' ? 'Включаю протокол на сервере…' : 'Выключаю протокол на сервере…');
    users = await invoke('set_protocols', {
      conn: sm.buildConn(form(), probe, $('trust').checked),
      enable: action === 'enable' ? [id] : [],
      disable: action === 'disable' ? [id] : [],
    });
    say(action === 'enable' ? 'Протокол включён. Ссылки пользователей обновлены, сервер добавлен в список клиента.' : 'Протокол выключен.');
  });
}

function renderUsers() {
  const ul = $('users');
  ul.replaceChildren();
  if (!users) return;
  const removable = sm.canRemoveUser(users.users);
  for (const name of users.users) {
    const li = document.createElement('li');
    li.className = 'col';
    const line = document.createElement('div');
    line.className = 'line';
    const n = document.createElement('span');
    n.className = 'name';
    n.textContent = name;
    const linkBtn = document.createElement('button');
    linkBtn.className = 'small';
    linkBtn.textContent = 'Ссылка';
    const del = document.createElement('button');
    del.className = 'danger';
    del.textContent = 'Удалить';
    del.disabled = busy || !removable;
    del.title = removable ? '' : 'Нельзя удалить последнего пользователя';
    del.addEventListener('click', () => removeUser(name));
    line.append(n, linkBtn, del);
    li.append(line);
    // ссылка содержит UUID: на экране появляется только по нажатию
    linkBtn.addEventListener('click', () => {
      const old = li.querySelector('.linkbox');
      if (old) return old.remove();
      const box = document.createElement('div');
      box.className = 'linkbox';
      for (const l of sm.linksForUser(users.links, name)) {
        const t = document.createElement('div');
        t.className = 'muted';
        t.textContent = sm.protoLabel(l.proto);
        box.append(t, linkRow(l.link || '', l.qrSvg));
      }
      li.append(box);
    });
    ul.append(li);
  }
}

/** SVG показывается как картинка (data URL): скрипты внутри <img> не выполняются, innerHTML не используется. */
export function qrImage(svg) {
  const img = document.createElement('img');
  img.className = 'qr';
  img.alt = 'QR-код ссылки';
  img.src = `data:image/svg+xml;charset=utf-8,${encodeURIComponent(svg)}`;
  return img;
}

function linkRow(link, qrSvg) {
  const wrap = document.createElement('div');
  wrap.className = 'linkwrap';
  const row = document.createElement('div');
  row.className = 'linkrow';
  const input = document.createElement('input');
  input.readOnly = true;
  input.value = link;
  input.addEventListener('focus', () => input.select());
  const copy = document.createElement('button');
  copy.className = 'small';
  copy.textContent = 'Копировать';
  copy.addEventListener('click', async () => {
    try {
      await navigator.clipboard.writeText(link);
      copy.textContent = 'Скопировано';
    } catch {
      input.select();
      copy.textContent = 'Выдели и скопируй';
    }
  });
  row.append(input, copy);
  wrap.append(row);
  if (qrSvg) wrap.append(qrImage(qrSvg));
  return wrap;
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
    render();
  }
}

async function onProbe() {
  probe = null;
  $('trust').checked = false;
  await guarded(async () => {
    say('Проверяю ключ сервера…');
    const port = sm.parsePort($('s-sshport').value);
    if (!port.ok) throw new Error('Порт SSH: число от 1 до 65535');
    probe = await invoke('probe_host_key', { host: $('s-host').value.trim(), port: port.value || 22 });
    say('');
  });
}

async function onProvision() {
  await guarded(async () => {
    const req = sm.buildProvisionRequest({
      port: $('p-port').value, sni: $('p-sni').value, profile: $('p-profile').value, userName: $('p-user').value,
      hardenSsh: $('p-harden').checked, bbr: $('p-bbr').checked, firewall: $('p-fw').checked,
      protocols: sm.PROTOCOLS.map((p) => p.id).filter((id) => $(`p-proto-${id}`).checked),
    });
    $('log').textContent = '';
    $('result').classList.add('hidden');
    say('Установка идёт, это займёт несколько минут. Не закрывай окно.');
    const r = await invoke('provision', { conn: sm.buildConn(form(), probe, $('trust').checked), req });
    $('s-pass').value = ''; // пароль больше не нужен: дальше вход по сохранённому ключу
    // ключ хоста теперь сохранён: обновляем проверку, иначе без пароля кнопки «Пользователи» остались бы заблокированы
    try {
      probe = await invoke('probe_host_key', { host: $('s-host').value.trim(), port: sm.parsePort($('s-sshport').value).value || 22 });
      $('trust').checked = false;
    } catch { /* не критично: можно нажать «Проверить сервер» вручную */ }
    showResult(r);
    say(r.savedAs ? `Готово. Сервер добавлен в список клиента как «${r.savedAs}».` : 'Готово.');
  });
}

function showResult(r) {
  const box = $('result');
  box.replaceChildren();
  const ul = document.createElement('ul');
  ul.className = 'notes';
  for (const n of r.notes) {
    const li = document.createElement('li');
    li.textContent = `${sm.noteMark(n)} ${n.text}`;
    ul.append(li);
  }
  box.append(ul);
  for (const l of r.links) {
    const t = document.createElement('div');
    t.className = 'muted';
    t.textContent = `${sm.protoLabel(l.proto)}: ссылка для «${l.name}» (Happ, Hiddify, v2rayN, sing-box…):`;
    box.append(t, linkRow(l.link, l.qrSvg));
  }
  box.classList.remove('hidden');
}

async function checkServerVersion() {
  await guarded(async () => {
    say('Проверяю версию сервера…');
    srvUpdate = await invoke('server_update_status', { conn: sm.buildConn(form(), probe, $('trust').checked) });
    say('');
  });
}

async function updateServer() {
  if (!window.confirm('Обновить sing-box на сервере? VPN прервётся на несколько секунд. Если новая версия не запустится, вернётся прежняя.')) return;
  await guarded(async () => {
    $('log').textContent = '';
    say('Обновляю сервер, не закрывай окно…');
    srvUpdate = await invoke('update_server', { conn: sm.buildConn(form(), probe, $('trust').checked) });
    say(`Готово: sing-box ${srvUpdate.installed} на сервере.`);
  });
}

async function loadUsers() {
  await guarded(async () => {
    say('Загружаю пользователей…');
    users = await invoke('list_users', { conn: sm.buildConn(form(), probe, $('trust').checked) });
    say('');
  });
}

async function addUser() {
  const name = $('new-user').value.trim();
  if (!sm.validUserName(name)) return say('Имя: латиница, цифры, _ и -, до 32 символов.', true);
  await guarded(async () => {
    say('Добавляю пользователя…');
    users = await invoke('add_user', { conn: sm.buildConn(form(), probe, $('trust').checked), name });
    $('new-user').value = '';
    say(`Пользователь «${name}» добавлен.`);
  });
}

async function removeUser(name) {
  if (!window.confirm(`Удалить «${name}»? Его ссылка перестанет работать.`)) return;
  await guarded(async () => {
    say('Удаляю пользователя…');
    users = await invoke('remove_user', { conn: sm.buildConn(form(), probe, $('trust').checked), name });
    say(`Пользователь «${name}» удалён.`);
  });
}

export function initServer() {
  listen('progress', (e) => logLine(String(e.payload)));
  initPartners(say);
  $('probe-btn').addEventListener('click', onProbe);
  $('provision-btn').addEventListener('click', onProvision);
  $('users-btn').addEventListener('click', loadUsers);
  $('su-check-btn').addEventListener('click', checkServerVersion);
  $('su-update-btn').addEventListener('click', updateServer);
  $('add-user-btn').addEventListener('click', addUser);
  for (const id of ['s-host', 's-user', 's-sshport', 's-pass', 's-key', 'trust']) {
    $(id).addEventListener('input', render);
    $(id).addEventListener('change', render);
  }
  // смена адреса или порта делает прежнюю проверку ключа недействительной
  for (const id of ['s-host', 's-sshport']) {
    $(id).addEventListener('input', () => {
      probe = null;
      users = null;
      srvUpdate = null;
      $('trust').checked = false;
      render();
    });
  }
  render();
}
