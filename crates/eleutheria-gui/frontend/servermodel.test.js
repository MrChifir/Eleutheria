import test from 'node:test';
import assert from 'node:assert/strict';
import * as m from './servermodel.js';

const known = { fingerprint: 'SHA256:a', status: { kind: 'known' } };
const unknown = { fingerprint: 'SHA256:a', status: { kind: 'unknown' } };
const changed = { fingerprint: 'SHA256:new', status: { kind: 'changed', previous: 'SHA256:old' } };
const form = { host: ' 203.0.113.5 ', user: '', sshPort: '', password: 'pw', keyPath: '' };

test('ключ хоста: известный, новый, изменённый', () => {
  assert.equal(m.hostKeyView(null), null);
  assert.deepEqual([m.hostKeyView(known).tone, m.hostKeyView(known).needsConfirm], ['ok', false]);
  const u = m.hostKeyView(unknown);
  assert.equal(u.needsConfirm, true);
  assert.match(u.text, /SHA256:a/);
  const c = m.hostKeyView(changed);
  assert.equal(c.blocked, true);
  assert.match(c.text, /SHA256:old/);
  assert.match(c.text, /SHA256:new/);
});

test('продолжать можно только с известным или явно подтверждённым ключом', () => {
  assert.equal(m.keyAccepted(known, false), true);
  assert.equal(m.keyAccepted(unknown, false), false);
  assert.equal(m.keyAccepted(unknown, true), true);
  assert.equal(m.keyAccepted(changed, true), false, 'смена ключа не обходится галочкой');
  assert.equal(m.keyAccepted(null, true), false);
});

test('canRun учитывает учётные данные и сохранённый ключ', () => {
  assert.equal(m.canRun(form, unknown, true), true);
  assert.equal(m.canRun(form, unknown, false), false);
  assert.equal(m.canRun({ ...form, password: '' }, unknown, true), false);
  assert.equal(m.canRun({ ...form, password: '' }, known, false), true, 'для известного сервера хватает сохранённого ключа');
  assert.equal(m.canRun({ ...form, host: '  ' }, known, false), false);
  assert.equal(m.canRun({ ...form, password: '', keyPath: ' /k ' }, unknown, true), true);
});

test('buildConn: умолчания и доверенный fingerprint только для нового сервера', () => {
  const c = m.buildConn(form, unknown, true);
  assert.deepEqual(c, { host: '203.0.113.5', user: 'root', sshPort: 22, password: 'pw', keyPath: null, trustedFingerprint: 'SHA256:a' });
  assert.equal(m.buildConn(form, unknown, false).trustedFingerprint, null);
  assert.equal(m.buildConn(form, known, true).trustedFingerprint, null);
  assert.equal(m.buildConn(form, changed, true).trustedFingerprint, null);
  assert.equal(m.buildConn({ ...form, password: '', keyPath: ' /k ', sshPort: '2222', user: 'ubuntu' }, known, false).sshPort, 2222);
  assert.equal(m.buildConn({ ...form, password: '', keyPath: ' /k ' }, known, false).password, null);
});

test('порты', () => {
  assert.deepEqual(m.parsePort(''), { ok: true, value: null });
  assert.deepEqual(m.parsePort(' 443 '), { ok: true, value: 443 });
  for (const bad of ['0', '65536', '-1', '4x', '1e3', '443.5']) assert.equal(m.parsePort(bad).ok, false, bad);
});

test('запрос установки', () => {
  const r = m.buildProvisionRequest({ port: '', sni: ' ', profile: '', userName: '', hardenSsh: true, bbr: false, firewall: true });
  assert.deepEqual(r, { port: null, sni: null, profile: 'Eleutheria', userName: 'default', hardenSsh: true, bbr: false, firewall: true });
  assert.equal(m.buildProvisionRequest({ port: '8443', sni: 'www.apple.com', profile: 'P', userName: 'me' }).port, 8443);
  assert.throws(() => m.buildProvisionRequest({ port: '99999' }), /Порт VPN/);
});

test('пользователи: имя, удаление последнего, отметки заметок', () => {
  assert.equal(m.validUserName('anna_1-x'), true);
  for (const bad of ['', 'a b', 'я', 'a'.repeat(33), 'a;b']) assert.equal(m.validUserName(bad), false, bad);
  assert.equal(m.canRemoveUser(['a']), false);
  assert.equal(m.canRemoveUser(['a', 'b']), true);
  assert.equal(m.canRemoveUser(undefined), false);
  assert.equal(m.noteMark({ ok: true }), '✓');
  assert.equal(m.noteMark({ ok: false }), '⚠');
});
