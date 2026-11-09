import test from 'node:test';
import assert from 'node:assert/strict';
import { cmpVersion, helperOutdated, updateView, progressPercent, serverUpdateView, startReportMessage, manualImportReady } from './updatemodel.js';

test('cmpVersion: числа, пререлизы, мусор (те же случаи, что в Rust)', () => {
  assert.equal(cmpVersion('1.9.0', '1.14.3'), -1);
  assert.equal(cmpVersion('1.14.3', '1.14.3'), 0);
  assert.equal(cmpVersion('v2.0.0', '1.99.99'), 1);
  assert.equal(cmpVersion('1.14.10', '1.14.9'), 1);
  assert.equal(cmpVersion('1.13.0-rc.3', '1.13.0'), -1);
  assert.equal(cmpVersion('1.13.0-rc.10', '1.13.0-rc.9'), 1);
  assert.equal(cmpVersion('1.13.0-alpha', '1.13.0-beta'), -1);
  assert.equal(cmpVersion('1.13.0-1', '1.13.0-alpha'), -1);
  assert.equal(cmpVersion('1.13.0+b5', '1.13.0'), 0);
  for (const bad of ['', 'abc', '1.2', '1.2.3.4', null, undefined]) assert.equal(cmpVersion(bad, '1.0.0'), null, String(bad));
});

test('helperOutdated: только запущенный и старше приложения', () => {
  const ov = (running, version, appVersion = '0.2.0') => ({ helper: { running, version }, appVersion });
  assert.equal(helperOutdated(ov(true, '0.1.0')), true);
  assert.equal(helperOutdated(ov(true, '0.2.0')), false);
  assert.equal(helperOutdated(ov(true, '0.3.0')), false);
  assert.equal(helperOutdated(ov(false, null)), false);
  assert.equal(helperOutdated(ov(true, 'мусор')), false);
  assert.equal(helperOutdated(ov(true, '0.1.0', null)), false, 'версия приложения неизвестна');
  assert.equal(helperOutdated(null), false);
});

test('updateView: все исходы проверки', () => {
  assert.equal(updateView(null).canInstall, false);
  assert.match(updateView({ kind: 'disabled' }).text, /не задан ключ/);
  assert.equal(updateView({ kind: 'unsupported', reason: 'нужен AppImage' }).text, 'нужен AppImage');
  assert.equal(updateView({ kind: 'upToDate' }).canInstall, false);
  const a = updateView({ kind: 'available', info: { version: '0.2.0', current: '0.1.0', notes: 'n', date: '2026-10-22' } });
  assert.equal(a.canInstall, true);
  assert.match(a.text, /0\.2\.0.*0\.1\.0.*2026-10-22/);
  assert.doesNotMatch(updateView({ kind: 'available', info: { version: '0.2.0', current: '0.1.0', notes: null, date: null } }).text, /от /);
});

test('progressPercent: неизвестный размер, границы', () => {
  assert.equal(progressPercent({ done: 5, total: null }), null);
  assert.equal(progressPercent({ done: 5, total: 0 }), null);
  assert.equal(progressPercent({ done: 50, total: 200 }), 25);
  assert.equal(progressPercent({ done: 300, total: 200 }), 100);
  assert.equal(progressPercent(null), null);
});

test('serverUpdateView: обновлять можно только устаревший сервер', () => {
  const d = (status, installed = '1.0.0') => serverUpdateView({ status, installed, bundled: '1.14.3' });
  assert.equal(d('outdated').canUpdate, true);
  for (const s of ['upToDate', 'newer', 'notInstalled', 'unknown']) assert.equal(d(s).canUpdate, false, s);
  assert.match(d('newer', '2.0.0').text, /обнови приложение/);
  assert.equal(serverUpdateView(null).text, '');
});

test('startReportMessage: откат важнее подтверждения, пустой отчёт молчит', () => {
  assert.equal(startReportMessage(null), null);
  assert.equal(startReportMessage({ updatedTo: null, rolledBackFrom: null }), null);
  const ok = startReportMessage({ updatedTo: '0.2.0', rolledBackFrom: null });
  assert.deepEqual([ok.isErr, ok.text.includes('0.2.0')], [false, true]);
  const rb = startReportMessage({ updatedTo: '0.2.0', rolledBackFrom: '0.3.0' });
  assert.deepEqual([rb.isErr, rb.text.includes('0.3.0'), rb.text.includes('вернули')], [true, true, true]);
});

test('manualImportReady: нужны оба пути', () => {
  assert.equal(manualImportReady('a.AppImage', 'a.AppImage.sig'), true);
  assert.equal(manualImportReady('a.AppImage', ''), false);
  assert.equal(manualImportReady('  ', 'x.sig'), false);
  assert.equal(manualImportReady('""', 'x.sig'), false);
  assert.equal(manualImportReady(null, undefined), false);
});
