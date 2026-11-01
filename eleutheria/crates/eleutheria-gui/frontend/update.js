// Обновление приложения и helper на главной вкладке. Логика решений живёт в updatemodel.js.
import * as um from './updatemodel.js';

const invoke = (cmd, args) => window.__TAURI__.core.invoke(cmd, args);
const listen = (ev, cb) => window.__TAURI__.event.listen(ev, cb);
const $ = (id) => document.getElementById(id);

const HOUR_MS = 3600 * 1000;

/** ctx: { overview(), busy(), guarded(fn), say(text, isErr) } */
export function initUpdates(ctx) {
  let outcome = null;
  let working = false;
  let note = ''; // текст ошибки проверки

  function render() {
    const ov = ctx.overview();
    const v = um.updateView(outcome);
    $('upd-version').textContent = ov && ov.appVersion ? `Версия приложения: ${ov.appVersion}` : '';
    $('upd-status').textContent = note || v.text;
    const notes = outcome && outcome.kind === 'available' ? outcome.info.notes : null;
    $('upd-notes').textContent = notes || '';
    $('upd-notes').classList.toggle('hidden', !notes);
    $('upd-install-btn').classList.toggle('hidden', !v.canInstall);
    $('upd-install-btn').disabled = working || ctx.busy();
    $('upd-check-btn').disabled = working || ctx.busy();
    $('upd-file-btn').disabled = working || ctx.busy();
    $('helper-upd').classList.toggle('hidden', !um.helperOutdated(ov));
    $('helper-upd-btn').disabled = working || ctx.busy();
  }

  async function check(manual) {
    working = true;
    note = '';
    render();
    try {
      outcome = await invoke('check_update');
    } catch (e) {
      outcome = null;
      note = `Не удалось проверить обновления: ${e}`;
      if (manual) ctx.say(note, true);
    } finally {
      working = false;
      render();
    }
  }

  async function install() {
    working = true;
    const bar = $('upd-progress');
    bar.value = 0;
    bar.classList.remove('hidden');
    render();
    try {
      ctx.say('Скачиваю обновление…');
      await invoke('download_update'); // подпись проверяется здесь, до любых изменений в системе
      ctx.say('Пакет скачан и проверен. Устанавливаю, приложение перезапустится…');
      await invoke('install_update');
    } catch (e) {
      ctx.say(`Обновить не удалось: ${e}`, true);
    } finally {
      working = false;
      bar.classList.add('hidden');
      render();
    }
  }

  async function installFromFile() {
    const [file, sig] = [$('upd-file').value.trim(), $('upd-sig').value.trim()];
    if (!um.manualImportReady(file, sig)) {
      ctx.say('Укажи путь к файлу обновления и к файлу подписи .sig.', true);
      return;
    }
    working = true;
    render();
    try {
      ctx.say('Проверяю подпись и версию…');
      const r = await invoke('import_update', { file, sig });
      ctx.say(`Пакет ${r.version} проверен и установлен. ${r.restarting ? 'Приложение перезапустится…' : ''}`);
    } catch (e) {
      ctx.say(`Обновить из файла не удалось: ${e}`, true);
    } finally {
      working = false;
      render();
    }
  }

  async function updateHelper() {
    const ov = ctx.overview();
    if (ov && ov.connection && ov.connection.mode === 'tun' && !window.confirm('Туннель будет прерван на время обновления helper. Продолжить?')) return;
    await ctx.guarded(async () => {
      ctx.say('Обновляю helper: подтверди запрос прав администратора…');
      await invoke('install_helper');
      ctx.say('Helper обновлён.');
    });
  }

  async function autoCheck() {
    if (working || ctx.busy()) return;
    try {
      if (await invoke('update_due')) await check(false);
    } catch { /* фоновая проверка молчит */ }
  }

  listen('update-progress', (e) => {
    const pct = um.progressPercent(e.payload);
    const bar = $('upd-progress');
    if (pct === null) bar.removeAttribute('value');
    else bar.value = pct;
  });
  listen('update-warning', (e) => ctx.say(e.payload, true));
  $('upd-check-btn').addEventListener('click', () => check(true));
  $('upd-install-btn').addEventListener('click', install);
  $('upd-file-btn').addEventListener('click', installFromFile);
  $('helper-upd-btn').addEventListener('click', updateHelper);
  invoke('confirm_started')
    .then((r) => {
      const m = um.startReportMessage(r);
      if (m) ctx.say(m.text, m.isErr);
    })
    .catch(() => { /* не критично: сторож отката сработает по таймеру, если приложение и правда не стартовало */ });
  setTimeout(autoCheck, 3000);
  setInterval(autoCheck, HOUR_MS);
  render();
  return { render };
}
