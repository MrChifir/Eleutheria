// Блок «Категории трафика» на главной вкладке. Решения и тексты живут в probermodel.js.
import * as pm from './probermodel.js';

const invoke = (cmd, args) => window.__TAURI__.core.invoke(cmd, args);
const $ = (id) => document.getElementById(id);

/** ctx: { overview(), busy(), say(text, isErr) } */
export function initProber(ctx) {
  let cats = [];
  let prober = null;

  function render() {
    const ul = $('cats');
    ul.replaceChildren();
    const connected = !!(ctx.overview() && ctx.overview().connection);
    for (const r of pm.rows(cats, connected ? prober : null)) {
      const li = document.createElement('li');
      li.className = 'cat-row';
      const dot = document.createElement('span');
      dot.className = `dot ${r.state === 'ok' ? 'on' : r.state === 'unknown' ? 'off' : r.state}`;
      const name = document.createElement('span');
      name.className = 'name';
      name.textContent = r.title;
      const text = document.createElement('span');
      text.className = 'delay';
      text.textContent = r.text;
      li.append(dot, name, text);
      if (r.id !== pm.TUNNEL) {
        const lab = document.createElement('label');
        lab.className = 'check';
        const cb = document.createElement('input');
        cb.type = 'checkbox';
        cb.checked = r.enabled;
        cb.disabled = ctx.busy();
        cb.addEventListener('change', () => toggle(r.id, cb.checked));
        lab.append(cb);
        li.append(lab);
      }
      ul.append(li);
    }
    const ev = pm.eventsText(connected ? prober : null);
    $('prober-events').textContent = ev;
    $('prober-events').classList.toggle('hidden', !ev);
    $('cats-hint').classList.toggle('hidden', !(ctx.overview() && ctx.overview().connection));
  }

  async function toggle(id, enabled) {
    try {
      await invoke('set_category', { id, enabled });
      ctx.say('Изменение категории вступит в силу при следующем подключении.');
    } catch (e) {
      ctx.say(String(e), true);
    }
    await loadCats();
  }

  async function loadCats() {
    try {
      cats = await invoke('categories_list');
    } catch (_) {
      cats = [];
    }
    render();
  }

  async function poll() {
    try {
      prober = await invoke('prober_status');
    } catch (_) {
      prober = null;
    }
    render();
  }

  loadCats();
  return { render, poll, loadCats };
}
