// Блок «Нет сервера?»: партнёрские хостинги. Список и открытие ссылок берутся из eleutheria-app::partners,
// интерфейс открывает только id из этого списка.

const invoke = (cmd, args) => window.__TAURI__.core.invoke(cmd, args);
const $ = (id) => document.getElementById(id);

/** Загружает список и выводит кнопки «Открыть …». `say(text, isErr)` показывает ошибки. */
export async function initPartners(say) {
  const list = $('partners-list');
  let items;
  try {
    items = await invoke('partners_list');
  } catch (e) {
    say(`Не удалось загрузить список хостингов: ${e}`, true);
    return;
  }
  list.replaceChildren();
  for (const p of items) {
    const b = document.createElement('button');
    b.className = 'small';
    b.textContent = `${p.name} ↗`;
    b.title = 'Откроется в браузере';
    b.addEventListener('click', async () => {
      try {
        await invoke('open_partner', { id: p.id });
      } catch (e) {
        say(`Не удалось открыть ссылку: ${e}`, true);
      }
    });
    list.append(b);
  }
}
