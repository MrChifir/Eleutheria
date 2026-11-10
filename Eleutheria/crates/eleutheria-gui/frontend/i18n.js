// Локализация интерфейса: русский и английский, переключение без перезапуска.
// Словари лежат в locales.js. Выбор языка хранится в localStorage; пока пользователь не выбрал, действует русский,
// а при первом запуске app.js показывает окно выбора языка.
import { DICT } from './locales.js';

export const LANGS = ['ru', 'en'];
export const LANG_KEY = 'eleutheria.lang.v1';

let lang = 'ru';
const subs = new Set();

function readStored() {
  try {
    const v = window.localStorage.getItem(LANG_KEY);
    return LANGS.includes(v) ? v : null;
  } catch (_) {
    return null;
  }
}

/** Язык системы для предварительного выбора в окне первого запуска. */
export function detectLang() {
  const n = typeof navigator !== 'undefined' && navigator.language ? navigator.language : '';
  return /^ru\b/i.test(n) ? 'ru' : 'en';
}

export function hasChosen() {
  return readStored() !== null;
}

export function getLang() {
  return lang;
}

/** Значение по ключу: строка или массив. Нет перевода — берём русский, иначе сам ключ. */
export function tl(key) {
  const v = DICT[lang] && DICT[lang][key];
  if (v !== undefined) return v;
  const r = DICT.ru[key];
  return r !== undefined ? r : key;
}

/** Строка по ключу с подстановкой {name}. */
export function t(key, params) {
  const v = tl(key);
  if (typeof v !== 'string' || !params) return v;
  return v.replace(/\{(\w+)\}/g, (m, k) => (params[k] !== undefined && params[k] !== null ? String(params[k]) : m));
}

/** Переводит разметку: data-i18n (текст), data-i18n-ph (placeholder), data-i18n-title, data-i18n-aria. */
export function applyStatic(root = document) {
  if (!root || !root.querySelectorAll) return;
  for (const el of root.querySelectorAll('[data-i18n]')) el.textContent = t(el.dataset.i18n);
  for (const el of root.querySelectorAll('[data-i18n-ph]')) el.setAttribute('placeholder', t(el.dataset.i18nPh));
  for (const el of root.querySelectorAll('[data-i18n-title]')) el.setAttribute('title', t(el.dataset.i18nTitle));
  for (const el of root.querySelectorAll('[data-i18n-aria]')) el.setAttribute('aria-label', t(el.dataset.i18nAria));
  for (const el of root.querySelectorAll('[data-lang-btn]')) el.classList.toggle('active', el.dataset.langBtn === lang);
}

/** Подписка на смену языка; возвращает функцию отписки. */
export function onLangChange(cb) {
  subs.add(cb);
  return () => subs.delete(cb);
}

/** Меняет язык, запоминает выбор, переводит разметку и сообщает подписчикам. */
export function setLang(next, { persist = true } = {}) {
  if (!LANGS.includes(next)) return;
  lang = next;
  if (persist) {
    try { window.localStorage.setItem(LANG_KEY, next); } catch (_) { /* хранилище недоступно: выбор не запомнится */ }
  }
  if (typeof document !== 'undefined') {
    document.documentElement.lang = next;
    applyStatic(document);
  }
  for (const cb of [...subs]) cb(next);
}

/** Начальный язык: сохранённый выбор, иначе русский. */
export function initLang() {
  lang = readStored() || 'ru';
  if (typeof document !== 'undefined') {
    document.documentElement.lang = lang;
    applyStatic(document);
  }
  return lang;
}

export function toggleLang() {
  setLang(lang === 'ru' ? 'en' : 'ru');
}
