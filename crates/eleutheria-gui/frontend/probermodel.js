import { t } from './i18n.js';
// Модель блока «Категории трафика»: чистые функции без DOM (проверяются в Node).

export const CLASS_TEXT = Object.fromEntries(
  ['PROTOCOL_BLOCKED', 'SERVER_IP_BLOCKED', 'EXIT_BLOCKED_BY_SITE', 'UNCLASSIFIED'].map((k) => [k, undefined]),
);
for (const k of Object.keys(CLASS_TEXT)) Object.defineProperty(CLASS_TEXT, k, { enumerable: true, get: () => t(`cls.${k}`) });

export const TUNNEL = 'canary';

export function classText(c) {
  return Object.hasOwn(CLASS_TEXT, c) ? CLASS_TEXT[c] : '';
}

/** Состояние строки: ok | warn | bad | unknown. */
export function rowState(pairs) {
  if (!pairs || pairs.length === 0) return 'unknown';
  const failed = pairs.filter((p) => p.health === 'failed').length;
  if (failed === pairs.length) return 'bad';
  if (failed > 0 || pairs.some((p) => p.health === 'suspect' || p.degraded)) return 'warn';
  return 'ok';
}

/** Короткий текст строки: что именно не так (первый отказавший путь) или лучшая задержка. */
export function rowText(pairs, state) {
  if (state === 'unknown') return t('row.nodata');
  if (state === 'ok') {
    const ms = pairs.map((p) => p.ms).filter((x) => typeof x === 'number');
    return ms.length ? t('row.okMs', { ms: Math.min(...ms) }) : t('row.ok');
  }
  const bad = pairs.find((p) => p.health === 'failed') || pairs.find((p) => p.health === 'suspect') || pairs.find((p) => p.degraded);
  if (!bad) return '';
  if (bad.health === 'failed') {
    const why = classText(bad.class);
    return t('row.failed', { server: bad.server, why: why ? ', ' + why : '' });
  }
  return bad.health === 'suspect' ? t('row.suspect', { server: bad.server }) : t('row.slow', { server: bad.server });
}

/** Строки таблицы: сначала туннель, затем категории в порядке списка. */
export function rows(categories, prober) {
  const pairs = prober ? prober.pairs : [];
  const by = (id) => pairs.filter((p) => p.category === id);
  const out = [];
  const tun = by(TUNNEL);
  if (prober) out.push({ id: TUNNEL, title: t('row.tunnel'), enabled: true, state: rowState(tun), text: rowText(tun, rowState(tun)) });
  for (const c of categories) {
    if (!c.enabled) {
      out.push({ id: c.id, title: c.title, enabled: false, state: 'unknown', text: t('row.disabled') });
      continue;
    }
    const ps = by(c.id);
    const s = rowState(ps);
    out.push({ id: c.id, title: c.title, enabled: true, state: s, text: rowText(ps, s) });
  }
  return out;
}

export function eventLine(e, tz = undefined) {
  const d = new Date(e.at * 1000);
  const hh = String(tz === 'utc' ? d.getUTCHours() : d.getHours()).padStart(2, '0');
  const mm = String(tz === 'utc' ? d.getUTCMinutes() : d.getMinutes()).padStart(2, '0');
  return `${hh}:${mm}  ${e.text}`;
}

export function eventsText(prober, limit = 8, tz = undefined) {
  if (!prober || !prober.events || prober.events.length === 0) return '';
  return prober.events.slice(-limit).map((e) => eventLine(e, tz)).join('\n');
}
