import { t } from './i18n.js';
// Чистая модель интерфейса: решает, что показывать, и не трогает DOM. Тестируется через `node --test`.

export const RU_LEVELS = ['off', 'minimal', 'rulesets'].map((value) => ({ value, get label() { return t(`ru.${value}`); } }));

export function isConnected(ov) {
  return !!(ov && ov.connection);
}

/** Почему TUN недоступен, либо null, если доступен. */
export function tunDisabledReason(ov) {
  if (ov && ov.helper && ov.helper.running) return null;
  return t('tun.reason');
}

/** Режим по умолчанию: TUN, если helper работает, иначе локальный прокси. Недоступный выбор заменяется на прокси. */
export function pickMode(ov, wanted) {
  if (wanted === 'tun' && tunDisabledReason(ov) === null) return 'tun';
  if (wanted === 'proxy') return 'proxy';
  return tunDisabledReason(ov) === null ? 'tun' : 'proxy';
}

export function statusText(ov) {
  if (!ov) return t('loading');
  const c = ov.connection;
  if (!c) return t('status.off');
  if (c.mode === 'tun') return t('status.tun');
  return t('status.proxy', { port: c.listenPort });
}

/** Состояние главной кнопки. */
export function buttonState(ov, busy) {
  if (busy) return { label: t('btn.wait'), action: 'none', disabled: true };
  if (!ov) return { label: t('loading'), action: 'none', disabled: true };
  if (isConnected(ov)) return { label: t('btn.disconnect'), action: 'disconnect', disabled: false };
  const empty = !ov.servers || ov.servers.length === 0;
  return { label: t('btn.connect'), action: 'connect', disabled: empty };
}

export function formatDelay(s) {
  if (s.delayMs != null) return t('delay.ms', { ms: s.delayMs });
  return s.error ? t('delay.unavailable') : '—';
}

/** Рабочие по возрастанию задержки, затем недоступные; активный не теряется. */
export function sortLatency(servers) {
  return [...servers].sort((a, b) => {
    const ax = a.delayMs == null ? Infinity : a.delayMs;
    const bx = b.delayMs == null ? Infinity : b.delayMs;
    return ax - bx || a.name.localeCompare(b.name);
  });
}

/** Запрос на подключение из состояния формы. server = '' означает «авто». */
export function buildConnectRequest(form) {
  return { mode: form.mode, server: form.server ? form.server : null, ruDirect: form.ruDirect };
}

/** Текст итога подключения. */
export function connectSummary(r) {
  if (r.mode === 'tun') return t('connect.tun');
  if (r.delayMs != null) return t('connect.ok', { ms: r.delayMs });
  return t('connect.warn', { why: r.warning || t('connect.unknown') });
}
