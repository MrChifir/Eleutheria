// Чистая модель интерфейса: решает, что показывать, и не трогает DOM. Тестируется через `node --test`.

export const RU_LEVELS = [
  { value: 'off', label: 'Всё через VPN' },
  { value: 'minimal', label: 'Напрямую: .ru, .su, .рф и локальные' },
  { value: 'rulesets', label: 'Напрямую: российские сервисы и IP (нужны правила)' },
];

export function isConnected(ov) {
  return !!(ov && ov.connection);
}

/** Почему TUN недоступен, либо null, если доступен. */
export function tunDisabledReason(ov) {
  if (ov && ov.helper && ov.helper.running) return null;
  return 'Для системного VPN нужна служба helper: установи её кнопкой ниже (потребуются права администратора).';
}

/** Режим по умолчанию: TUN, если helper работает, иначе локальный прокси. Недоступный выбор заменяется на прокси. */
export function pickMode(ov, wanted) {
  if (wanted === 'tun' && tunDisabledReason(ov) === null) return 'tun';
  if (wanted === 'proxy') return 'proxy';
  return tunDisabledReason(ov) === null ? 'tun' : 'proxy';
}

export function statusText(ov) {
  if (!ov) return 'Загрузка…';
  const c = ov.connection;
  if (!c) return 'Отключено';
  if (c.mode === 'tun') return 'Подключено: весь трафик системы через VPN';
  return `Подключено: локальный прокси 127.0.0.1:${c.listenPort}`;
}

/** Состояние главной кнопки. */
export function buttonState(ov, busy) {
  if (busy) return { label: 'Подождите…', action: 'none', disabled: true };
  if (!ov) return { label: 'Загрузка…', action: 'none', disabled: true };
  if (isConnected(ov)) return { label: 'Отключить', action: 'disconnect', disabled: false };
  const empty = !ov.servers || ov.servers.length === 0;
  return { label: 'Подключить', action: 'connect', disabled: empty };
}

export function formatDelay(s) {
  if (s.delayMs != null) return `${s.delayMs} мс`;
  return s.error ? 'недоступен' : '—';
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
  if (r.mode === 'tun') return 'Туннель поднят.';
  if (r.delayMs != null) return `Подключено, проверка через сервер: ${r.delayMs} мс.`;
  return `Прокси поднят, но проверка через сервер не прошла (${r.warning || 'причина неизвестна'}).`;
}
