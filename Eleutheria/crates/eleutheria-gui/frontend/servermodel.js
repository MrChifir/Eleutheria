import { t } from './i18n.js';
// Чистая модель мастера «Сервер»: проверки, сборка запросов, тексты. Тестируется через `node --test`.

/** Как показать результат проверки ключа сервера. */
export function hostKeyView(probe) {
  if (!probe) return null;
  const k = probe.status.kind;
  if (k === 'known') {
    return { tone: 'ok', needsConfirm: false, blocked: false, text: t('hk.known') };
  }
  if (k === 'unknown') {
    return {
      tone: 'warn', needsConfirm: true, blocked: false,
      text: t('hk.unknown', { fp: probe.fingerprint }),
    };
  }
  return {
    tone: 'bad', needsConfirm: false, blocked: true,
    text: t('hk.changed', { prev: probe.status.previous, fp: probe.fingerprint }),
  };
}

export function hasCredentials(form, hasSavedKey = false) {
  return !!((form.password && form.password.length) || (form.keyPath && form.keyPath.trim()) || hasSavedKey);
}

export function canProbe(form) {
  return !!(form.host && form.host.trim());
}

/** Можно ли продолжать после проверки ключа: известный ключ или явно подтверждённый новый. */
export function keyAccepted(probe, confirmed) {
  const v = hostKeyView(probe);
  if (!v || v.blocked) return false;
  return v.needsConfirm ? !!confirmed : true;
}

export function canRun(form, probe, confirmed) {
  return canProbe(form) && keyAccepted(probe, confirmed) && hasCredentials(form, probe && probe.status.kind === 'known');
}

/** SshConn для backend. Подтверждённый fingerprint передаётся только для незнакомого сервера. */
export function buildConn(form, probe, confirmed) {
  const trust = probe && probe.status.kind === 'unknown' && confirmed ? probe.fingerprint : null;
  const port = parsePort(form.sshPort);
  return {
    host: form.host.trim(),
    user: (form.user || 'root').trim(),
    sshPort: port.ok && port.value ? port.value : 22,
    password: form.password ? form.password : null,
    keyPath: form.keyPath && form.keyPath.trim() ? form.keyPath.trim() : null,
    trustedFingerprint: trust,
  };
}

/** Пустая строка = значение по умолчанию (value: null). */
export function parsePort(text) {
  const t = (text ?? '').toString().trim();
  if (t === '') return { ok: true, value: null };
  if (!/^\d{1,5}$/.test(t)) return { ok: false, value: null };
  const n = Number(t);
  return n >= 1 && n <= 65535 ? { ok: true, value: n } : { ok: false, value: null };
}

export function buildProvisionRequest(o) {
  const port = parsePort(o.port);
  if (!port.ok) throw new Error(t('err.vpnPort'));
  return {
    port: port.value,
    sni: o.sni && o.sni.trim() ? o.sni.trim() : null,
    profile: o.profile && o.profile.trim() ? o.profile.trim() : 'Eleutheria',
    userName: o.userName && o.userName.trim() ? o.userName.trim() : 'default',
    hardenSsh: !!o.hardenSsh,
    bbr: !!o.bbr,
    firewall: !!o.firewall,
    protocols: Array.isArray(o.protocols) ? o.protocols.filter((x) => PROTOCOLS.some((p) => p.id === x)) : [],
  };
}

/** Дополнительные протоколы сервера (VLESS+Reality есть всегда). id совпадают с ядром. */
export const PROTOCOLS = [
  ['hysteria2', 'Hysteria2'], ['tuic', 'TUIC v5'], ['ss2022', 'Shadowsocks 2022'],
  ['trojan', 'Trojan'], ['anytls', 'AnyTLS'], ['shadowtls', 'ShadowTLS v3'],
].map(([id, label]) => ({ id, label, get hint() { return t(`proto.hint.${id}`); } }));

export function protoLabel(id) {
  if (id === 'vless') return 'VLESS+Reality';
  return PROTOCOLS.find((p) => p.id === id)?.label ?? String(id);
}

/** Ссылки одного пользователя в порядке протоколов (Reality первой). */
export function linksForUser(links, name) {
  return (Array.isArray(links) ? links : []).filter((l) => l.name === name);
}

/** Строки блока «Протоколы сервера»: включён ли каждый и что произойдёт по кнопке. */
export function protocolRows(enabled) {
  const on = new Set(Array.isArray(enabled) ? enabled : []);
  return PROTOCOLS.map((p) => ({ ...p, on: on.has(p.id), action: on.has(p.id) ? 'disable' : 'enable' }));
}

export function noteMark(n) {
  return n.ok ? '✓' : '⚠';
}

/** Имя нового пользователя до отправки: те же правила, что на сервере. */
export function validUserName(n) {
  return /^[A-Za-z0-9_-]{1,32}$/.test(n || '');
}

/** Можно ли удалить пользователя: последнего удалять нельзя. */
export function canRemoveUser(users) {
  return Array.isArray(users) && users.length > 1;
}
