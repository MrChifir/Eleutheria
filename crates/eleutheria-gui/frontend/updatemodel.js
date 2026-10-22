// Чистая модель обновлений (приложение, helper, сервер): тексты и решения без DOM. Тестируется через `node --test`.

/** Сравнение версий вида 1.14.3 / v1.14.3 / 1.13.0-rc.3. Возвращает -1, 0, 1 или null, если это не версия. */
export function cmpVersion(a, b) {
  const parse = (v) => {
    const m = /^v?(\d+)\.(\d+)\.(\d+)(?:-([0-9A-Za-z.-]+))?(?:\+.*)?$/.exec(String(v ?? '').trim());
    return m ? { n: [+m[1], +m[2], +m[3]], pre: m[4] ?? null } : null;
  };
  const x = parse(a);
  const y = parse(b);
  if (!x || !y) return null;
  for (let i = 0; i < 3; i++) if (x.n[i] !== y.n[i]) return x.n[i] < y.n[i] ? -1 : 1;
  if (x.pre === y.pre) return 0;
  if (x.pre === null) return 1; // релиз выше пререлиза
  if (y.pre === null) return -1;
  const [p, q] = [x.pre.split('.'), y.pre.split('.')];
  for (let i = 0; i < Math.max(p.length, q.length); i++) {
    if (p[i] === undefined) return -1;
    if (q[i] === undefined) return 1;
    const [pn, qn] = [/^\d+$/.test(p[i]), /^\d+$/.test(q[i])];
    if (pn && qn) { if (+p[i] !== +q[i]) return +p[i] < +q[i] ? -1 : 1; }
    else if (pn !== qn) return pn ? -1 : 1;
    else if (p[i] !== q[i]) return p[i] < q[i] ? -1 : 1;
  }
  return 0;
}

/** Helper запущен и старше приложения: после обновления приложения службу нужно переустановить. */
export function helperOutdated(ov) {
  if (!ov || !ov.helper || !ov.helper.running) return false;
  return cmpVersion(ov.helper.version, ov.appVersion) === -1;
}

/** Что показать по результату проверки обновления приложения. */
export function updateView(outcome) {
  if (!outcome) return { text: '', canInstall: false };
  switch (outcome.kind) {
    case 'disabled':
      return { text: 'Обновления из приложения выключены: в этой сборке не задан ключ подписи.', canInstall: false };
    case 'unsupported':
      return { text: outcome.reason, canInstall: false };
    case 'upToDate':
      return { text: 'Установлена последняя версия.', canInstall: false };
    case 'available': {
      const i = outcome.info;
      return { text: `Доступна версия ${i.version} (сейчас ${i.current})${i.date ? `, от ${i.date}` : ''}.`, canInstall: true };
    }
    default:
      return { text: '', canInstall: false };
  }
}

/** Процент скачивания, либо null, если размер неизвестен. */
export function progressPercent(p) {
  if (!p || !p.total || p.total <= 0) return null;
  return Math.max(0, Math.min(100, Math.round((p.done / p.total) * 100)));
}

/** Состояние серверной части относительно sing-box в приложении. */
export function serverUpdateView(dto) {
  if (!dto) return { text: '', canUpdate: false };
  switch (dto.status) {
    case 'upToDate':
      return { text: `Серверная часть актуальна (sing-box ${dto.installed}).`, canUpdate: false };
    case 'outdated':
      return { text: `На сервере sing-box ${dto.installed}, в приложении ${dto.bundled}. Сервер можно обновить.`, canUpdate: true };
    case 'newer':
      return { text: `На сервере sing-box ${dto.installed} новее, чем в приложении (${dto.bundled}): сначала обнови приложение.`, canUpdate: false };
    case 'notInstalled':
      return { text: 'На сервере нет установки Eleutheria: сначала выполни установку.', canUpdate: false };
    default:
      return { text: 'Не удалось определить версию sing-box на сервере.', canUpdate: false };
  }
}

/** Сообщение при запуске: откат важнее подтверждения; null, если сообщать нечего. */
export function startReportMessage(r) {
  if (!r) return null;
  if (r.rolledBackFrom) return { text: `Обновление до ${r.rolledBackFrom} не запустилось, вернули прежнюю версию. Подробности и новая попытка: на вкладке обновлений.`, isErr: true };
  if (r.updatedTo) return { text: `Приложение обновлено до версии ${r.updatedTo}.`, isErr: false };
  return null;
}

/** Оба пути заданы (после обрезки пробелов и кавычек, которые часто остаются при копировании пути). */
export function manualImportReady(file, sig) {
  const clean = (v) => String(v ?? '').trim().replace(/^["']|["']$/g, '');
  return clean(file).length > 0 && clean(sig).length > 0;
}
