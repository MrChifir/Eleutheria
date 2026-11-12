//! Партнёрские хостинги для покупки VPS. Единственный источник списка: интерфейс берёт имена отсюда,
//! а открывает ссылку только по `id` из этого списка, поэтому произвольный адрес из интерфейса не откроется.
//!
//! Ссылки партнёрские: по ним автор проекта может получить вознаграждение.

use serde::Serialize;

#[derive(Serialize, Clone, Copy, Debug, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct Partner {
    pub id: &'static str,
    pub name: &'static str,
    pub url: &'static str,
}

/// Список для русского интерфейса: российские хостинги.
pub const PARTNERS_RU: &[Partner] = &[
    Partner { id: "vdsina", name: "VDSina", url: "https://vdsina.ru/?partner=6j678cbfa1a1" },
    Partner { id: "fornex", name: "Fornex", url: "https://fornex.com/code/1cmpci/" },
    Partner { id: "ihc", name: "IHC", url: "https://www.ihc.ru/?ref=459056" },
    Partner { id: "justhost", name: "Justhost", url: "https://justhost.ru/?ref=381717" },
    Partner { id: "nodex-go", name: "Nodex", url: "https://nodex-go.com/register?ref=64545" },
];

/// Список для английского интерфейса.
pub const PARTNERS_EN: &[Partner] = &[
    Partner { id: "noothost", name: "NootHost", url: "https://noothost.com/?aff=5" },
    Partner { id: "mangohost", name: "MangoHost", url: "https://mangohost.net/?affid=4740" },
    Partner { id: "serva", name: "Serva", url: "https://serva.one/?ref=15372" },
    Partner { id: "unihost", name: "Unihost", url: "https://dashboard.unihost.com/aff.php?aff=119" },
    Partner { id: "vpsone", name: "VPS.one", url: "https://vps.one/?ref=23079" },
];

/// Список для текущего языка интерфейса.
pub fn list() -> &'static [Partner] {
    if eleutheria_core::i18n::is_en() { PARTNERS_EN } else { PARTNERS_RU }
}

/// Адрес партнёра по идентификатору; для неизвестного идентификатора `None`.
pub fn url_for(id: &str) -> Option<&'static str> {
    list().iter().find(|p| p.id == id).map(|p| p.url)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn partner_links_are_https_and_ids_unique() {
        for set in [PARTNERS_RU, PARTNERS_EN] {
            let mut ids = std::collections::HashSet::new();
            for p in set {
                assert!(p.url.starts_with("https://"), "не https: {}", p.url);
                assert!(ids.insert(p.id), "повтор id: {}", p.id);
            }
            assert_eq!(set.len(), 5);
        }
    }

    #[test]
    fn only_known_ids_resolve() {
        use eleutheria_core::i18n::{self, Lang};
        i18n::set(Lang::Ru);
        assert_eq!(url_for("vdsina"), Some("https://vdsina.ru/?partner=6j678cbfa1a1"));
        assert!(url_for("noothost").is_none());
        assert!(url_for("https://evil.example").is_none());
        assert!(url_for("").is_none());
        i18n::set(Lang::En);
        assert_eq!(url_for("noothost"), Some("https://noothost.com/?aff=5"));
        assert!(url_for("vdsina").is_none());
        i18n::set(Lang::Ru);
    }
}
