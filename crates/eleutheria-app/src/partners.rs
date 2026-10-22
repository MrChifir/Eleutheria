//! Партнёрские хостинги для покупки VPS. Единственный источник списка: интерфейс берёт имена отсюда,
//! а открывает ссылку только по `id` из этого списка, поэтому произвольный адрес из интерфейса не откроется.
//!
//! Ссылки партнёрские: по ним автор проекта может получить вознаграждение. Интерфейс сообщает об этом пользователю.

use serde::Serialize;

#[derive(Serialize, Clone, Copy, Debug, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct Partner {
    pub id: &'static str,
    pub name: &'static str,
    pub url: &'static str,
}

pub const PARTNERS: &[Partner] = &[
    Partner { id: "vdsina", name: "VDSina", url: "https://vdsina.ru/?partner=6j678cbfa1a1" },
    Partner { id: "fornex", name: "Fornex", url: "https://fornex.com/code/1cmpci/" },
    Partner { id: "ihc", name: "IHC", url: "https://www.ihc.ru/?ref=459056" },
    Partner { id: "justhost", name: "Justhost", url: "https://justhost.ru/?ref=381717" },
    Partner { id: "nodex-go", name: "Nodex", url: "https://nodex-go.com/register?ref=64545" },
];

/// Адрес партнёра по идентификатору; для неизвестного идентификатора `None`.
pub fn url_for(id: &str) -> Option<&'static str> {
    PARTNERS.iter().find(|p| p.id == id).map(|p| p.url)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn partner_links_are_https_and_ids_unique() {
        let mut ids = std::collections::HashSet::new();
        for p in PARTNERS {
            assert!(p.url.starts_with("https://"), "не https: {}", p.url);
            assert!(ids.insert(p.id), "повтор id: {}", p.id);
        }
        assert_eq!(PARTNERS.len(), 5);
    }

    #[test]
    fn only_known_ids_resolve() {
        assert_eq!(url_for("vdsina"), Some("https://vdsina.ru/?partner=6j678cbfa1a1"));
        assert!(url_for("https://evil.example").is_none());
        assert!(url_for("").is_none());
    }
}
