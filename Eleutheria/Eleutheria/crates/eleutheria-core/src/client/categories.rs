//! Категории трафика для пробера и роутера: набор доменов, адрес пробы и тумблер «включено».
//!
//! Включённая категория получает свой переключатель `cat-<id>` в sing-box и проверяется отдельно:
//! если выходной IP текущего сервера не пускают на сайты категории, роутер переводит только её на другой путь.
//! Выключенная категория идёт вместе с остальным трафиком (общий переключатель `proxy`).

use std::collections::BTreeSet;
use std::fs;

use anyhow::{bail, Result};
use serde::{Deserialize, Serialize};

use crate::store::config_dir;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Category {
    /// `[a-z0-9-]`, до 24 символов; `canary` зарезервирован под общую проверку туннеля
    pub id: String,
    pub title: String,
    /// суффиксы доменов (`youtube.com` покрывает и поддомены)
    pub domains: Vec<String>,
    /// https-адрес, который открывает пробер; ответ любого кода, кроме 403/451/5xx, считается успехом
    pub probe_url: String,
    pub enabled: bool,
}

fn cat(id: &str, title: &str, domains: &[&str], url: &str) -> Category {
    Category { id: id.into(), title: title.into(), domains: domains.iter().map(|d| d.to_string()).collect(), probe_url: url.into(), enabled: true }
}

/// Встроенный набор. Адреса проб лёгкие (страницы или `generate_204`), домены взяты по основным хостам сервиса.
pub fn builtin() -> Vec<Category> {
    vec![
        cat("video", "Видео", &["youtube.com", "youtu.be", "googlevideo.com", "ytimg.com", "ggpht.com"], "https://www.youtube.com/generate_204"),
        cat("messengers", "Мессенджеры", &["telegram.org", "t.me", "telegram.me", "web.whatsapp.com", "whatsapp.com", "whatsapp.net"], "https://telegram.org/"),
        cat("social", "Соцсети", &["instagram.com", "cdninstagram.com", "facebook.com", "fbcdn.net", "twitter.com", "x.com", "twimg.com"], "https://www.instagram.com/"),
        cat("ai", "ИИ-сервисы", &["openai.com", "chatgpt.com", "oaistatic.com", "anthropic.com", "claude.ai", "gemini.google.com"], "https://chatgpt.com/"),
    ]
}

/// Что сохраняется на диске: только отличия от встроенного набора.
#[derive(Default, Serialize, Deserialize)]
struct Overrides {
    #[serde(default)]
    disabled: BTreeSet<String>,
    #[serde(default)]
    custom: Vec<Category>,
}

fn path() -> std::path::PathBuf {
    config_dir().join("categories.json")
}

fn read_overrides() -> Overrides {
    fs::read_to_string(path()).ok().and_then(|t| serde_json::from_str(&t).ok()).unwrap_or_default()
}

fn merge(o: Overrides) -> Vec<Category> {
    let mut all = builtin();
    for c in o.custom {
        if validate_one(&c).is_ok() && !all.iter().any(|x| x.id == c.id) {
            all.push(c);
        }
    }
    for c in &mut all {
        c.enabled = !o.disabled.contains(&c.id);
    }
    all
}

/// Текущий набор: встроенные + собственные из `categories.json` с учётом тумблеров. Битые записи пропускаются.
pub fn load() -> Vec<Category> {
    merge(read_overrides())
}

pub fn set_enabled(id: &str, enabled: bool) -> Result<()> {
    let mut o = read_overrides();
    if !merge(Overrides { disabled: BTreeSet::new(), custom: o.custom.clone() }).iter().any(|c| c.id == id) {
        bail!("категории `{id}` нет");
    }
    if enabled {
        o.disabled.remove(id);
    } else {
        o.disabled.insert(id.to_string());
    }
    fs::create_dir_all(config_dir())?;
    fs::write(path(), serde_json::to_vec_pretty(&o)?)?;
    Ok(())
}

pub fn valid_domain(d: &str) -> bool {
    !d.is_empty()
        && d.len() <= 253
        && !d.starts_with('.')
        && !d.ends_with('.')
        && !d.contains("..")
        && d.chars().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-' || c == '.')
}

pub fn validate_one(c: &Category) -> Result<()> {
    if c.id.is_empty() || c.id.len() > 24 || c.id == crate::client::prober::CANARY || !c.id.chars().all(|ch| ch.is_ascii_lowercase() || ch.is_ascii_digit() || ch == '-') {
        bail!("недопустимый id категории `{}`", c.id);
    }
    if c.domains.is_empty() || c.domains.len() > 64 {
        bail!("категория `{}`: от 1 до 64 доменов", c.id);
    }
    if let Some(d) = c.domains.iter().find(|d| !valid_domain(d)) {
        bail!("категория `{}`: недопустимый домен `{d}`", c.id);
    }
    if !c.probe_url.starts_with("https://") || c.probe_url.len() > 512 || c.probe_url.chars().any(|ch| ch.is_whitespace() || ch.is_control()) {
        bail!("категория `{}`: адрес пробы должен быть https:// без пробелов", c.id);
    }
    Ok(())
}

/// Проверка набора целиком (его присылают helper'у с правами root, поэтому проверка строгая).
pub fn validate(cs: &[Category]) -> Result<()> {
    if cs.len() > 16 {
        bail!("слишком много категорий (максимум 16)");
    }
    let mut seen = BTreeSet::new();
    for c in cs {
        validate_one(c)?;
        if !seen.insert(&c.id) {
            bail!("категория `{}` повторяется", c.id);
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builtin_set_is_valid_and_enabled() {
        let b = builtin();
        validate(&b).unwrap();
        assert!(b.iter().all(|c| c.enabled));
        assert!(b.iter().any(|c| c.id == "video"));
    }

    #[test]
    fn merge_applies_toggles_and_custom_but_drops_broken_or_duplicate() {
        let good = Category { id: "bank".into(), title: "Банк".into(), domains: vec!["example.com".into()], probe_url: "https://example.com/".into(), enabled: true };
        let dup = Category { id: "video".into(), ..good.clone() };
        let bad = Category { id: "x y".into(), ..good.clone() };
        let m = merge(Overrides { disabled: ["ai".to_string()].into(), custom: vec![good, dup, bad] });
        assert!(!m.iter().find(|c| c.id == "ai").unwrap().enabled);
        assert!(m.iter().find(|c| c.id == "bank").unwrap().enabled);
        assert_eq!(m.iter().filter(|c| c.id == "video").count(), 1);
        assert!(m.iter().all(|c| c.id != "x y"));
        assert!(m.iter().find(|c| c.id == "video").unwrap().domains.len() > 1, "дубликат не заменил встроенную");
    }

    #[test]
    fn validation_rejects_injection_and_reserved_names() {
        let ok = builtin().remove(0);
        for bad in [
            Category { id: "canary".into(), ..ok.clone() },
            Category { id: "A".into(), ..ok.clone() },
            Category { domains: vec![], ..ok.clone() },
            Category { domains: vec!["ex ample.com".into()], ..ok.clone() },
            Category { domains: vec!["a\"b.com".into()], ..ok.clone() },
            Category { domains: vec!["Example.com".into()], ..ok.clone() },
            Category { domains: vec![".com".into()], ..ok.clone() },
            Category { probe_url: "http://example.com/".into(), ..ok.clone() },
            Category { probe_url: "https://a.com/ x".into(), ..ok.clone() },
        ] {
            assert!(validate_one(&bad).is_err(), "{bad:?}");
        }
        assert!(validate(&[ok.clone(), ok]).is_err(), "дубликаты id");
    }
}
