//! Язык сообщений (русский или английский). / Message language (Russian or English).
//!
//! Язык глобальный на процесс: GUI выставляет его командой `set_language`, CLI берёт из окружения
//! (`ELEUTHERIA_LANG`, затем `LC_ALL` / `LC_MESSAGES` / `LANG`). По умолчанию русский, чтобы поведение
//! и тесты не менялись, пока язык не выбран явно.
//!
//! Использование: `tr!("русский текст", "english text")`. Выбирается только одна ветка, поэтому для текста
//! с подстановками пишем `tr!(format!("… {x}"), format!("… {x}"))`.

use std::sync::atomic::{AtomicU8, Ordering};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Lang {
    Ru,
    En,
}

static LANG: AtomicU8 = AtomicU8::new(0);

pub fn set(l: Lang) {
    LANG.store(if l == Lang::En { 1 } else { 0 }, Ordering::Relaxed);
}

pub fn get() -> Lang {
    if LANG.load(Ordering::Relaxed) == 1 {
        Lang::En
    } else {
        Lang::Ru
    }
}

pub fn is_en() -> bool {
    get() == Lang::En
}

/// "ru", "ru-RU", "ru_RU.UTF-8" → Ru; "en", "en_US.UTF-8", "C" и всё остальное известное → En; пусто → None.
pub fn parse(s: &str) -> Option<Lang> {
    let t = s.trim().to_ascii_lowercase();
    if t.is_empty() {
        return None;
    }
    if t == "ru" || t.starts_with("ru-") || t.starts_with("ru_") || t.starts_with("ru.") {
        Some(Lang::Ru)
    } else {
        Some(Lang::En)
    }
}

/// Язык из окружения (для CLI): `ELEUTHERIA_LANG`, `LC_ALL`, `LC_MESSAGES`, `LANG`. Ничего не задано: английский.
pub fn from_env() -> Lang {
    for k in ["ELEUTHERIA_LANG", "LC_ALL", "LC_MESSAGES", "LANG"] {
        if let Some(l) = std::env::var(k).ok().and_then(|v| parse(&v)) {
            return l;
        }
    }
    Lang::En
}

/// Выбирает текст по текущему языку: `tr!(ru, en)`. Выражения вычисляются лениво.
#[macro_export]
macro_rules! tr {
    ($ru:expr, $en:expr $(,)?) => {
        if $crate::i18n::is_en() {
            $en
        } else {
            $ru
        }
    };
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_locales() {
        assert_eq!(parse("ru_RU.UTF-8"), Some(Lang::Ru));
        assert_eq!(parse("ru"), Some(Lang::Ru));
        assert_eq!(parse("en_US.UTF-8"), Some(Lang::En));
        assert_eq!(parse("C"), Some(Lang::En));
        assert_eq!(parse(""), None);
    }
}
