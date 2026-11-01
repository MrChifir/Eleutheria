//! Сравнение версий вида `1.14.3`, `v1.14.3`, `1.13.0-rc.3` (без внешних зависимостей).
//! Нужно, чтобы решить, устарела ли серверная часть относительно бандла.

use std::cmp::Ordering;

#[derive(Debug, PartialEq, Eq)]
struct Ver {
    nums: [u64; 3],
    pre: Option<String>,
}

fn parse(v: &str) -> Option<Ver> {
    let v = v.trim().trim_start_matches('v');
    let v = v.split('+').next()?; // build-метаданные не влияют на порядок
    let (core, pre) = match v.split_once('-') {
        Some((c, p)) if !p.is_empty() => (c, Some(p.to_string())),
        Some(_) => return None,
        None => (v, None),
    };
    let mut it = core.split('.');
    let mut nums = [0u64; 3];
    for slot in nums.iter_mut() {
        *slot = it.next()?.parse().ok()?;
    }
    if it.next().is_some() {
        return None;
    }
    Some(Ver { nums, pre })
}

/// Сравнение пререлизных суффиксов по правилам semver: числовые части как числа, числовые меньше текстовых.
fn cmp_pre(a: &str, b: &str) -> Ordering {
    let (mut ai, mut bi) = (a.split('.'), b.split('.'));
    loop {
        match (ai.next(), bi.next()) {
            (None, None) => return Ordering::Equal,
            (None, Some(_)) => return Ordering::Less,
            (Some(_), None) => return Ordering::Greater,
            (Some(x), Some(y)) => {
                let o = match (x.parse::<u64>(), y.parse::<u64>()) {
                    (Ok(p), Ok(q)) => p.cmp(&q),
                    (Ok(_), Err(_)) => Ordering::Less,
                    (Err(_), Ok(_)) => Ordering::Greater,
                    (Err(_), Err(_)) => x.cmp(y),
                };
                if o != Ordering::Equal {
                    return o;
                }
            }
        }
    }
}

/// None, если любая из строк не похожа на версию.
pub fn compare(a: &str, b: &str) -> Option<Ordering> {
    let (a, b) = (parse(a)?, parse(b)?);
    Some(a.nums.cmp(&b.nums).then_with(|| match (&a.pre, &b.pre) {
        (None, None) => Ordering::Equal,
        (Some(_), None) => Ordering::Less, // 1.0.0-rc.1 < 1.0.0
        (None, Some(_)) => Ordering::Greater,
        (Some(x), Some(y)) => cmp_pre(x, y),
    }))
}

/// Последний токен первой строки вывода `sing-box version` («sing-box version 1.14.3» → «1.14.3»).
pub fn from_version_output(out: &str) -> Option<String> {
    let tok = out.lines().next()?.split_whitespace().last()?;
    parse(tok).map(|_| tok.trim_start_matches('v').to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use Ordering::*;

    #[test]
    fn orders_numerically_not_lexically() {
        assert_eq!(compare("1.9.0", "1.14.3"), Some(Less));
        assert_eq!(compare("1.14.3", "1.14.3"), Some(Equal));
        assert_eq!(compare("v2.0.0", "1.99.99"), Some(Greater));
        assert_eq!(compare("1.14.10", "1.14.9"), Some(Greater));
    }

    #[test]
    fn prerelease_is_below_release() {
        assert_eq!(compare("1.13.0-rc.3", "1.13.0"), Some(Less));
        assert_eq!(compare("1.13.0-rc.10", "1.13.0-rc.9"), Some(Greater));
        assert_eq!(compare("1.13.0-alpha", "1.13.0-beta"), Some(Less));
        assert_eq!(compare("1.13.0-1", "1.13.0-alpha"), Some(Less));
        assert_eq!(compare("1.13.0+build5", "1.13.0"), Some(Equal));
    }

    #[test]
    fn garbage_is_none() {
        for bad in ["", "abc", "1.2", "1.2.3.4", "1.2.x", "1.2.3-", "-1.2.3"] {
            assert_eq!(compare(bad, "1.0.0"), None, "{bad}");
        }
    }

    #[test]
    fn parses_singbox_output() {
        assert_eq!(from_version_output("sing-box version 1.14.3\n\nEnvironment: go1.24"), Some("1.14.3".into()));
        assert_eq!(from_version_output("sing-box version 21.14.3"), Some("21.14.3".into()));
        assert_eq!(from_version_output(""), None);
        assert_eq!(from_version_output("command not found"), None);
    }
}
