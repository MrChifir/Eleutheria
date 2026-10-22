//! Загрузка релиза sing-box на клиенте и проверка SHA256 по закреплённым хешам.

use std::path::PathBuf;

use anyhow::{bail, Context, Result};
use sha2::{Digest, Sha256};

pub const VERSION: &str = "1.14.3";

/// (os, arch, sha256 архива: tar.gz, для windows zip). Хеши сверяй с релизом на GitHub при обновлении версии.
const PINNED: &[(&str, &str, &str)] = &[
    ("linux", "amd64", "e2bdf179c15a3652955dc44867e33ca0965c9c9b91b34267dcc5a5d639a5feee"),
    ("linux", "arm64", "29dae24d76bea3bc62d07dd3e60cfc12003de7debbd6b768df9be9c68360174e"),
    ("darwin", "arm64", "0360ce634a04c26a6b4fd957517987bb4f6c8950f63435ce3c5af2fcae5860c5"),
    ("darwin", "amd64", "6d002b74d03b478547349cc10af89e007868596e5aa931816d45da9f544715a9"),
    ("windows", "amd64", "d8b86ef58936dba9230ec6a57ffa4243933f3c14ef4809828b6c553440ed1518"),
    ("windows", "arm64", "195b35424c6e3f5913954c7f08c5d8ba2d2199f6d18eb27a3972a5a29cdaa78c"),
];

/// Имя архива релиза: для Windows zip, для остальных tar.gz.
pub fn archive_name(os: &str, arch: &str) -> String {
    let ext = if os == "windows" { "zip" } else { "tar.gz" };
    format!("sing-box-{VERSION}-{os}-{arch}.{ext}")
}

/// Сопоставление `uname -m` с именем архитектуры в релизе.
pub fn arch_from_uname(m: &str) -> Result<&'static str> {
    match m.trim() {
        "x86_64" | "amd64" => Ok("amd64"),
        "aarch64" | "arm64" => Ok("arm64"),
        other => bail!("архитектура сервера `{other}` пока не поддерживается (нужны x86_64 или aarch64)"),
    }
}

fn cache_dir() -> PathBuf {
    let base = std::env::var_os("XDG_CACHE_HOME")
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".cache")))
        .or_else(|| std::env::var_os("LOCALAPPDATA").map(PathBuf::from))
        .unwrap_or_else(std::env::temp_dir);
    base.join("eleutheria")
}

/// Платформа этой машины в терминах имён релиза sing-box: (os, arch).
pub fn local_platform() -> Result<(&'static str, &'static str)> {
    let os = match std::env::consts::OS {
        "linux" => "linux",
        "macos" => "darwin",
        "windows" => "windows",
        other => bail!("клиент работает на Linux, macOS и Windows (сейчас `{other}`)"),
    };
    let arch = match std::env::consts::ARCH {
        "x86_64" => "amd64",
        "aarch64" => "arm64",
        other => bail!("архитектура `{other}` не поддерживается"),
    };
    Ok((os, arch))
}

/// Байты проверенного tar.gz для серверной архитектуры (Linux).
pub async fn fetch_verified(arch: &str) -> Result<Vec<u8>> {
    fetch_verified_for("linux", arch).await
}

/// Возвращает байты проверенного tar.gz для платформы. Кэширует на диске.
pub async fn fetch_verified_for(os: &str, arch: &str) -> Result<Vec<u8>> {
    let expected = PINNED
        .iter()
        .find(|(o, a, _)| *o == os && *a == arch)
        .map(|(_, _, h)| *h)
        .with_context(|| format!("нет закреплённого хеша для {os}-{arch}"))?;

    let name = archive_name(os, arch);
    let path = cache_dir().join(&name);

    if let Ok(bytes) = tokio::fs::read(&path).await {
        if hex::encode(Sha256::digest(&bytes)) == expected {
            return Ok(bytes);
        }
        // кэш повреждён, перекачиваем
    }

    let url = format!("https://github.com/SagerNet/sing-box/releases/download/v{VERSION}/{name}");
    let bytes = reqwest::get(&url)
        .await
        .with_context(|| format!("не удалось скачать {url}"))?
        .error_for_status()?
        .bytes()
        .await?
        .to_vec();

    let got = hex::encode(Sha256::digest(&bytes));
    if got != expected {
        bail!("SHA256 не совпал для {name}: ожидался {expected}, получен {got}. Установка прервана.");
    }
    tokio::fs::create_dir_all(cache_dir()).await.ok();
    tokio::fs::write(&path, &bytes).await.ok();
    Ok(bytes)
}

/// Достать бинарник `sing-box` из tar.gz релиза.
pub fn extract_binary(tgz: &[u8]) -> Result<Vec<u8>> {
    use std::io::Read;
    let gz = flate2::read::GzDecoder::new(tgz);
    let mut ar = tar::Archive::new(gz);
    for entry in ar.entries()? {
        let mut e = entry?;
        let is_bin = e.path()?.file_name().map(|n| n == "sing-box").unwrap_or(false);
        if is_bin && e.header().entry_type().is_file() {
            let mut buf = Vec::new();
            e.read_to_end(&mut buf)?;
            return Ok(buf);
        }
    }
    bail!("в архиве нет бинарника sing-box")
}

/// Достать из zip релиза для Windows `sing-box.exe` и все `.dll` (библиотеки лежат рядом с exe).
/// Возвращает пары (имя файла, содержимое). Имена берутся только как последний компонент пути.
pub fn extract_windows_bundle(zip_bytes: &[u8]) -> Result<Vec<(String, Vec<u8>)>> {
    use std::io::Read;
    let mut ar = zip::ZipArchive::new(std::io::Cursor::new(zip_bytes)).context("повреждён zip sing-box")?;
    let mut out = Vec::new();
    for i in 0..ar.len() {
        let mut f = ar.by_index(i)?;
        if !f.is_file() {
            continue;
        }
        // enclosed_name отбрасывает записи с `..` и абсолютными путями (zip-slip)
        let Some(name) = f.enclosed_name().and_then(|p| p.file_name().map(|n| n.to_string_lossy().into_owned())) else { continue };
        let lower = name.to_lowercase();
        if lower == "sing-box.exe" || lower.ends_with(".dll") {
            // предел размера защищает от zip-бомбы; реальный sing-box.exe около 80 МБ
            if f.size() > 400 * 1024 * 1024 {
                bail!("файл `{name}` в архиве слишком велик");
            }
            let mut buf = Vec::with_capacity(f.size() as usize);
            f.read_to_end(&mut buf)?;
            out.push((name, buf));
        }
    }
    if !out.iter().any(|(n, _)| n.eq_ignore_ascii_case("sing-box.exe")) {
        bail!("в архиве нет sing-box.exe");
    }
    Ok(out)
}

/// Локальный sing-box для клиента: скачивается один раз, хеш проверяется по закреплённому.
pub async fn ensure_local_binary() -> Result<PathBuf> {
    let (os, arch) = local_platform()?;
    let dir = crate::store::config_dir().join("bin");
    let file = if os == "windows" { format!("sing-box-{VERSION}.exe") } else { format!("sing-box-{VERSION}") };
    let path = dir.join(&file);
    if path.exists() {
        return Ok(path);
    }
    let archive = fetch_verified_for(os, arch).await?;
    tokio::fs::create_dir_all(&dir).await?;
    if os == "windows" {
        // exe и его dll кладём рядом: libcronet.dll загружается из каталога процесса
        let mut exe = None;
        for (name, data) in extract_windows_bundle(&archive)? {
            if name.eq_ignore_ascii_case("sing-box.exe") {
                exe = Some(data);
            } else {
                tokio::fs::write(dir.join(&name), &data).await?;
            }
        }
        let tmp = dir.join(format!("{file}.part"));
        tokio::fs::write(&tmp, exe.context("в архиве нет sing-box.exe")?).await?;
        tokio::fs::rename(&tmp, &path).await?;
        return Ok(path);
    }
    let bin = extract_binary(&archive)?;
    let tmp = dir.join(format!("{file}.part"));
    tokio::fs::write(&tmp, &bin).await?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o755))?;
    }
    tokio::fs::rename(&tmp, &path).await?;
    Ok(path)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn make_zip(files: &[(&str, &[u8])]) -> Vec<u8> {
        let mut w = zip::ZipWriter::new(std::io::Cursor::new(Vec::new()));
        let opts = zip::write::SimpleFileOptions::default().compression_method(zip::CompressionMethod::Stored);
        for (n, d) in files {
            w.start_file(*n, opts).unwrap();
            w.write_all(d).unwrap();
        }
        w.finish().unwrap().into_inner()
    }

    #[test]
    fn windows_bundle_extracts_exe_and_dlls_by_basename() {
        let z = make_zip(&[
            ("sing-box-1.14.3-windows-amd64/libcronet.dll", b"DLL"),
            ("sing-box-1.14.3-windows-amd64/LICENSE", b"lic"),
            ("sing-box-1.14.3-windows-amd64/sing-box.exe", b"EXE"),
            ("../evil.dll", b"x"),
        ]);
        let out = extract_windows_bundle(&z).unwrap();
        let names: Vec<&str> = out.iter().map(|(n, _)| n.as_str()).collect();
        assert!(names.contains(&"sing-box.exe") && names.contains(&"libcronet.dll"));
        assert!(!names.contains(&"LICENSE"));
        // запись с `..` в пути пропускается целиком (zip-slip), в имена попадают только базовые имена файлов
        assert!(!names.contains(&"evil.dll"));
        assert!(names.iter().all(|n| !n.contains('/') && !n.contains('\\')));
        assert_eq!(out.iter().find(|(n, _)| n == "sing-box.exe").unwrap().1, b"EXE");
    }

    #[test]
    fn windows_bundle_without_exe_is_an_error() {
        let z = make_zip(&[("x/libcronet.dll", b"DLL")]);
        assert!(extract_windows_bundle(&z).is_err());
        assert!(extract_windows_bundle(b"not a zip").is_err());
    }

    #[test]
    fn archive_names_and_pins_cover_every_supported_platform() {
        assert_eq!(archive_name("linux", "amd64"), format!("sing-box-{VERSION}-linux-amd64.tar.gz"));
        assert_eq!(archive_name("windows", "amd64"), format!("sing-box-{VERSION}-windows-amd64.zip"));
        for (os, arch) in [("linux", "amd64"), ("linux", "arm64"), ("darwin", "amd64"), ("darwin", "arm64"), ("windows", "amd64"), ("windows", "arm64")] {
            let h = PINNED.iter().find(|(o, a, _)| *o == os && *a == arch).unwrap_or_else(|| panic!("нет хеша {os}-{arch}")).2;
            assert_eq!(h.len(), 64, "{os}-{arch}");
            assert!(h.bytes().all(|b| b.is_ascii_hexdigit()));
        }
    }
}
