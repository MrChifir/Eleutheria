//! Самоподписанный сертификат для QUIC-протоколов (Hysteria2, TUIC). Домена у пользователя нет, поэтому клиент
//! не проверяет цепочку, а закрепляет открытый ключ сервера (SHA-256 от SPKI, base64): подмена сертификата
//! без знания закрытого ключа невозможна. Сертификат создаётся на клиенте и загружается на сервер по SSH.

use anyhow::{Context, Result};
use base64::{engine::general_purpose::STANDARD, Engine};
use rcgen::{CertificateParams, KeyPair, PublicKeyData};
use sha2::{Digest, Sha256};

pub struct Cert {
    pub cert_pem: String,
    pub key_pem: String,
    /// SHA-256 от SPKI в base64: формат `certificate_public_key_sha256` в sing-box
    pub spki_sha256_b64: String,
    /// SHA-256 от DER-сертификата в hex: формат `pinSHA256` в URI Hysteria2
    pub cert_sha256_hex: String,
}

pub fn spki_pin(spki_der: &[u8]) -> String {
    STANDARD.encode(Sha256::digest(spki_der))
}

/// Новый ключ ECDSA P-256 и сертификат на 10 лет для имени `sni`.
pub fn generate(sni: &str) -> Result<Cert> {
    let key = KeyPair::generate().context("не удалось создать ключ")?;
    let mut params = CertificateParams::new(vec![sni.to_string()]).context("недопустимое имя для сертификата")?;
    params.not_before = rcgen::date_time_ymd(2024, 1, 1);
    params.not_after = rcgen::date_time_ymd(2044, 1, 1);
    let cert = params.self_signed(&key).context("не удалось выпустить сертификат")?;
    Ok(Cert {
        cert_pem: cert.pem(),
        key_pem: key.serialize_pem(),
        spki_sha256_b64: spki_pin(&key.subject_public_key_info()),
        cert_sha256_hex: hex::encode(Sha256::digest(cert.der().as_ref())),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generates_pem_and_pins_of_expected_shape() {
        let c = generate("www.bing.com").unwrap();
        assert!(c.cert_pem.starts_with("-----BEGIN CERTIFICATE-----"));
        assert!(c.key_pem.contains("PRIVATE KEY"));
        assert_eq!(c.spki_sha256_b64.len(), 44);
        assert!(c.spki_sha256_b64.ends_with('='));
        assert_eq!(c.cert_sha256_hex.len(), 64);
        let d = generate("www.bing.com").unwrap();
        assert_ne!(c.spki_sha256_b64, d.spki_sha256_b64, "каждый раз новый ключ");
    }
}
