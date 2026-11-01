pub mod client;
pub mod config;
pub mod fleet;
pub mod harden;
#[cfg(unix)]
pub mod helper_install;
#[cfg(windows)]
#[path = "helper_install_win.rs"]
pub mod helper_install;
pub mod ipc;
pub mod profiles;
pub mod provision;
pub mod rollback;
pub mod secrets;
pub mod singbox;
pub mod ssh;
pub mod state;
pub mod store;
pub mod tlscert;
pub mod tx;
pub mod userprofiles;
pub mod users;
pub mod version;
pub mod winhelper;

use qrcode::{render::unicode, QrCode};

/// QR-код как SVG (для GUI). Размер вектора не важен: масштабируется стилями.
pub fn qr_svg(data: &str) -> anyhow::Result<String> {
    use qrcode::render::svg;
    let code = QrCode::new(data.as_bytes())?;
    Ok(code.render::<svg::Color>().min_dimensions(220, 220).quiet_zone(true).build())
}

/// QR-код для терминала (Unicode-блоки).
pub fn qr_text(data: &str) -> anyhow::Result<String> {
    let code = QrCode::new(data.as_bytes())?;
    Ok(code.render::<unicode::Dense1x2>().quiet_zone(true).build())
}

#[cfg(test)]
mod qr_tests {
    use super::*;

    #[test]
    fn svg_qr_is_a_vector_image_and_depends_on_input() {
        let a = qr_svg("vless://a158cda3@203.0.113.5:443#x").unwrap();
        let b = qr_svg("vless://b158cda3@203.0.113.5:443#x").unwrap();
        assert!(a.contains("<svg") && a.contains("</svg>"));
        assert!(!a.contains("<script"));
        assert_ne!(a, b);
        assert!(qr_svg(&"x".repeat(10_000)).is_err(), "слишком длинные данные не помещаются в QR");
    }
}
