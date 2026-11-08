//! Помощник для scripts/e2e-rollback.sh: вызывает ту же логику, что и GUI перед установкой обновления.
//!   e2e_rollback arm <config-dir> <appimage> <cli> <from> <to> <timeout-secs>
//!   e2e_rollback confirm <config-dir> <running-version>
use std::path::Path;

fn main() {
    let a: Vec<String> = std::env::args().collect();
    match a.get(1).map(String::as_str) {
        Some("arm") => {
            let ai = Path::new(&a[3]);
            eleutheria_app::update::arm_rollback_in(Path::new(&a[2]), "linux", Some(ai), ai, Path::new(&a[4]), &a[5], &a[6], a[7].parse().unwrap()).unwrap();
        }
        Some("confirm") => {
            let r = eleutheria_app::update::confirm_started(Path::new(&a[2]), &a[3]);
            println!("{}", serde_json::to_string(&r).unwrap());
        }
        _ => {
            eprintln!("usage: arm|confirm");
            std::process::exit(2);
        }
    }
}
