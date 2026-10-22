//! Ручная проверка M2.4: ключ из хранилища секретов входит на настоящий sshd (:2222) без файла ключа.
//! ELEUTHERIA_CONFIG_DIR=/tmp/x cargo run -p eleutheria-core --example e2e_keypem -- <authorized_keys_path>
use eleutheria_core::ssh::{Auth, Ssh, Target};
use eleutheria_core::store;

#[tokio::main(flavor = "current_thread")]
async fn main() -> anyhow::Result<()> {
    let ak = std::env::args().nth(1).expect("путь к authorized_keys");
    let key = store::ensure_key("127.0.0.1")?;
    std::fs::write(&ak, format!("{}\n", key.public))?;
    let t = Target { host: "127.0.0.1".into(), port: 2222, user: "root".into(), auth: Auth::KeyPem { pem: key.pem.clone() } };
    let s = Ssh::connect(&t, Box::new(|_| true)).await?;
    let out = s.run("echo ok").await?;
    println!("вход по ключу из хранилища: {}", out.stdout_str());
    // чужой ключ должен быть отклонён
    let other = eleutheria_core::store::ensure_key("other.example")?;
    let t2 = Target { auth: Auth::KeyPem { pem: other.pem }, ..t };
    let rejected = Ssh::connect(&t2, Box::new(|_| true)).await.is_err();
    println!("чужой ключ отклонён: {rejected}");
    anyhow::ensure!(out.stdout_str() == "ok" && rejected);
    Ok(())
}
