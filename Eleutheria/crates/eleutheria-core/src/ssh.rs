//! Тонкая обёртка над russh: подключение, проверка host key, exec, загрузка файлов.

use std::sync::Arc;
use std::time::Duration;

use anyhow::{bail, Context, Result};
use russh::client::{self, Handle};
use russh::keys::{decode_secret_key, load_secret_key, HashAlg, PrivateKeyWithHashAlg, PublicKeyOrCertificate};
use russh::{ChannelMsg, Disconnect};

/// Решает, доверять ли ключу сервера. Получает fingerprint вида `SHA256:...`.
pub type HostKeyVerifier = Box<dyn Fn(&str) -> bool + Send + Sync>;

pub enum Auth {
    Password(String),
    KeyFile { path: String, passphrase: Option<String> },
    /// Приватный ключ в формате OpenSSH прямо в памяти (из хранилища секретов, без файла на диске).
    KeyPem { pem: String },
}

pub struct Target {
    pub host: String,
    pub port: u16,
    pub user: String,
    pub auth: Auth,
}

struct Client {
    verifier: HostKeyVerifier,
}

impl client::Handler for Client {
    type Error = russh::Error;

    async fn check_server_key(
        &mut self,
        key: &PublicKeyOrCertificate,
    ) -> Result<bool, Self::Error> {
        let fp = match key {
            PublicKeyOrCertificate::PublicKey { key, .. } => key.fingerprint(HashAlg::Sha256),
            PublicKeyOrCertificate::Certificate(_) => return Ok(false),
        };
        Ok((self.verifier)(&fp.to_string()))
    }
}

/// Сервер отклонил аутентификацию (отдельный тип, чтобы вызывающий мог предложить другой способ входа).
#[derive(Debug)]
pub struct AuthRejected;

impl std::fmt::Display for AuthRejected {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "аутентификация отклонена (проверь логин/пароль/ключ)")
    }
}

impl std::error::Error for AuthRejected {}

pub struct Output {
    pub code: u32,
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
}

impl Output {
    pub fn stdout_str(&self) -> String {
        String::from_utf8_lossy(&self.stdout).trim().to_string()
    }
    pub fn stderr_str(&self) -> String {
        String::from_utf8_lossy(&self.stderr).trim().to_string()
    }
}

pub struct Ssh {
    handle: Handle<Client>,
}

impl Ssh {
    pub async fn connect(t: &Target, verifier: HostKeyVerifier) -> Result<Self> {
        let config = Arc::new(client::Config {
            inactivity_timeout: Some(Duration::from_secs(120)),
            ..Default::default()
        });
        let mut handle = tokio::time::timeout(
            Duration::from_secs(20),
            client::connect(config, (t.host.as_str(), t.port), Client { verifier }),
        )
        .await
        .context("таймаут подключения к серверу")?
        .context("не удалось подключиться по SSH (неверный IP/порт или host key отклонён)")?;

        let ok = match &t.auth {
            Auth::Password(p) => handle
                .authenticate_password(t.user.clone(), p.clone())
                .await?
                .success(),
            Auth::KeyFile { .. } | Auth::KeyPem { .. } => {
                let key = match &t.auth {
                    Auth::KeyFile { path, passphrase } => load_secret_key(path, passphrase.as_deref())
                        .with_context(|| format!("не удалось прочитать ключ {path}"))?,
                    Auth::KeyPem { pem } => decode_secret_key(pem, None).context("не удалось разобрать сохранённый SSH-ключ")?,
                    Auth::Password(_) => unreachable!(),
                };
                let hash = handle.best_supported_rsa_hash().await?.flatten();
                handle
                    .authenticate_publickey(
                        t.user.clone(),
                        PrivateKeyWithHashAlg::new(Arc::new(key), hash),
                    )
                    .await?
                    .success()
            }
        };
        if !ok {
            return Err(AuthRejected.into());
        }
        Ok(Self { handle })
    }

    /// Выполнить команду, опционально подав stdin. Не бросает ошибку на ненулевой код.
    pub async fn run_with_stdin(&self, cmd: &str, stdin: Option<&[u8]>) -> Result<Output> {
        let mut ch = self.handle.channel_open_session().await?;
        ch.exec(true, cmd).await?;
        if let Some(data) = stdin {
            ch.data(data).await?;
            ch.eof().await?;
        }
        let (mut out, mut err, mut code) = (Vec::new(), Vec::new(), None);
        while let Some(msg) = ch.wait().await {
            match msg {
                ChannelMsg::Data { data } => out.extend_from_slice(&data),
                ChannelMsg::ExtendedData { data, .. } => err.extend_from_slice(&data),
                ChannelMsg::ExitStatus { exit_status } => code = Some(exit_status),
                _ => {}
            }
        }
        Ok(Output {
            code: code.unwrap_or(255),
            stdout: out,
            stderr: err,
        })
    }

    pub async fn run(&self, cmd: &str) -> Result<Output> {
        self.run_with_stdin(cmd, None).await
    }

    /// Выполнить и потребовать код 0.
    pub async fn run_ok(&self, cmd: &str) -> Result<String> {
        let o = self.run(cmd).await?;
        if o.code != 0 {
            bail!("команда `{cmd}` завершилась с кодом {}: {}", o.code, o.stderr_str());
        }
        Ok(o.stdout_str())
    }

    /// Загрузить файл через stdin `cat` (без SFTP), с атомарной заменой и правами.
    pub async fn upload(&self, remote_path: &str, data: &[u8], mode: u32) -> Result<()> {
        let tmp = format!("{remote_path}.eleutheria-tmp");
        let cmd = format!(
            "cat > {tmp} && chmod {mode:o} {tmp} && mv -f {tmp} {remote_path}",
            tmp = shq(&tmp),
            remote_path = shq(remote_path),
        );
        let o = self.run_with_stdin(&cmd, Some(data)).await?;
        if o.code != 0 {
            bail!("загрузка {remote_path} не удалась: {}", o.stderr_str());
        }
        Ok(())
    }

    pub async fn close(self) -> Result<()> {
        self.handle
            .disconnect(Disconnect::ByApplication, "", "en")
            .await?;
        Ok(())
    }
}

/// Экранирование для POSIX-шелла.
pub fn shq(s: &str) -> String {
    format!("'{}'", s.replace('\'', "'\\''"))
}
