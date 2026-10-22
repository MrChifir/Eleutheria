//! IPC между CLI/GUI и привилегированным helper'ом: одна JSON-строка запроса и одна ответа.
//! Unix: сокет, доступ только владельцу установки (uid через SO_PEERCRED) и root.
//! Windows: named pipe с DACL (SYSTEM, администраторы и SID установившего пользователя), сетевые клиенты отклоняются.
//!
//! Важное свойство безопасности: helper НЕ принимает готовый конфиг sing-box (через конфиг можно
//! читать и писать файлы от root). Он получает только данные серверов, валидирует их и сам собирает конфиг.

use std::future::Future;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, BufReader};
#[cfg(unix)]
use tokio::net::{UnixListener, UnixStream};

use crate::client::config::RuDirect;
use crate::client::profile::Server;

pub const MAX_LINE: usize = 1 << 20;

pub fn default_socket_path() -> PathBuf {
    if let Some(p) = std::env::var_os("ELEUTHERIA_HELPER_SOCKET") {
        return PathBuf::from(p);
    }
    if cfg!(windows) {
        PathBuf::from(crate::winhelper::PIPE_NAME)
    } else if cfg!(target_os = "macos") {
        PathBuf::from("/var/run/eleutheria-helper.sock")
    } else {
        PathBuf::from("/run/eleutheria/helper.sock")
    }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct StartParams {
    pub servers: Vec<Server>,
    pub ru_direct: RuDirect,
    pub selected: Option<String>,
    pub test_url: String,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(tag = "cmd", rename_all = "snake_case")]
pub enum Request {
    Ping,
    Start(StartParams),
    Stop,
    Status,
}

#[derive(Serialize, Deserialize, Debug, Clone, Default, PartialEq, Eq)]
pub struct StatusInfo {
    pub running: bool,
    pub pid: Option<u32>,
    pub clash_port: Option<u16>,
    pub secret: Option<String>,
    pub test_url: Option<String>,
    /// (тег, имя) серверов
    pub servers: Vec<(String, String)>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(tag = "result", rename_all = "snake_case")]
pub enum Response {
    Pong { version: String },
    Started { pid: u32 },
    Stopped { was_running: bool },
    Status(StatusInfo),
    Error { message: String },
}

async fn read_line<R: AsyncBufReadExt + Unpin>(r: &mut R) -> Result<Vec<u8>> {
    let mut buf = Vec::new();
    let n = r.take(MAX_LINE as u64 + 1).read_until(b'\n', &mut buf).await?;
    if n == 0 {
        bail!("соединение закрыто без данных");
    }
    if buf.len() > MAX_LINE {
        bail!("запрос слишком большой");
    }
    Ok(buf)
}

async fn write_line<W: AsyncWrite + Unpin, T: Serialize>(s: &mut W, v: &T) -> Result<()> {
    let mut data = serde_json::to_vec(v)?;
    data.push(b'\n');
    s.write_all(&data).await?;
    s.flush().await?;
    Ok(())
}

/// Отправить запрос helper'у и получить ответ.
pub async fn request(sock: &Path, req: &Request) -> Result<Response> {
    let mut s = tokio::time::timeout(Duration::from_secs(3), connect(sock))
        .await
        .context("helper не отвечает (таймаут подключения)")?
        .with_context(|| format!("не удалось подключиться к helper ({})", sock.display()))?;
    // Если запись не удалась, сервер мог уже ответить отказом и закрыть соединение: прочитаем его ответ.
    let write_err = write_line(&mut s, req).await.err();
    let mut r = BufReader::new(&mut s);
    match tokio::time::timeout(Duration::from_secs(60), read_line(&mut r)).await {
        Ok(Ok(line)) => serde_json::from_slice(&line).context("некорректный ответ helper'а"),
        Ok(Err(e)) => Err(write_err.unwrap_or(e)),
        Err(_) => Err(write_err.unwrap_or_else(|| anyhow::anyhow!("helper не ответил вовремя"))),
    }
}

#[cfg(unix)]
async fn connect(sock: &Path) -> std::io::Result<UnixStream> {
    UnixStream::connect(sock).await
}

/// Windows: все экземпляры pipe заняты, повторяем (ERROR_PIPE_BUSY = 231). Таймаут снаружи, в `request`.
#[cfg(windows)]
async fn connect(sock: &Path) -> std::io::Result<tokio::net::windows::named_pipe::NamedPipeClient> {
    use tokio::net::windows::named_pipe::ClientOptions;
    loop {
        match ClientOptions::new().open(sock) {
            Ok(c) => return Ok(c),
            Err(e) if e.raw_os_error() == Some(231) => tokio::time::sleep(Duration::from_millis(50)).await,
            Err(e) => return Err(e),
        }
    }
}

/// Обработать одно соединение: прочитать запрос, вызвать обработчик, ответить, закрыть без потери ответа.
async fn handle_conn<S, H, Fut>(mut stream: S, allowed: bool, h: Arc<H>)
where
    S: AsyncRead + AsyncWrite + Unpin,
    H: Fn(Request) -> Fut + Send + Sync + 'static,
    Fut: Future<Output = Response> + Send + 'static,
{
    let resp = if !allowed {
        Response::Error { message: "доступ запрещён".into() }
    } else {
        let mut r = BufReader::new(&mut stream);
        match tokio::time::timeout(Duration::from_secs(10), read_line(&mut r)).await {
            Ok(Ok(line)) => match serde_json::from_slice::<Request>(&line) {
                Ok(req) => h(req).await,
                Err(_) => Response::Error { message: "некорректный запрос".into() },
            },
            Ok(Err(e)) => Response::Error { message: format!("{e:#}") },
            Err(_) => Response::Error { message: "таймаут чтения запроса".into() },
        }
    };
    let _ = write_line(&mut stream, &resp).await;
    // Закрываем мягко: дочитываем остаток запроса, иначе RST может стереть ответ у клиента.
    // На Windows это же ожидание гарантирует, что клиент забрал ответ до закрытия pipe.
    let _ = stream.shutdown().await;
    let _ = tokio::time::timeout(Duration::from_secs(1), async {
        let mut sink = tokio::io::sink();
        let _ = tokio::io::copy(&mut (&mut stream).take(MAX_LINE as u64), &mut sink).await;
    })
    .await;
}

/// Принимать соединения. Обрабатывает по одному запросу на соединение.
#[cfg(unix)]
pub async fn serve<H, Fut>(listener: UnixListener, allowed_uid: u32, handler: H) -> Result<()>
where
    H: Fn(Request) -> Fut + Send + Sync + 'static,
    Fut: Future<Output = Response> + Send + 'static,
{
    let handler = Arc::new(handler);
    loop {
        let (stream, _) = listener.accept().await?;
        let h = handler.clone();
        tokio::spawn(async move {
            let allowed = stream
                .peer_cred()
                .map(|c| c.uid() == 0 || c.uid() == allowed_uid)
                .unwrap_or(false);
            handle_conn(stream, allowed, h).await;
        });
    }
}

/// Дескриптор безопасности из SDDL; освобождается через LocalFree.
#[cfg(windows)]
struct SecurityDescriptor(*mut std::ffi::c_void);

// Указатель принадлежит только этому значению и после создания не меняется, только читается.
#[cfg(windows)]
unsafe impl Send for SecurityDescriptor {}
#[cfg(windows)]
unsafe impl Sync for SecurityDescriptor {}

#[cfg(windows)]
impl SecurityDescriptor {
    /// Доступ через метод, чтобы замыкание (edition 2021, disjoint capture) захватывало всю обёртку (Send + Sync),
    /// а не голое поле `*mut c_void`.
    fn as_ptr(&self) -> *mut std::ffi::c_void {
        self.0
    }

    fn from_sddl(sddl: &str) -> Result<Self> {
        use windows_sys::Win32::Security::Authorization::{ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1};
        let wide: Vec<u16> = sddl.encode_utf16().chain(std::iter::once(0)).collect();
        let mut sd: *mut std::ffi::c_void = std::ptr::null_mut();
        let ok = unsafe { ConvertStringSecurityDescriptorToSecurityDescriptorW(wide.as_ptr(), SDDL_REVISION_1, &mut sd, std::ptr::null_mut()) };
        if ok == 0 || sd.is_null() {
            bail!("не удалось разобрать SDDL: {}", std::io::Error::last_os_error());
        }
        Ok(Self(sd))
    }
}

#[cfg(windows)]
impl Drop for SecurityDescriptor {
    fn drop(&mut self) {
        unsafe { windows_sys::Win32::Foundation::LocalFree(self.0) };
    }
}

/// Windows: слушать named pipe `name` с DACL `sddl`. Первый экземпляр создаётся с `first_pipe_instance`,
/// чтобы чужой процесс не мог занять имя раньше службы. Сетевые клиенты отклоняются.
#[cfg(windows)]
pub async fn serve_pipe<H, Fut>(name: &str, sddl: &str, handler: H) -> Result<()>
where
    H: Fn(Request) -> Fut + Send + Sync + 'static,
    Fut: Future<Output = Response> + Send + 'static,
{
    use tokio::net::windows::named_pipe::{NamedPipeServer, ServerOptions};
    use windows_sys::Win32::Security::SECURITY_ATTRIBUTES;

    let sd = SecurityDescriptor::from_sddl(sddl)?;
    // attrs собирается внутри замыкания и не живёт через .await: иначе future перестал бы быть Send
    let make = |first: bool| -> std::io::Result<NamedPipeServer> {
        let mut attrs = SECURITY_ATTRIBUTES {
            nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
            lpSecurityDescriptor: sd.as_ptr(),
            bInheritHandle: 0,
        };
        let mut o = ServerOptions::new();
        o.first_pipe_instance(first).reject_remote_clients(true).access_inbound(true).access_outbound(true);
        // SAFETY: attrs указывает на живую SECURITY_ATTRIBUTES с валидным дескриптором (sd живёт до конца функции);
        // WinAPI копирует дескриптор при создании pipe.
        unsafe { o.create_with_security_attributes_raw(name, &mut attrs as *mut _ as *mut std::ffi::c_void) }
    };

    let handler = Arc::new(handler);
    let mut server = make(true).with_context(|| format!("не удалось создать pipe {name}"))?;
    loop {
        server.connect().await?;
        let connected = std::mem::replace(&mut server, make(false)?); // следующий экземпляр готов до обработки текущего
        let h = handler.clone();
        // доступ ограничен DACL на самом pipe, дополнительной проверки владельца на стороне сервера нет
        tokio::spawn(handle_conn(connected, true, h));
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;

    /// Сервер разрешает uid текущего пользователя (владельца сокета). Тесты не должны зависеть от того,
    /// root ли запускает их: на CI они идут от обычного пользователя.
    async fn start_server(name: &str) -> PathBuf {
        use std::os::unix::fs::MetadataExt;
        let path = std::env::temp_dir().join(format!("el-ipc-{name}-{}.sock", std::process::id()));
        let _ = std::fs::remove_file(&path);
        let l = UnixListener::bind(&path).unwrap();
        let uid = std::fs::metadata(&path).unwrap().uid();
        tokio::spawn(serve(l, uid, |req| async move {
            match req {
                Request::Ping => Response::Pong { version: "t".into() },
                _ => Response::Error { message: "не в тесте".into() },
            }
        }));
        path
    }

    #[tokio::test]
    async fn ping_roundtrip_and_unknown_command() {
        let p = start_server("rt").await;
        match request(&p, &Request::Ping).await.unwrap() {
            Response::Pong { version } => assert_eq!(version, "t"),
            r => panic!("{r:?}"),
        }
        match request(&p, &Request::Stop).await.unwrap() {
            Response::Error { .. } => {}
            r => panic!("{r:?}"),
        }
        // сырой мусор и неизвестная команда не роняют сервер
        for raw in [&b"not json\n"[..], &br#"{"cmd":"exec","argv":["id"]}"#[..]] {
            let mut s = UnixStream::connect(&p).await.unwrap();
            s.write_all(raw).await.unwrap();
            s.write_all(b"\n").await.unwrap();
            let mut r = BufReader::new(&mut s);
            let line = read_line(&mut r).await.unwrap();
            let resp: Response = serde_json::from_slice(&line).unwrap();
            assert!(matches!(resp, Response::Error { ref message } if message == "некорректный запрос"));
        }
        assert!(matches!(request(&p, &Request::Ping).await.unwrap(), Response::Pong { .. }));
    }

    #[tokio::test]
    async fn oversized_request_is_rejected_and_server_survives() {
        let p = start_server("big").await;
        let mut s = UnixStream::connect(&p).await.unwrap();
        let big = vec![b'a'; MAX_LINE + 4096];
        let _ = s.write_all(&big).await; // сервер может закрыть соединение раньше конца записи
        let mut r = BufReader::new(&mut s);
        if let Ok(line) = read_line(&mut r).await {
            let resp: Response = serde_json::from_slice(&line).unwrap();
            assert!(matches!(resp, Response::Error { .. }));
        }
        assert!(matches!(request(&p, &Request::Ping).await.unwrap(), Response::Pong { .. }));
    }

    #[test]
    fn requests_serialize_with_cmd_tag() {
        assert_eq!(serde_json::to_string(&Request::Ping).unwrap(), r#"{"cmd":"ping"}"#);
        assert_eq!(serde_json::to_string(&Request::Stop).unwrap(), r#"{"cmd":"stop"}"#);
    }
}