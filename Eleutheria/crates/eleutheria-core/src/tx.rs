//! Журнал отката: каждый применённый шаг регистрирует команду-«отмену»,
//! при ошибке они выполняются в обратном порядке.

use crate::ssh::Ssh;

pub type Report<'a> = &'a (dyn Fn(&str) + Sync);

#[derive(Default)]
pub struct Tx {
    undo: Vec<(String, String)>,
}

impl Tx {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn push(&mut self, label: impl Into<String>, cmd: impl Into<String>) {
        self.undo.push((label.into(), cmd.into()));
    }

    pub fn is_empty(&self) -> bool {
        self.undo.is_empty()
    }

    pub async fn rollback(&mut self, ssh: &Ssh, report: Report<'_>) {
        while let Some((label, cmd)) = self.undo.pop() {
            report(&format!("Откат: {label}"));
            match ssh.run(&cmd).await {
                Ok(o) if o.code == 0 => {}
                Ok(o) => report(&format!("  откат «{label}» завершился с кодом {}: {}", o.code, o.stderr_str())),
                Err(e) => report(&format!("  не удалось откатить «{label}»: {e:#}")),
            }
        }
    }
}
