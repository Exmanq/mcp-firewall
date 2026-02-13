use anyhow::Context;
use chrono::Utc;
use serde::Serialize;
use std::{fs::OpenOptions, io::Write, path::PathBuf};

#[derive(Debug, Clone)]
pub struct AuditLogger {
    path: PathBuf,
}

#[derive(Debug, Serialize)]
pub struct AuditEvent {
    pub request_id: String,
    pub method: String,
    pub allowed: bool,
    pub reason: String,
    pub origin: Option<String>,
    pub upstream_status: Option<u16>,
    pub timestamp: String,
}

impl AuditLogger {
    pub fn new(path: PathBuf) -> Self {
        Self { path }
    }

    pub fn log(&self, mut event: AuditEvent) -> anyhow::Result<()> {
        event.timestamp = Utc::now().to_rfc3339();
        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)
            .with_context(|| format!("failed to open audit log at {}", self.path.display()))?;
        let line = serde_json::to_string(&event)?;
        writeln!(file, "{line}")?;
        Ok(())
    }
}
