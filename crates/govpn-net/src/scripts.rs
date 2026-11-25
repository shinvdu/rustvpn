//! up/down script execution with the same environment variables as Go.

use std::process::Stdio;

use anyhow::Result;
use tokio::process::Command;

use crate::{ENV_IFACE, ENV_REMOTE};

pub async fn run_script(path: &str, iface: &str, remote: &str) -> Result<Option<String>> {
    if path.is_empty() {
        return Ok(None);
    }
    if !std::path::Path::new(path).exists() {
        return Err(anyhow::anyhow!("script {path} does not exist"));
    }
    let output = Command::new(path)
        .env(ENV_IFACE, iface)
        .env(ENV_REMOTE, remote)
        .stdin(Stdio::null())
        .output()
        .await?;
    if !output.status.success() {
        eprintln!(
            "script {path} failed: {} {}",
            output.status,
            String::from_utf8_lossy(&output.stderr)
        );
        return Ok(None);
    }
    Ok(Some(String::from_utf8_lossy(&output.stdout).into_owned()))
}

pub async fn call_up(path: &str, iface: &str, remote: &str) -> String {
    match run_script(path, iface, remote).await {
        Ok(Some(out)) if iface.is_empty() => out.lines().next().unwrap_or("").trim().to_string(),
        _ => iface.to_string(),
    }
}

pub async fn call_down(path: &str, iface: &str, remote: &str) {
    let _ = run_script(path, iface, remote).await;
}
