//! up/down script execution with the same environment variables as Go.
//!
//! Scripts run with a bounded wall-clock duration and bounded output so a
//! hung or noisy helper can never stall the data path or the shutdown
//! path indefinitely.

use std::process::Stdio;
use std::time::Duration;

use anyhow::{anyhow, Result};
use tokio::io::AsyncReadExt;
use tokio::process::Command;

use crate::{ENV_IFACE, ENV_REMOTE};

/// Upper bound for a single up/down script invocation.
#[cfg(not(test))]
const SCRIPT_TIMEOUT: Duration = Duration::from_secs(10);
// Keep the test bound short but not so tight that `cargo test --workspace`
// parallel scheduling can starve a trivial `echo` script.
#[cfg(test)]
const SCRIPT_TIMEOUT: Duration = Duration::from_secs(2);
/// Per-stream output cap; the interface name is the only expected output.
const MAX_OUTPUT: u64 = 64 * 1024;

pub async fn run_script(path: &str, iface: &str, remote: &str) -> Result<Option<String>> {
    if path.is_empty() {
        return Ok(None);
    }
    if !std::path::Path::new(path).exists() {
        return Err(anyhow!("script {path} does not exist"));
    }
    let mut child = Command::new(path)
        .env(ENV_IFACE, iface)
        .env(ENV_REMOTE, remote)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true)
        .spawn()
        .map_err(|e| anyhow!("spawn {path}: {e}"))?;

    let mut stdout = child
        .stdout
        .take()
        .ok_or_else(|| anyhow!("script {path}: no stdout"))?
        .take(MAX_OUTPUT);
    let mut stderr = child
        .stderr
        .take()
        .ok_or_else(|| anyhow!("script {path}: no stderr"))?
        .take(MAX_OUTPUT);

    let collect = async {
        let mut out = Vec::new();
        let mut err = Vec::new();
        let (r1, r2) = tokio::join!(stdout.read_to_end(&mut out), stderr.read_to_end(&mut err));
        let status = child.wait().await;
        (r1, r2, status, out, err)
    };

    match tokio::time::timeout(SCRIPT_TIMEOUT, collect).await {
        Err(_) => Err(anyhow!("script {path} timed out after {SCRIPT_TIMEOUT:?}")),
        Ok((Err(e), _, _, _, _)) => Err(anyhow!("script {path}: {e}")),
        Ok((_, Err(e), _, _, _)) => Err(anyhow!("script {path}: {e}")),
        Ok((_, _, Err(e), _, _)) => Err(anyhow!("script {path}: {e}")),
        Ok((_, _, Ok(status), out, _err)) if status.success() => {
            Ok(Some(String::from_utf8_lossy(&out).into_owned()))
        }
        Ok((_, _, Ok(status), _, err)) => Err(anyhow!(
            "script {path} failed: {status} {}",
            String::from_utf8_lossy(&err).trim()
        )),
    }
}

pub async fn call_up(path: &str, iface: &str, remote: &str) -> String {
    match run_script(path, iface, remote).await {
        Ok(Some(out)) if iface.is_empty() => out.lines().next().unwrap_or("").trim().to_string(),
        Ok(_) => iface.to_string(),
        Err(e) => {
            eprintln!("up script failed: {e:#}");
            iface.to_string()
        }
    }
}

pub async fn call_down(path: &str, iface: &str, remote: &str) {
    if let Err(e) = run_script(path, iface, remote).await {
        eprintln!("down script failed: {e:#}");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU64, Ordering};

    static SCRIPT_ID: AtomicU64 = AtomicU64::new(0);

    fn script(body: &str) -> PathBuf {
        let path = std::env::temp_dir().join(format!(
            "rustvpn-script-{}-{}",
            std::process::id(),
            SCRIPT_ID.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::write(&path, format!("#!/bin/sh\n{body}\n")).unwrap();
        let mut perm = std::fs::metadata(&path).unwrap().permissions();
        perm.set_mode(0o755);
        std::fs::set_permissions(&path, perm).unwrap();
        path
    }

    #[tokio::test]
    async fn returns_stdout_on_success() {
        let p = script("echo rsvpn0");
        let out = run_script(p.to_str().unwrap(), "tap0", "1.2.3.4")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(out.trim(), "rsvpn0");
        let _ = std::fs::remove_file(p);
    }

    #[tokio::test]
    async fn failure_and_missing_are_errors() {
        let p = script("exit 3");
        assert!(run_script(p.to_str().unwrap(), "tap0", "1.2.3.4")
            .await
            .is_err());
        let _ = std::fs::remove_file(p);
        assert!(run_script("/nonexistent/rustvpn-script", "tap0", "1.2.3.4")
            .await
            .is_err());
    }

    #[tokio::test]
    async fn hung_script_times_out() {
        let p = script("sleep 30");
        let started = std::time::Instant::now();
        assert!(run_script(p.to_str().unwrap(), "tap0", "1.2.3.4")
            .await
            .is_err());
        assert!(started.elapsed() < std::time::Duration::from_secs(5));
        let _ = std::fs::remove_file(p);
    }

    #[tokio::test]
    async fn call_up_uses_first_stdout_line_when_iface_empty() {
        let p = script("echo rsvpn9; echo ignored");
        let iface = call_up(p.to_str().unwrap(), "", "1.2.3.4").await;
        assert_eq!(iface, "rsvpn9");
        let _ = std::fs::remove_file(p);
    }
}
