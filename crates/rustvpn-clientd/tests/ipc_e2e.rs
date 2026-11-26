//! Console-mode end-to-end test for the daemon IPC.
//!
//! On Unix it uses a temporary Unix socket; on Windows it uses a uniquely
//! named pipe.  It never connects a VPN or touches host network state: the
//! daemon is started with a fake `nft` binary on Unix and the Windows startup
//! path has no firewall work in M2.

use std::path::PathBuf;
use std::process::Stdio;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use rustvpn_client_ipc::{Client, Event, EventStream, Request, Response};
use tokio::process::{Child, Command};

static NEXT: AtomicU64 = AtomicU64::new(0);

#[cfg(unix)]
fn endpoint() -> PathBuf {
    std::env::temp_dir().join(format!(
        "rustvpn-clientd-e2e-{}-{}.sock",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    ))
}

#[cfg(windows)]
fn endpoint() -> PathBuf {
    PathBuf::from(format!(
        r"\\.\pipe\rustvpn-clientd-e2e-{}-{}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    ))
}

fn spawn_daemon(path: &PathBuf) -> Child {
    let mut command = Command::new(env!("CARGO_BIN_EXE_rustvpn-clientd"));
    command
        .arg("-console")
        .arg("-socket")
        .arg(path)
        .arg("-hello-timeout")
        .arg("5")
        .arg("-idle-timeout")
        .arg("30")
        .stdout(Stdio::null())
        .stderr(Stdio::inherit())
        .kill_on_drop(true);
    #[cfg(unix)]
    command.env("RUSTVPN_NFT_BIN", "/bin/true");
    command.spawn().expect("spawn rustvpn-clientd")
}

async fn connect_with_retry(path: &PathBuf) -> Client {
    for _ in 0..200 {
        match Client::connect(path).await {
            Ok(client) => return client,
            Err(_) => tokio::time::sleep(Duration::from_millis(25)).await,
        }
    }
    panic!("daemon did not accept a connection on {}", path.display());
}

#[tokio::test]
async fn console_mode_serves_status_logs_events_and_stops() {
    let path = endpoint();
    let mut child = spawn_daemon(&path);
    let mut client = connect_with_retry(&path).await;

    let status = client.status().await.expect("status");
    assert_eq!(status.state, "idle");
    // The log ring starts empty; startup messages go to stderr only.
    client.logs(10).await.expect("logs");

    let mut events = EventStream::subscribe(&path).await.expect("subscribe");

    // Disconnect on an idle engine emits an idle state and a log line.
    client.disconnect().await.expect("disconnect");
    let event = tokio::time::timeout(Duration::from_secs(5), events.next())
        .await
        .expect("event timeout")
        .expect("event stream error")
        .expect("event stream closed");
    assert!(
        matches!(event, Event::State(_) | Event::Log(_)),
        "unexpected event {event:?}"
    );

    let mut saw_log = false;
    for _ in 0..100 {
        let logs = client.logs(20).await.expect("logs");
        if logs.iter().any(|line| line.line.contains("disconnected")) {
            saw_log = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert!(saw_log, "disconnect log did not reach the log ring");

    match client.request(Request::Shutdown).await.expect("shutdown") {
        Response::Ok => {}
        other => panic!("unexpected shutdown response: {other:?}"),
    }
    let status = tokio::time::timeout(Duration::from_secs(10), child.wait())
        .await
        .expect("daemon did not exit")
        .expect("wait failed");
    assert!(status.success(), "daemon exited with {status}");
    cleanup(&path);
}

#[cfg(unix)]
fn cleanup(path: &PathBuf) {
    let _ = std::fs::remove_file(path);
    let mut marker = path.as_os_str().to_os_string();
    marker.push(".clean");
    let _ = std::fs::remove_file(PathBuf::from(marker));
}

#[cfg(windows)]
fn cleanup(_path: &PathBuf) {}
