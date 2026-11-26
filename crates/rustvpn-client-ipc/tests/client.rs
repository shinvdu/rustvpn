use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

use rustvpn_client_ipc::transport::{self, ListenOptions};
use rustvpn_client_ipc::{
    read_frame, write_frame, Client, EngineStatus, Event, Request, Response, PROTOCOL_VERSION,
};

static NEXT: AtomicU64 = AtomicU64::new(0);

#[cfg(unix)]
fn socket_path() -> PathBuf {
    std::env::temp_dir().join(format!(
        "rustvpn-ipc-test-{}-{}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    ))
}

#[cfg(windows)]
fn socket_path() -> PathBuf {
    PathBuf::from(format!(
        r"\\.\pipe\rustvpn-ipc-test-{}-{}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    ))
}

async fn fake_daemon(path: PathBuf) -> tokio::task::JoinHandle<()> {
    let mut listener = transport::Listener::bind(&path, &ListenOptions::default()).unwrap();
    tokio::spawn(async move {
        let mut stream = listener.accept().await.unwrap();
        let hello: Request = read_frame(&mut stream).await.unwrap().unwrap();
        assert!(matches!(hello, Request::Hello { version } if version == PROTOCOL_VERSION));
        write_frame(
            &mut stream,
            &Response::Hello {
                version: PROTOCOL_VERSION,
                daemon_version: "test".into(),
            },
        )
        .await
        .unwrap();

        let request: Request = read_frame(&mut stream).await.unwrap().unwrap();
        assert!(matches!(request, Request::Status));
        write_frame(
            &mut stream,
            &Response::Status {
                status: Box::new(EngineStatus {
                    state: "connected".into(),
                    profile: Some("office".into()),
                    ..EngineStatus::default()
                }),
            },
        )
        .await
        .unwrap();
    })
}

#[tokio::test]
async fn client_handshakes_and_requests_status() {
    let path = socket_path();
    let server = fake_daemon(path.clone()).await;
    let mut client = Client::connect(&path).await.unwrap();
    let status = client.status().await.unwrap();
    assert_eq!(status.state, "connected");
    assert_eq!(status.profile.as_deref(), Some("office"));
    server.await.unwrap();
    cleanup(&path);
}

#[tokio::test]
async fn subscribe_receives_events() {
    let path = socket_path();
    let mut listener = transport::Listener::bind(&path, &ListenOptions::default()).unwrap();
    let server = tokio::spawn(async move {
        let mut stream = listener.accept().await.unwrap();
        let _: Request = read_frame(&mut stream).await.unwrap().unwrap();
        write_frame(
            &mut stream,
            &Response::Hello {
                version: PROTOCOL_VERSION,
                daemon_version: "test".into(),
            },
        )
        .await
        .unwrap();
        let _: Request = read_frame(&mut stream).await.unwrap().unwrap();
        write_frame(&mut stream, &Response::Subscribed)
            .await
            .unwrap();
        write_frame(
            &mut stream,
            &Event::Log(rustvpn_client_ipc::LogLine {
                ts_ms: 1,
                level: "info".into(),
                line: "connected".into(),
            }),
        )
        .await
        .unwrap();
    });
    let mut stream = rustvpn_client_ipc::EventStream::subscribe(&path)
        .await
        .unwrap();
    let event = stream.next().await.unwrap().unwrap();
    assert!(matches!(event, Event::Log(line) if line.line == "connected"));
    server.await.unwrap();
    cleanup(&path);
}

#[cfg(unix)]
fn cleanup(path: &PathBuf) {
    let _ = std::fs::remove_file(path);
}

#[cfg(windows)]
fn cleanup(_path: &PathBuf) {
    // The pipe disappears when the last handle is closed.
}
