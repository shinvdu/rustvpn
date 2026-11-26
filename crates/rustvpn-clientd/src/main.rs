//! RustVPN client daemon.
//!
//! Runs the tunnel with the privileges needed for TAP/routes and exposes a
//! local Unix socket to the GUI.  It does not link Tauri or any web view.

use std::collections::VecDeque;
use std::os::unix::fs::FileTypeExt;
use std::path::{Path, PathBuf};
use std::process;
use std::sync::{Arc, Mutex, RwLock};
use std::time::Duration;

use anyhow::{bail, Context, Result};
use rustvpn_client_core::{Command, Engine, EngineOptions, ValidatedProfile};
use rustvpn_client_ipc::{
    read_frame, write_frame, EngineStatus, Event, LogLine, ProfileSpec, Request, Response,
    PROTOCOL_VERSION, SOCKET_ENV,
};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::{broadcast, mpsc, Semaphore};
use tokio_util::sync::CancellationToken;
use zeroize::Zeroizing;

const DAEMON_VERSION: &str = env!("CARGO_PKG_VERSION");
const MAX_LOG_LINES: usize = 2000;
const DEFAULT_HELLO_TIMEOUT_SECS: u64 = 5;
const DEFAULT_IDLE_TIMEOUT_SECS: u64 = 300;
const WRITE_TIMEOUT: Duration = Duration::from_secs(10);

/// Content that proves the previous daemon removed its network state on a
/// clean shutdown.  A missing or truncated marker is treated as a crash so
/// the kill switch stays fail-closed.
const CLEAN_SHUTDOWN_MARKER: &[u8] = b"rustvpn-clientd clean shutdown v1\n";

/// Sibling state file next to the IPC socket (for systemd this lives in the
/// writable `RuntimeDirectory`).  Appending instead of `with_extension` keeps
/// the socket name intact and avoids clashing with `client.clean`.
fn clean_marker_path(socket: &Path) -> PathBuf {
    let mut name = socket.as_os_str().to_os_string();
    name.push(".clean");
    PathBuf::from(name)
}

fn previous_shutdown_was_clean(marker: &Path) -> bool {
    std::fs::read(marker)
        .map(|content| content == CLEAN_SHUTDOWN_MARKER)
        .unwrap_or(false)
}

fn write_clean_marker(marker: &Path) -> std::io::Result<()> {
    std::fs::write(marker, CLEAN_SHUTDOWN_MARKER)
}

fn remove_clean_marker(marker: &Path) {
    let _ = std::fs::remove_file(marker);
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum StartupFirewallCleanup {
    /// The previous daemon shut down cleanly: remove all of this instance's
    /// tables and start with a clean host.
    Clean,
    /// The previous daemon crashed: delete only the non-security MSS table and
    /// preserve the kill switch so the host stays fail-closed.
    AfterCrash,
}

fn startup_firewall_cleanup(previous_shutdown_was_clean: bool) -> StartupFirewallCleanup {
    if previous_shutdown_was_clean {
        StartupFirewallCleanup::Clean
    } else {
        StartupFirewallCleanup::AfterCrash
    }
}

struct Args {
    socket: PathBuf,
    socket_group: String,
    hello_timeout: Duration,
    idle_timeout: Duration,
    no_host_dns: bool,
    help: bool,
    version: bool,
}

fn usage() -> ! {
    eprintln!(
        "Usage of rustvpn-clientd:\n\
         \x20 -socket path (default {})\n\
         \x20 -socket-group group (optional; socket becomes 0660)\n\
         \x20 -hello-timeout seconds (default {DEFAULT_HELLO_TIMEOUT_SECS}; 0 disables)\n\
         \x20 -idle-timeout seconds (default {DEFAULT_IDLE_TIMEOUT_SECS}; 0 disables)\n\
         \x20 -no-host-dns (leave DNS to the caller; for netns/containers)\n\
         \x20 -version\n\
         \x20 -help\n\
         \n\
         The idle timeout closes connections that send no request; event\n\
         subscriptions are kept open for as long as the daemon runs.\n\
         The socket can also be chosen with {SOCKET_ENV}.",
        default_socket().display()
    );
    process::exit(2);
}

fn default_socket() -> PathBuf {
    if let Some(path) = std::env::var_os(SOCKET_ENV) {
        return PathBuf::from(path);
    }
    if unsafe { libc::geteuid() } == 0 {
        PathBuf::from("/run/rustvpn-client/client.sock")
    } else {
        rustvpn_client_ipc::default_socket_path()
    }
}

fn parse_args() -> Args {
    let mut args = Args {
        socket: default_socket(),
        socket_group: String::new(),
        hello_timeout: Duration::from_secs(DEFAULT_HELLO_TIMEOUT_SECS),
        idle_timeout: Duration::from_secs(DEFAULT_IDLE_TIMEOUT_SECS),
        no_host_dns: false,
        help: false,
        version: false,
    };
    let mut it = std::env::args().skip(1);
    while let Some(arg) = it.next() {
        let (name, inline) = match arg.split_once('=') {
            Some((name, value)) => (
                name.trim_start_matches('-').to_string(),
                Some(value.to_string()),
            ),
            None => (arg.trim_start_matches('-').to_string(), None),
        };
        let mut take = |name: &str| -> String {
            inline.clone().unwrap_or_else(|| {
                it.next().unwrap_or_else(|| {
                    eprintln!("flag needs an argument: -{name}");
                    usage();
                })
            })
        };
        match name.as_str() {
            "socket" => args.socket = PathBuf::from(take("socket")),
            "socket-group" => args.socket_group = take("socket-group"),
            "hello-timeout" => {
                let value = take("hello-timeout");
                args.hello_timeout = Duration::from_secs(parse_secs(&value, "hello-timeout"));
            }
            "idle-timeout" => {
                let value = take("idle-timeout");
                args.idle_timeout = Duration::from_secs(parse_secs(&value, "idle-timeout"));
            }
            "no-host-dns" => args.no_host_dns = true,
            "version" => args.version = true,
            "h" | "help" => args.help = true,
            "" => usage(),
            other => {
                eprintln!("flag provided but not defined: -{other}");
                usage();
            }
        }
    }
    if args.help {
        usage();
    }
    args
}

fn parse_secs(value: &str, flag: &str) -> u64 {
    value.parse::<u64>().unwrap_or_else(|_| {
        eprintln!("invalid value for -{flag}: {value:?} (expected whole seconds)");
        usage()
    })
}

#[derive(Clone)]
struct Shared {
    status: Arc<RwLock<EngineStatus>>,
    logs: Arc<Mutex<VecDeque<LogLine>>>,
    events: broadcast::Sender<Event>,
    commands: mpsc::Sender<Command>,
    shutdown: CancellationToken,
}

#[tokio::main]
async fn main() {
    let args = parse_args();
    if args.version {
        println!("rustvpn-clientd {DAEMON_VERSION}");
        return;
    }

    let gid = if args.socket_group.is_empty() {
        None
    } else {
        match resolve_gid(&args.socket_group) {
            Ok(gid) => Some(gid),
            Err(error) => {
                eprintln!("{error:#}");
                process::exit(1);
            }
        }
    };

    if let Err(error) = run(
        args.socket,
        gid,
        args.hello_timeout,
        args.idle_timeout,
        args.no_host_dns,
    )
    .await
    {
        eprintln!("{error:#}");
        process::exit(1);
    }
}

async fn run(
    socket_path: PathBuf,
    gid: Option<u32>,
    hello_timeout: Duration,
    idle_timeout: Duration,
    no_host_dns: bool,
) -> Result<()> {
    if socket_path.as_os_str().len() >= 100 {
        bail!("socket path is too long: {}", socket_path.display());
    }
    prepare_socket_parent(&socket_path)?;
    remove_stale_socket(&socket_path).await?;

    // Kill-switch crash policy.  Table names are scoped by the socket path, so
    // another RustVPN daemon in the same netns is not touched.
    //
    //  * clean shutdown marker present -> remove both tables (the host was
    //    restored on shutdown; this is also a backstop after a failed removal);
    //  * marker absent -> the previous instance crashed.  Preserve the
    //    kill-switch table (fail-closed), remove only MSS, and let the engine
    //    bootstrap through the preserved table on the next connect.
    //
    // The marker is removed before cleanup so a crash during startup is still
    // classified as a crash on the next start.
    let firewall_scope = rustvpn_client_core::firewall::instance_scope(&socket_path);
    let marker = clean_marker_path(&socket_path);
    let clean = previous_shutdown_was_clean(&marker);
    remove_clean_marker(&marker);
    match startup_firewall_cleanup(clean) {
        StartupFirewallCleanup::Clean => {
            rustvpn_client_core::netcfg::cleanup_stale_firewall(&firewall_scope).await;
        }
        StartupFirewallCleanup::AfterCrash => {
            rustvpn_client_core::netcfg::cleanup_stale_mss(&firewall_scope).await;
            // Keep the table and guarantee its drop-policy chain exists even if
            // the crash happened mid-create.  No DNS is allowed while idle.
            match rustvpn_client_core::firewall::bootstrap_kill_switch(&firewall_scope, None, false)
                .await
            {
                Ok(true) => eprintln!(
                    "previous run did not shut down cleanly; preserving this instance's \
                     kill-switch table (fail-closed) until a connection replaces it or an \
                     explicit disconnect removes it"
                ),
                Ok(false) => {}
                Err(error) => eprintln!(
                    "previous run did not shut down cleanly; cannot verify this instance's \
                     kill-switch table: {error:#}"
                ),
            }
        }
    }

    let (commands_tx, commands_rx) = mpsc::channel(8);
    let (events_tx, _) = broadcast::channel(256);
    let shutdown = CancellationToken::new();
    let status = Arc::new(RwLock::new(EngineStatus {
        state: "idle".into(),
        ..EngineStatus::default()
    }));
    let logs = Arc::new(Mutex::new(VecDeque::with_capacity(MAX_LOG_LINES)));
    let shared = Shared {
        status: status.clone(),
        logs: logs.clone(),
        events: events_tx.clone(),
        commands: commands_tx,
        shutdown: shutdown.clone(),
    };

    let engine = Engine::spawn_with_options(
        commands_rx,
        events_tx.clone(),
        EngineOptions {
            no_host_dns,
            firewall_scope: firewall_scope.clone(),
        },
    );
    spawn_collector(events_tx.clone(), status.clone(), logs.clone());

    let listener = UnixListener::bind(&socket_path)
        .with_context(|| format!("bind {}", socket_path.display()))?;
    apply_socket_permissions(&socket_path, gid)?;
    eprintln!(
        "rustvpn-clientd {DAEMON_VERSION} listening on {} (mode {})",
        socket_path.display(),
        if gid.is_some() { "0660" } else { "0600" }
    );

    let accept_shared = shared.clone();
    let accept = tokio::spawn(async move {
        accept_loop(listener, accept_shared, gid, hello_timeout, idle_timeout).await;
    });

    tokio::select! {
        _ = shutdown.cancelled() => {}
        _ = wait_signal() => shutdown.cancel(),
    }
    let _ = shared.commands.send(Command::Shutdown).await;
    let _ = engine.await;
    accept.abort();
    // The engine removed the guard (routes, DNS, kill switch, MSS) before it
    // returned.  A crash-preserved kill switch may still exist when the daemon
    // was stopped while idle; a clean stop restores connectivity.  Record that
    // so the next start removes any leftovers instead of treating them as a
    // crash.
    rustvpn_client_core::netcfg::cleanup_stale_firewall(&firewall_scope).await;
    if let Err(error) = write_clean_marker(&marker) {
        eprintln!(
            "warning: cannot write clean-shutdown marker {}: {error}",
            marker.display()
        );
    }
    let _ = std::fs::remove_file(&socket_path);
    eprintln!("rustvpn-clientd stopped");
    Ok(())
}

fn spawn_collector(
    events: broadcast::Sender<Event>,
    status: Arc<RwLock<EngineStatus>>,
    logs: Arc<Mutex<VecDeque<LogLine>>>,
) {
    let mut rx = events.subscribe();
    tokio::spawn(async move {
        loop {
            match rx.recv().await {
                Ok(Event::State(next)) => {
                    if let Ok(mut current) = status.write() {
                        *current = next;
                    }
                }
                Ok(Event::Traffic(sample)) => {
                    if let Ok(mut current) = status.write() {
                        current.traffic = sample;
                    }
                }
                Ok(Event::Log(line)) => {
                    eprintln!("[{}] {}", line.level, line.line);
                    if let Ok(mut ring) = logs.lock() {
                        if ring.len() >= MAX_LOG_LINES {
                            ring.pop_front();
                        }
                        ring.push_back(line);
                    }
                }
                Ok(Event::Lagged { missed }) => {
                    eprintln!("client event collector lagged by {missed} event(s)");
                }
                Err(broadcast::error::RecvError::Lagged(missed)) => {
                    eprintln!("client event collector lagged by {missed} event(s)");
                }
                Err(broadcast::error::RecvError::Closed) => break,
            }
        }
    });
}

async fn accept_loop(
    listener: UnixListener,
    shared: Shared,
    gid: Option<u32>,
    hello_timeout: Duration,
    idle_timeout: Duration,
) {
    let limit = Arc::new(Semaphore::new(16));
    loop {
        let (stream, _) = match listener.accept().await {
            Ok(pair) => pair,
            Err(error) => {
                eprintln!("accept failed: {error}");
                tokio::time::sleep(Duration::from_secs(1)).await;
                continue;
            }
        };
        if !peer_allowed(&stream, gid) {
            eprintln!("rejected unauthorized IPC client");
            continue;
        }
        let Ok(permit) = limit.clone().try_acquire_owned() else {
            eprintln!("too many IPC connections; dropping client");
            continue;
        };
        let shared = shared.clone();
        tokio::spawn(async move {
            let _permit = permit;
            if let Err(error) = handle_connection(stream, shared, hello_timeout, idle_timeout).await
            {
                eprintln!("IPC client failed: {error:#}");
            }
        });
    }
}

async fn handle_connection(
    mut stream: UnixStream,
    shared: Shared,
    hello_timeout: Duration,
    idle_timeout: Duration,
) -> Result<()> {
    let Some(hello) = read_request(&mut stream, hello_timeout, "client hello").await? else {
        return Ok(());
    };
    match hello {
        Request::Hello { version } if version == PROTOCOL_VERSION => {
            write_value(
                &mut stream,
                &Response::Hello {
                    version: PROTOCOL_VERSION,
                    daemon_version: DAEMON_VERSION.into(),
                },
            )
            .await?;
        }
        Request::Hello { version } => {
            write_value(
                &mut stream,
                &Response::Error {
                    message: format!(
                        "protocol mismatch: daemon v{PROTOCOL_VERSION}, client v{version}"
                    ),
                },
            )
            .await?;
            return Ok(());
        }
        _ => {
            write_value(
                &mut stream,
                &Response::Error {
                    message: "hello required".into(),
                },
            )
            .await?;
            return Ok(());
        }
    }

    loop {
        let Some(request) = read_request(&mut stream, idle_timeout, "idle IPC client").await?
        else {
            return Ok(());
        };
        let response = match request {
            Request::Hello { .. } => Response::Error {
                message: "already greeted".into(),
            },
            Request::Status => {
                let status = shared
                    .status
                    .read()
                    .map(|status| status.clone())
                    .unwrap_or_default();
                Response::Status {
                    status: Box::new(status),
                }
            }
            Request::Connect { profile, password } => {
                if let Err(error) = ValidatedProfile::new(profile.as_ref()) {
                    Response::Error {
                        message: format!("{error:#}"),
                    }
                } else {
                    connect(*profile, password, &shared).await
                }
            }
            Request::Disconnect => match shared.commands.send(Command::Disconnect).await {
                Ok(()) => Response::Ok,
                Err(_) => Response::Error {
                    message: "engine unavailable".into(),
                },
            },
            Request::Logs { limit } => {
                let lines: Vec<LogLine> = shared
                    .logs
                    .lock()
                    .map(|ring| {
                        let take = if limit == 0 {
                            ring.len()
                        } else {
                            (limit as usize).min(ring.len())
                        };
                        ring.iter().skip(ring.len() - take).cloned().collect()
                    })
                    .unwrap_or_default();
                Response::Logs { lines }
            }
            Request::Shutdown => {
                let _ = shared.commands.send(Command::Shutdown).await;
                shared.shutdown.cancel();
                Response::Ok
            }
            Request::Subscribe => {
                write_value(&mut stream, &Response::Subscribed).await?;
                let (read, write) = stream.into_split();
                subscribe_loop(read, write, &shared).await?;
                return Ok(());
            }
        };
        write_value(&mut stream, &response).await?;
    }
}

async fn read_request<R>(reader: &mut R, limit: Duration, what: &str) -> Result<Option<Request>>
where
    R: AsyncRead + Unpin,
{
    if limit.is_zero() {
        return Ok(read_frame(reader).await?);
    }
    match tokio::time::timeout(limit, read_frame::<_, Request>(reader)).await {
        Ok(result) => Ok(result?),
        Err(_) => bail!("{what} timed out after {}s", limit.as_secs()),
    }
}

async fn write_value<W, T>(writer: &mut W, value: &T) -> Result<()>
where
    W: AsyncWrite + Unpin,
    T: serde::Serialize + ?Sized,
{
    match tokio::time::timeout(WRITE_TIMEOUT, write_frame(writer, value)).await {
        Ok(result) => Ok(result?),
        Err(_) => bail!("IPC write timed out after {}s", WRITE_TIMEOUT.as_secs()),
    }
}

async fn connect(profile: ProfileSpec, password: String, shared: &Shared) -> Response {
    let command = Command::Connect {
        profile: Box::new(profile),
        password: Zeroizing::new(password),
    };
    match shared.commands.send(command).await {
        Ok(()) => Response::Ok,
        Err(_) => Response::Error {
            message: "engine unavailable".into(),
        },
    }
}

async fn subscribe_loop(
    mut read: tokio::net::unix::OwnedReadHalf,
    mut write: tokio::net::unix::OwnedWriteHalf,
    shared: &Shared,
) -> Result<()> {
    let mut rx = shared.events.subscribe();
    loop {
        tokio::select! {
            event = rx.recv() => match event {
                Ok(event) => {
                    if write_value(&mut write, &event).await.is_err() {
                        return Ok(());
                    }
                }
                Err(broadcast::error::RecvError::Lagged(missed)) => {
                    if write_value(&mut write, &Event::Lagged { missed }).await.is_err() {
                        return Ok(());
                    }
                }
                Err(broadcast::error::RecvError::Closed) => return Ok(()),
            },
            incoming = read_frame::<_, Request>(&mut read) => {
                match incoming {
                    Ok(None) => return Ok(()),
                    Ok(Some(_)) => {
                        // A subscriber connection must not multiplex commands.
                        return Ok(());
                    }
                    Err(_) => return Ok(()),
                }
            }
        }
    }
}

async fn wait_signal() {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{signal, SignalKind};
        let mut term = signal(SignalKind::terminate()).expect("SIGTERM handler");
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {},
            _ = term.recv() => {},
        }
    }
    #[cfg(not(unix))]
    {
        let _ = tokio::signal::ctrl_c().await;
    }
}

fn prepare_socket_parent(path: &Path) -> Result<()> {
    let Some(parent) = path.parent() else {
        return Ok(());
    };
    let existed = parent.exists();
    std::fs::create_dir_all(parent).with_context(|| format!("create {}", parent.display()))?;
    #[cfg(unix)]
    if !existed {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = std::fs::metadata(parent)?.permissions();
        let system = parent == Path::new("/run/rustvpn-client");
        perms.set_mode(if system { 0o755 } else { 0o700 });
        std::fs::set_permissions(parent, perms)?;
    }
    Ok(())
}

async fn remove_stale_socket(path: &Path) -> Result<()> {
    let meta = match std::fs::symlink_metadata(path) {
        Ok(meta) => meta,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error.into()),
    };
    if !meta.file_type().is_socket() {
        bail!("{} exists and is not a socket", path.display());
    }
    match UnixStream::connect(path).await {
        Ok(_) => bail!(
            "another rustvpn-clientd is already listening on {}",
            path.display()
        ),
        Err(error) if error.kind() == std::io::ErrorKind::ConnectionRefused => {
            std::fs::remove_file(path)
                .with_context(|| format!("remove stale socket {}", path.display()))?;
        }
        Err(error) => {
            return Err(error).with_context(|| format!("probe existing socket {}", path.display()));
        }
    }
    Ok(())
}

fn apply_socket_permissions(path: &Path, gid: Option<u32>) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = std::fs::metadata(path)?.permissions();
        perms.set_mode(if gid.is_some() { 0o660 } else { 0o600 });
        std::fs::set_permissions(path, perms)?;
        if let Some(gid) = gid {
            use std::os::unix::fs::MetadataExt;
            if std::fs::metadata(path)?.gid() != gid {
                std::os::unix::fs::chown(path, None, Some(gid))
                    .with_context(|| format!("chown socket to gid {gid}"))?;
            }
        }
    }
    Ok(())
}

fn peer_allowed(stream: &UnixStream, gid: Option<u32>) -> bool {
    let Ok(cred) = stream.peer_cred() else {
        return false;
    };
    if cred.uid() == 0 || cred.uid() == unsafe { libc::geteuid() } {
        return true;
    }
    if let Some(gid) = gid {
        if cred.gid() == gid {
            return true;
        }
        if let Some(pid) = cred.pid() {
            return supplementary_has_gid(pid, gid);
        }
        return false;
    }
    cred.uid() == unsafe { libc::geteuid() }
}

/// `SO_PEERCRED` only reports the primary gid; desktop users join the
/// service group as a supplementary group, so consult `/proc/<pid>/status`.
fn supplementary_has_gid(pid: i32, gid: u32) -> bool {
    let path = format!("/proc/{pid}/status");
    let Ok(status) = std::fs::read_to_string(path) else {
        return false;
    };
    let Some(line) = status.lines().find(|line| line.starts_with("Groups:")) else {
        return false;
    };
    line["Groups:".len()..]
        .split_whitespace()
        .filter_map(|value| value.parse::<u32>().ok())
        .any(|value| value == gid)
}

fn resolve_gid(name: &str) -> Result<u32> {
    if let Ok(gid) = name.parse::<u32>() {
        return Ok(gid);
    }
    let groups = std::fs::read_to_string("/etc/group").context("read /etc/group")?;
    for line in groups.lines() {
        let mut fields = line.split(':');
        if fields.next() == Some(name) {
            let _password = fields.next();
            if let Some(gid) = fields.next() {
                return gid
                    .parse()
                    .with_context(|| format!("invalid gid for group {name}"));
            }
        }
    }
    bail!("group {name} not found in /etc/group")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    #[test]
    fn numeric_gid_is_accepted() {
        assert_eq!(resolve_gid("12345").unwrap(), 12345);
    }

    #[test]
    fn supplementary_groups_include_primary_group() {
        let gid = unsafe { libc::getegid() };
        assert!(supplementary_has_gid(std::process::id() as i32, gid));
        assert!(!supplementary_has_gid(std::process::id() as i32, u32::MAX));
    }

    #[test]
    fn timeout_values_are_whole_seconds() {
        assert_eq!(parse_secs("0", "idle-timeout"), 0);
        assert_eq!(parse_secs("300", "idle-timeout"), 300);
    }

    #[tokio::test]
    async fn silent_client_hits_idle_timeout() {
        let (_client, mut server) = tokio::io::duplex(64);
        let error = read_request(&mut server, Duration::from_millis(25), "idle IPC client")
            .await
            .unwrap_err();
        assert!(format!("{error:#}").contains("timed out"), "{error:#}");
    }

    #[tokio::test]
    async fn disabled_timeout_accepts_eof() {
        let (client, mut server) = tokio::io::duplex(64);
        drop(client);
        assert!(read_request(&mut server, Duration::ZERO, "idle IPC client")
            .await
            .unwrap()
            .is_none());
    }

    #[test]
    fn clean_shutdown_marker_requires_exact_complete_content() {
        let dir =
            std::env::temp_dir().join(format!("rustvpn-clientd-marker-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let socket = dir.join("client.sock");
        let marker = clean_marker_path(&socket);
        assert_eq!(marker, dir.join("client.sock.clean"));
        assert!(!previous_shutdown_was_clean(&marker));

        // A crash during marker creation must not be mistaken for a clean
        // shutdown (which would delete a fail-closed kill switch).
        std::fs::write(&marker, b"rustvpn-clientd clean").unwrap();
        assert!(!previous_shutdown_was_clean(&marker));

        write_clean_marker(&marker).unwrap();
        assert!(previous_shutdown_was_clean(&marker));
        remove_clean_marker(&marker);
        assert!(!marker.exists());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn startup_policy_preserves_the_kill_switch_only_after_a_crash() {
        assert_eq!(
            startup_firewall_cleanup(true),
            StartupFirewallCleanup::Clean
        );
        assert_eq!(
            startup_firewall_cleanup(false),
            StartupFirewallCleanup::AfterCrash
        );
    }

    #[test]
    fn socket_permissions_are_owner_only_without_group() {
        let path =
            std::env::temp_dir().join(format!("rustvpn-clientd-mode-{}", std::process::id()));
        std::fs::write(&path, b"").unwrap();
        apply_socket_permissions(&path, None).unwrap();
        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
        let _ = std::fs::remove_file(path);
    }
}
