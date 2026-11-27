//! RustVPN client daemon.
//!
//! Runs the tunnel with the privileges needed for TAP/routes and exposes a
//! local IPC endpoint to the GUI.  On Unix this is a Unix domain socket; on
//! Windows it is a named pipe and the process can run as an SCM service.  It
//! does not link Tauri or any web view.

use std::collections::VecDeque;
#[cfg(unix)]
use std::os::unix::fs::FileTypeExt;
#[cfg(unix)]
use std::path::Path;
use std::path::PathBuf;
use std::process;
use std::sync::{Arc, Mutex, OnceLock, RwLock};
use std::time::Duration;

use anyhow::{bail, Context, Result};
use rustvpn_client_core::{Command, Engine, EngineOptions, ValidatedProfile};
use rustvpn_client_ipc::transport::{self, Connection};
use rustvpn_client_ipc::{
    read_frame, write_frame, EngineStatus, Event, LogLine, ProfileSpec, Request, Response,
    PROTOCOL_VERSION, SOCKET_ENV,
};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::sync::{broadcast, mpsc, Semaphore};
use tokio_util::sync::CancellationToken;
use zeroize::Zeroizing;

const DAEMON_VERSION: &str = env!("CARGO_PKG_VERSION");
const MAX_LOG_LINES: usize = 2000;
const MAX_LOG_LINE_CHARS: usize = 1024;
const MAX_LOGS_RESPONSE_LINES: usize = 256;
const DEFAULT_HELLO_TIMEOUT_SECS: u64 = 5;
const DEFAULT_IDLE_TIMEOUT_SECS: u64 = 300;
const WRITE_TIMEOUT: Duration = Duration::from_secs(10);

/// Content that proves the previous daemon removed its network state on a
/// clean shutdown.  A missing or truncated marker is treated as a crash so
/// the kill switch stays fail-closed.
#[cfg(unix)]
const CLEAN_SHUTDOWN_MARKER: &[u8] = b"rustvpn-clientd clean shutdown v1\n";

static LOG_FILE: OnceLock<Mutex<std::fs::File>> = OnceLock::new();

/// Write one daemon log line to stderr and, when configured, to a file.  In
/// Windows service mode stderr is not visible, so the file is the primary
/// sink until Event Log integration is added in M5.
macro_rules! dlog {
    ($($arg:tt)*) => {{
        let line = $crate::truncate_log_line(&format!($($arg)*));
        eprintln!("{line}");
        $crate::write_log_file(&line);
    }};
}

fn truncate_log_line(line: &str) -> String {
    if line.chars().count() <= MAX_LOG_LINE_CHARS {
        return line.to_string();
    }
    let mut text: String = line.chars().take(MAX_LOG_LINE_CHARS).collect();
    text.push('…');
    text
}

fn write_log_file(line: &str) {
    use std::io::Write;
    if let Some(file) = LOG_FILE.get() {
        if let Ok(mut file) = file.lock() {
            let _ = writeln!(file, "{line}");
            let _ = file.flush();
        }
    }
}

fn init_log_file(path: Option<PathBuf>) {
    let Some(path) = path else {
        return;
    };
    if let Some(parent) = path.parent() {
        if std::fs::create_dir_all(parent).is_err() {
            return;
        }
    }
    if let Ok(file) = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
    {
        let _ = LOG_FILE.set(Mutex::new(file));
    }
}

fn init_console_log() {
    if let Some(path) = std::env::var_os("RUSTVPN_CLIENTD_LOG") {
        init_log_file(Some(PathBuf::from(path)));
    }
}

/// Default service log: `%ProgramData%\RustVPN\clientd.log`.
#[cfg(windows)]
fn init_service_log() {
    let path = std::env::var_os("RUSTVPN_CLIENTD_LOG")
        .map(PathBuf::from)
        .or_else(|| {
            std::env::var_os("ProgramData")
                .map(|dir| PathBuf::from(dir).join("RustVPN").join("clientd.log"))
        });
    let Some(path) = path else {
        return;
    };
    if let Some(parent) = path.parent() {
        if let Err(error) = rustvpn_client_core::netcfg::ensure_secure_state_dir(parent) {
            eprintln!("refusing to write the service log under an insecure directory: {error:#}");
            return;
        }
    }
    init_log_file(Some(path.clone()));
    if let Err(error) = rustvpn_client_core::netcfg::harden_state_file(&path) {
        eprintln!(
            "cannot restrict the service log ACL {}: {error:#}",
            path.display()
        );
    }
}

#[cfg(windows)]
mod service;

/// Sibling state file next to the IPC socket (for systemd this lives in the
/// writable `RuntimeDirectory`).  Appending instead of `with_extension` keeps
/// the socket name intact and avoids clashing with `client.clean`.
#[cfg(unix)]
fn clean_marker_path(socket: &Path) -> PathBuf {
    let mut name = socket.as_os_str().to_os_string();
    name.push(".clean");
    PathBuf::from(name)
}

#[cfg(unix)]
fn previous_shutdown_was_clean(marker: &Path) -> bool {
    std::fs::read(marker)
        .map(|content| content == CLEAN_SHUTDOWN_MARKER)
        .unwrap_or(false)
}

#[cfg(unix)]
fn write_clean_marker(marker: &Path) -> std::io::Result<()> {
    std::fs::write(marker, CLEAN_SHUTDOWN_MARKER)
}

#[cfg(unix)]
fn remove_clean_marker(marker: &Path) {
    let _ = std::fs::remove_file(marker);
}

#[cfg(unix)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum StartupFirewallCleanup {
    /// The previous daemon shut down cleanly: remove all of this instance's
    /// tables and start with a clean host.
    Clean,
    /// The previous daemon crashed: delete only the non-security MSS table and
    /// preserve the kill switch so the host stays fail-closed.
    AfterCrash,
}

#[cfg(unix)]
fn startup_firewall_cleanup(previous_shutdown_was_clean: bool) -> StartupFirewallCleanup {
    if previous_shutdown_was_clean {
        StartupFirewallCleanup::Clean
    } else {
        StartupFirewallCleanup::AfterCrash
    }
}

struct Args {
    socket: PathBuf,
    #[cfg_attr(windows, allow(dead_code))]
    socket_group: String,
    #[cfg_attr(unix, allow(dead_code))]
    pipe_group: Option<String>,
    #[cfg_attr(unix, allow(dead_code))]
    service: bool,
    #[cfg_attr(unix, allow(dead_code))]
    console: bool,
    hello_timeout: Duration,
    idle_timeout: Duration,
    no_host_dns: bool,
    help: bool,
    version: bool,
    cleanup: bool,
}

fn usage() -> ! {
    eprintln!(
        "Usage of rustvpn-clientd:\n\
         \x20 -socket path (default {})\n\
         \x20 -socket-group group (Unix; socket becomes 0660)\n\
         \x20 -pipe-group group (Windows; restrict the pipe to a local group)\n\
         \x20 -hello-timeout seconds (default {DEFAULT_HELLO_TIMEOUT_SECS}; 0 disables)\n\
         \x20 -idle-timeout seconds (default {DEFAULT_IDLE_TIMEOUT_SECS}; 0 disables)\n\
         \x20 -no-host-dns (leave DNS to the caller; for netns/containers)\n\
         \x20 -console (run in the foreground; the default on Unix)\n\
         \x20 -service (Windows SCM service mode)\n\
         \x20 -version\n\
         \x20 -help\n\
         \n\
         The idle timeout closes connections that send no request; event\n\
         subscriptions are kept open for as long as the daemon runs.\n\
         The endpoint can also be chosen with {SOCKET_ENV}.",
        default_socket().display()
    );
    process::exit(2);
}

#[cfg(unix)]
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

#[cfg(windows)]
fn default_socket() -> PathBuf {
    rustvpn_client_ipc::default_socket_path()
}

fn parse_args() -> Args {
    let mut args = Args {
        socket: default_socket(),
        socket_group: String::new(),
        pipe_group: None,
        service: false,
        console: false,
        hello_timeout: Duration::from_secs(DEFAULT_HELLO_TIMEOUT_SECS),
        idle_timeout: Duration::from_secs(DEFAULT_IDLE_TIMEOUT_SECS),
        no_host_dns: false,
        help: false,
        version: false,
        cleanup: false,
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
            "pipe-group" => args.pipe_group = Some(take("pipe-group")),
            "hello-timeout" => {
                let value = take("hello-timeout");
                args.hello_timeout = Duration::from_secs(parse_secs(&value, "hello-timeout"));
            }
            "idle-timeout" => {
                let value = take("idle-timeout");
                args.idle_timeout = Duration::from_secs(parse_secs(&value, "idle-timeout"));
            }
            "no-host-dns" => args.no_host_dns = true,
            "cleanup" => args.cleanup = true,
            "console" => args.console = true,
            "service" | "windows-service" => args.service = true,
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

/// Everything `run` needs.  Built from the command line in both console and
/// service mode so both share the same shutdown path.
pub(crate) struct RunConfig {
    socket: PathBuf,
    #[cfg_attr(windows, allow(dead_code))]
    gid: Option<u32>,
    #[cfg_attr(unix, allow(dead_code))]
    pipe_group: Option<String>,
    hello_timeout: Duration,
    idle_timeout: Duration,
    no_host_dns: bool,
    wait_for_signals: bool,
    service_mode: bool,
    ready: Option<tokio::sync::oneshot::Sender<()>>,
}

pub(crate) fn build_config(args: &Args, wait_for_signals: bool) -> Result<RunConfig> {
    #[cfg(windows)]
    validate_console_endpoint(args)?;
    #[cfg(unix)]
    let gid = if args.socket_group.is_empty() {
        None
    } else {
        Some(resolve_gid(&args.socket_group)?)
    };
    #[cfg(not(unix))]
    let gid = None;
    Ok(RunConfig {
        socket: args.socket.clone(),
        gid,
        pipe_group: resolve_pipe_group(args)?,
        hello_timeout: args.hello_timeout,
        idle_timeout: args.idle_timeout,
        no_host_dns: args.no_host_dns,
        wait_for_signals,
        service_mode: args.service && !args.console,
        ready: None,
    })
}

/// Explicit group wins.  Service mode requires the dedicated local group;
/// a missing group is a fail-closed configuration error, never an
/// INTERACTIVE fallback.  Console mode without a group is restricted to the
/// daemon's own account by the pipe/process DACLs.
#[cfg(windows)]
fn resolve_pipe_group(args: &Args) -> Result<Option<String>> {
    if let Some(group) = &args.pipe_group {
        return Ok(Some(group.clone()));
    }
    if args.service {
        if rustvpn_client_ipc::windows::local_group_exists(
            rustvpn_client_ipc::windows::DEDICATED_GROUP,
        ) {
            return Ok(Some(rustvpn_client_ipc::windows::DEDICATED_GROUP.into()));
        }
        bail!(
            "Windows service mode requires the local RustVPN group; refusing the \
             INTERACTIVE fallback (reinstall the MSI or create the group and retry)"
        );
    }
    Ok(None)
}

#[cfg(not(windows))]
fn resolve_pipe_group(_args: &Args) -> Result<Option<String>> {
    Ok(None)
}

/// Console mode must never own the production pipe.  A standard user running
/// the installed daemon could otherwise impersonate the service to the GUI or
/// block the real service from starting.
#[cfg(windows)]
fn validate_console_endpoint(args: &Args) -> Result<()> {
    if args.service && !args.console {
        return Ok(());
    }
    let normalized = rustvpn_client_ipc::windows::normalize_pipe_path(&args.socket)
        .with_context(|| format!("validate console endpoint {:?}", args.socket))?;
    if normalized
        .to_string_lossy()
        .eq_ignore_ascii_case(rustvpn_client_ipc::windows::DEFAULT_PIPE_NAME)
    {
        bail!(
            "console mode must not bind the production pipe {}; pass a development \
             -socket name (and RUSTVPN_CLIENTD_SOCKET to the GUI) or run the service",
            rustvpn_client_ipc::windows::DEFAULT_PIPE_NAME
        );
    }
    Ok(())
}

/// Let the pipe's audience open this process for a read-only image query.
///
/// The GUI verifies the pipe server's image path and Authenticode signer
/// before sending a passphrase.  A LocalSystem service is not openable by a
/// standard user by default, so the daemon grants
/// `PROCESS_QUERY_LIMITED_INFORMATION | READ_CONTROL` to the same group that
/// the pipe DACL allows.  READ_CONTROL lets the GUI read the process owner;
/// neither right exposes memory, handle duplication or terminate access, and
/// the GUI still fails closed when the image/owner is not trusted.
#[cfg(windows)]
pub(crate) fn harden_process_identity(config: &RunConfig) {
    let audience = config.pipe_group.as_deref().unwrap_or("INTERACTIVE users");
    match rustvpn_client_ipc::windows::apply_process_query_acl(config.pipe_group.as_deref()) {
        Ok(()) => dlog!(
            "process DACL: granted read-only image query access to {audience} \
             (SYSTEM/Administrators retain full access)"
        ),
        Err(error) => dlog!(
            "warning: cannot grant process image-query access to {audience}: {error}; \
             unprivileged GUI verification will fail closed until this is fixed"
        ),
    }
}

#[cfg(not(windows))]
pub(crate) fn harden_process_identity(_config: &RunConfig) {}

#[derive(Clone)]
struct Shared {
    status: Arc<RwLock<EngineStatus>>,
    logs: Arc<Mutex<VecDeque<LogLine>>>,
    events: broadcast::Sender<Event>,
    commands: mpsc::Sender<Command>,
    shutdown: CancellationToken,
    #[cfg_attr(unix, allow(dead_code))]
    service_mode: bool,
}

fn main() {
    let args = parse_args();
    if args.version {
        println!("rustvpn-clientd {DAEMON_VERSION}");
        return;
    }

    #[cfg(windows)]
    if args.cleanup {
        match run_cleanup() {
            Ok(()) => return,
            Err(error) => {
                eprintln!("cleanup failed: {error:#}");
                process::exit(1);
            }
        }
    }

    #[cfg(windows)]
    if args.service && !args.console {
        if let Err(error) = service::run_dispatcher() {
            eprintln!("cannot start the Windows service dispatcher: {error}");
            process::exit(1);
        }
        return;
    }
    #[cfg(not(windows))]
    if args.service {
        eprintln!("-service is only supported on Windows; use -console");
        process::exit(2);
    }
    #[cfg(not(windows))]
    if args.cleanup {
        eprintln!("-cleanup is only supported on Windows");
        process::exit(2);
    }

    init_console_log();
    let config = match build_config(&args, true) {
        Ok(config) => config,
        Err(error) => {
            dlog!("{error:#}");
            process::exit(1);
        }
    };
    harden_process_identity(&config);
    let runtime = match tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
    {
        Ok(runtime) => runtime,
        Err(error) => {
            dlog!("cannot create async runtime: {error}");
            process::exit(1);
        }
    };
    let shutdown = CancellationToken::new();
    if let Err(error) = runtime.block_on(run(config, shutdown)) {
        dlog!("{error:#}");
        process::exit(1);
    }
}

#[cfg(windows)]
fn run_cleanup() -> Result<()> {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .context("create cleanup runtime")?;
    let report = runtime.block_on(rustvpn_client_core::netcfg::cleanup_stale_network())?;
    for action in &report.actions {
        println!("cleanup: {action}");
    }
    for error in &report.errors {
        eprintln!("cleanup warning: {error}");
    }
    if report.skipped_live_owner {
        eprintln!("cleanup skipped: another live RustVPN owner still owns network state");
    }
    if !report.errors.is_empty() {
        bail!(
            "cleanup left {} error(s); state kept for the next start",
            report.errors.len()
        );
    }
    Ok(())
}

async fn run(mut config: RunConfig, shutdown: CancellationToken) -> Result<()> {
    let socket_path = &config.socket;

    #[cfg(unix)]
    {
        if socket_path.as_os_str().len() >= 100 {
            bail!("socket path is too long: {}", socket_path.display());
        }
        prepare_socket_parent(socket_path)?;
        remove_stale_socket(socket_path).await?;
    }

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
    let firewall_scope = rustvpn_client_core::firewall::instance_scope(socket_path);
    #[cfg(unix)]
    let marker = clean_marker_path(socket_path);
    #[cfg(unix)]
    {
        let clean = previous_shutdown_was_clean(&marker);
        remove_clean_marker(&marker);
        match startup_firewall_cleanup(clean) {
            StartupFirewallCleanup::Clean => {
                rustvpn_client_core::netcfg::cleanup_stale_firewall(&firewall_scope).await;
            }
            StartupFirewallCleanup::AfterCrash => {
                rustvpn_client_core::netcfg::cleanup_stale_mss(&firewall_scope).await;
                // Keep the table and guarantee its drop-policy chain exists even
                // if the crash happened mid-create.  No DNS is allowed while busy.
                match rustvpn_client_core::firewall::bootstrap_kill_switch(
                    &firewall_scope,
                    None,
                    false,
                )
                .await
                {
                    Ok(true) => dlog!(
                        "previous run did not shut down cleanly; preserving this instance's \
                         kill-switch table (fail-closed) until a connection replaces it or an \
                         explicit disconnect removes it"
                    ),
                    Ok(false) => {}
                    Err(error) => dlog!(
                        "previous run did not shut down cleanly; cannot verify this instance's \
                         kill-switch table: {error:#}"
                    ),
                }
            }
        }
    }
    #[cfg(not(unix))]
    dlog!(
        "Windows M2: firewall/kill-switch state is not installed yet (deferred to M3); \
         the service shares the Linux clean shutdown path for IPC and the engine"
    );

    let (commands_tx, commands_rx) = mpsc::channel(8);
    let (events_tx, _) = broadcast::channel(256);
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
        service_mode: config.service_mode,
    };

    let engine = Engine::spawn_with_options(
        commands_rx,
        events_tx.clone(),
        EngineOptions {
            no_host_dns: config.no_host_dns,
            firewall_scope: firewall_scope.clone(),
        },
    );
    spawn_collector(events_tx.clone(), status.clone(), logs.clone());

    // In service mode retry a squatted endpoint instead of exiting on the
    // first first-instance collision.  The retry window is 60 s and stays
    // below the SCM wait hint configured in service.rs; console mode keeps
    // its immediate error.
    let mut bind_attempt = 0u32;
    let listener = loop {
        if shutdown.is_cancelled() {
            return Ok(());
        }
        match transport::Listener::bind(
            socket_path,
            &transport::ListenOptions {
                group: config.pipe_group.clone(),
            },
        ) {
            Ok(listener) => break listener,
            Err(error) if config.service_mode && bind_attempt < 30 => {
                bind_attempt += 1;
                dlog!(
                    "bind {} failed: {error}; retrying in 2s ({bind_attempt}/30)",
                    socket_path.display()
                );
                tokio::select! {
                    _ = tokio::time::sleep(Duration::from_secs(2)) => {}
                    _ = shutdown.cancelled() => return Ok(()),
                }
            }
            Err(error) => {
                return Err(error).with_context(|| format!("bind {}", socket_path.display()));
            }
        }
    };

    #[cfg(unix)]
    {
        apply_socket_permissions(socket_path, config.gid)?;
        eprintln!(
            "rustvpn-clientd {DAEMON_VERSION} listening on {} (mode {})",
            socket_path.display(),
            if config.gid.is_some() { "0660" } else { "0600" }
        );
    }
    #[cfg(not(unix))]
    dlog!(
        "rustvpn-clientd {DAEMON_VERSION} listening on {}",
        socket_path.display()
    );

    // The endpoint is bound: the SCM may now report Running instead of
    // claiming readiness while a 10-15 s crash-recovery cleanup is still
    // running.
    if let Some(ready) = config.ready.take() {
        let _ = ready.send(());
    }

    let policy = make_peer_policy(&config)?;
    let accept_shared = shared.clone();
    let hello_timeout = config.hello_timeout;
    let idle_timeout = config.idle_timeout;
    let accept = tokio::spawn(async move {
        accept_loop(listener, accept_shared, policy, hello_timeout, idle_timeout).await;
    });

    tokio::select! {
        _ = shutdown.cancelled() => {}
        _ = wait_signal(), if config.wait_for_signals => shutdown.cancel(),
    }
    let _ = shared.commands.send(Command::Shutdown).await;
    let _ = engine.await;
    accept.abort();
    // The engine removed the guard (routes, DNS, kill switch, MSS) before it
    // returned.  A crash-preserved kill switch may still exist when the daemon
    // was stopped while idle; a clean stop restores connectivity.  Record that
    // so the next start removes any leftovers instead of treating them as a
    // crash.
    #[cfg(unix)]
    {
        rustvpn_client_core::netcfg::cleanup_stale_firewall(&firewall_scope).await;
        if let Err(error) = write_clean_marker(&marker) {
            dlog!(
                "warning: cannot write clean-shutdown marker {}: {error}",
                marker.display()
            );
        }
        let _ = std::fs::remove_file(socket_path);
    }
    dlog!("rustvpn-clientd stopped");
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
                Ok(Event::Log(mut line)) => {
                    line.level = truncate_log_line(&line.level);
                    line.line = truncate_log_line(&line.line);
                    dlog!("[{}] {}", line.level, line.line);
                    if let Ok(mut ring) = logs.lock() {
                        if ring.len() >= MAX_LOG_LINES {
                            ring.pop_front();
                        }
                        ring.push_back(line);
                    }
                }
                Ok(Event::Lagged { missed }) => {
                    dlog!("client event collector lagged by {missed} event(s)");
                }
                Err(broadcast::error::RecvError::Lagged(missed)) => {
                    dlog!("client event collector lagged by {missed} event(s)");
                }
                Err(broadcast::error::RecvError::Closed) => break,
            }
        }
    });
}

#[cfg(unix)]
type PeerPolicy = Option<u32>;
#[cfg(windows)]
type PeerPolicy = rustvpn_client_ipc::windows::ClientPolicy;

#[cfg(unix)]
fn make_peer_policy(config: &RunConfig) -> Result<PeerPolicy> {
    Ok(config.gid)
}

#[cfg(windows)]
fn make_peer_policy(config: &RunConfig) -> Result<PeerPolicy> {
    rustvpn_client_ipc::windows::ClientPolicy::new(config.pipe_group.as_deref())
        .context("build the pipe client policy")
}

async fn accept_loop(
    mut listener: transport::Listener,
    shared: Shared,
    policy: PeerPolicy,
    hello_timeout: Duration,
    idle_timeout: Duration,
) {
    let limit = Arc::new(Semaphore::new(16));
    loop {
        let stream = match listener.accept().await {
            Ok(stream) => stream,
            Err(error) => {
                dlog!("accept failed: {error}");
                tokio::time::sleep(Duration::from_secs(1)).await;
                continue;
            }
        };
        if !peer_allowed(&stream, &policy) {
            dlog!("rejected unauthorized IPC client");
            continue;
        }
        let Ok(permit) = limit.clone().try_acquire_owned() else {
            dlog!("too many IPC connections; dropping client");
            continue;
        };
        let peer_is_admin = peer_is_administrator(&stream, &policy);
        let shared = shared.clone();
        tokio::spawn(async move {
            let _permit = permit;
            if let Err(error) =
                handle_connection(stream, shared, hello_timeout, idle_timeout, peer_is_admin).await
            {
                dlog!("IPC client failed: {error:#}");
            }
        });
    }
}

async fn handle_connection(
    mut stream: Connection,
    shared: Shared,
    hello_timeout: Duration,
    idle_timeout: Duration,
    peer_is_admin: bool,
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
                // `Ok` means the command was queued, not that teardown has
                // finished.  The engine first publishes `disconnecting` and
                // then `idle` after the adapter close; clients must wait for
                // the `idle` event (event subscription/status) rather than
                // treating this response as completion.
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
                            ring.len().min(MAX_LOGS_RESPONSE_LINES)
                        } else {
                            (limit as usize)
                                .min(ring.len())
                                .min(MAX_LOGS_RESPONSE_LINES)
                        };
                        ring.iter().skip(ring.len() - take).cloned().collect()
                    })
                    .unwrap_or_default();
                Response::Logs { lines }
            }
            Request::Shutdown => {
                if shared.service_mode && !peer_is_admin {
                    Response::Error {
                        message: "Shutdown requires an elevated administrator token".into(),
                    }
                } else {
                    let _ = shared.commands.send(Command::Shutdown).await;
                    shared.shutdown.cancel();
                    Response::Ok
                }
            }
            Request::Subscribe => {
                write_value(&mut stream, &Response::Subscribed).await?;
                let (read, write) = tokio::io::split(stream);
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

async fn subscribe_loop<R, W>(mut read: R, mut write: W, shared: &Shared) -> Result<()>
where
    R: AsyncRead + Unpin + Send + 'static,
    W: AsyncWrite + Unpin + Send + 'static,
{
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

#[cfg(unix)]
fn peer_allowed(stream: &Connection, gid: &PeerPolicy) -> bool {
    let Ok(cred) = stream.peer_cred() else {
        return false;
    };
    if cred.uid() == 0 || cred.uid() == unsafe { libc::geteuid() } {
        return true;
    }
    if let Some(gid) = *gid {
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

#[cfg(unix)]
fn peer_is_administrator(_stream: &Connection, _policy: &PeerPolicy) -> bool {
    // Unix Shutdown retains the historical same-user/root policy.
    true
}

#[cfg(windows)]
fn peer_is_administrator(stream: &Connection, policy: &PeerPolicy) -> bool {
    stream
        .peer_pid()
        .is_ok_and(|pid| policy.is_administrator(pid))
}

#[cfg(windows)]
fn peer_allowed(stream: &Connection, policy: &PeerPolicy) -> bool {
    match stream.peer_pid() {
        Ok(pid) => {
            let allowed = policy.allows(pid);
            if !allowed {
                // Log the actual user/groups/allowed SIDs: this is the only
                // place a standard-user access failure is visible without a
                // debugger, and it never includes a passphrase or profile.
                dlog!(
                    "rejected unauthorized IPC client: {}",
                    policy.rejection_reason(pid)
                );
            }
            allowed
        }
        Err(_) => false,
    }
}

/// `SO_PEERCRED` only reports the primary gid; desktop users join the
/// service group as a supplementary group, so consult `/proc/<pid>/status`.
#[cfg(unix)]
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

#[cfg(unix)]
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

#[cfg(unix)]
fn prepare_socket_parent(path: &Path) -> Result<()> {
    let Some(parent) = path.parent() else {
        return Ok(());
    };
    let existed = parent.exists();
    std::fs::create_dir_all(parent).with_context(|| format!("create {}", parent.display()))?;
    use std::os::unix::fs::PermissionsExt;
    if !existed {
        let mut perms = std::fs::metadata(parent)?.permissions();
        let system = parent == Path::new("/run/rustvpn-client");
        perms.set_mode(if system { 0o755 } else { 0o700 });
        std::fs::set_permissions(parent, perms)?;
    }
    Ok(())
}

#[cfg(unix)]
async fn remove_stale_socket(path: &Path) -> Result<()> {
    let meta = match std::fs::symlink_metadata(path) {
        Ok(meta) => meta,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error.into()),
    };
    if !meta.file_type().is_socket() {
        bail!("{} exists and is not a socket", path.display());
    }
    match transport::connect(path).await {
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

#[cfg(unix)]
fn apply_socket_permissions(path: &Path, gid: Option<u32>) -> Result<()> {
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
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(unix)]
    use std::os::unix::fs::PermissionsExt;

    #[cfg(unix)]
    #[test]
    fn numeric_gid_is_accepted() {
        assert_eq!(resolve_gid("12345").unwrap(), 12345);
    }

    #[cfg(unix)]
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

    #[cfg(unix)]
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

    #[cfg(unix)]
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

    #[cfg(unix)]
    #[tokio::test]
    async fn unix_peer_policy_allows_the_same_user_and_group() {
        let path =
            std::env::temp_dir().join(format!("rustvpn-clientd-peer-{}", std::process::id()));
        let _ = std::fs::remove_file(&path);
        let mut listener =
            transport::Listener::bind(&path, &transport::ListenOptions::default()).unwrap();
        let _client = transport::connect(&path).await.unwrap();
        let connection = listener.accept().await.unwrap();
        // Same-user is allowed regardless of group configuration.
        assert!(peer_allowed(&connection, &None));
        assert!(peer_allowed(&connection, &Some(u32::MAX)));
        let own_gid = unsafe { libc::getegid() };
        assert!(peer_allowed(&connection, &Some(own_gid)));
        drop(connection);
        let _ = std::fs::remove_file(path);
    }

    #[cfg(unix)]
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

    #[test]
    fn log_lines_are_bounded_before_entering_the_ring() {
        let long = "x".repeat(MAX_LOG_LINE_CHARS + 500);
        let line = truncate_log_line(&long);
        assert_eq!(line.chars().count(), MAX_LOG_LINE_CHARS + 1);
        assert!(line.ends_with('…'));
    }
}
