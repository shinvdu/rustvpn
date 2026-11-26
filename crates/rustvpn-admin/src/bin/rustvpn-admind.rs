//! Standalone web administration daemon for RustVPN.
//!
//! It serves the HTTP UI and owns the history database, but reaches the live
//! server through a local Unix control socket; it never holds CAP_NET_ADMIN.

use std::path::PathBuf;
use std::process;

use anyhow::{Context, Result};
use rustvpn_admin::backend::ControlBackend;
use rustvpn_admin::config_edit::ConfigPaths;
use rustvpn_admin::history::History;
use rustvpn_admin::model::EventLog;
use rustvpn_admin::store::Store;
use rustvpn_admin::{serve, AdminOptions, AdminState};

struct Args {
    listen: String,
    db: String,
    control: String,
    conf: String,
    disabled_conf: String,
    backup_dir: String,
    cookie_secure: bool,
    script_dir: Vec<String>,
}

fn usage() -> ! {
    eprintln!(
        "Usage of rustvpn-admind:\n\
         \x20 -listen string (default \"127.0.0.1:8080\")\n\
         \x20 -db string (default \"/var/lib/rustvpn/admin.db\")\n\
         \x20 -control string (default \"/run/rustvpn/control.sock\")\n\
         \x20 -conf string (default \"/etc/rustvpn/peers.yaml\")\n\
         \x20 -disabled-conf string (default peers.disabled.yaml next to -conf)\n\
         \x20 -backup-dir string (default backups/ next to -db)\n\
         \x20 -cookie-secure (set Secure/__Host- cookies; behind TLS)\n\
         \x20 -script-dir string (repeatable; must match the server allow-list)"
    );
    process::exit(2);
}

fn parse_args() -> Args {
    let mut args = Args {
        listen: "127.0.0.1:8080".into(),
        db: "/var/lib/rustvpn/admin.db".into(),
        control: "/run/rustvpn/control.sock".into(),
        conf: "/etc/rustvpn/peers.yaml".into(),
        disabled_conf: String::new(),
        backup_dir: String::new(),
        cookie_secure: false,
        script_dir: Vec::new(),
    };
    let mut iter = std::env::args().skip(1);
    while let Some(argument) = iter.next() {
        let (name, inline) = match argument.split_once('=') {
            Some((name, value)) => (
                name.trim_start_matches('-').to_string(),
                Some(value.to_string()),
            ),
            None => (argument.trim_start_matches('-').to_string(), None),
        };
        let mut take = |name: &str| -> String {
            inline.clone().unwrap_or_else(|| {
                iter.next().unwrap_or_else(|| {
                    eprintln!("flag needs an argument: -{name}");
                    usage();
                })
            })
        };
        match name.as_str() {
            "listen" => args.listen = take("listen"),
            "db" => args.db = take("db"),
            "control" => args.control = take("control"),
            "conf" => args.conf = take("conf"),
            "disabled-conf" => args.disabled_conf = take("disabled-conf"),
            "backup-dir" => args.backup_dir = take("backup-dir"),
            "cookie-secure" => args.cookie_secure = true,
            "script-dir" => args.script_dir.push(take("script-dir")),
            "h" | "help" => usage(),
            "" => usage(),
            other => {
                eprintln!("flag provided but not defined: -{other}");
                usage();
            }
        }
    }
    args
}

fn main() {
    let args = parse_args();
    if let Err(error) = run(args) {
        eprintln!("{error:#}");
        process::exit(1);
    }
}

fn run(args: Args) -> Result<()> {
    let db_path = PathBuf::from(&args.db);
    let store = std::sync::Arc::new(
        Store::open(&db_path)
            .map_err(|error| anyhow::anyhow!("open {}: {error}", db_path.display()))?,
    );
    if store.admin_count().unwrap_or(0) == 0 {
        anyhow::bail!(
            "no admin user in {}; run: rustvpn-admin-passwd -db {}",
            db_path.display(),
            db_path.display()
        );
    }

    let disabled = if args.disabled_conf.is_empty() {
        PathBuf::from(&args.conf)
            .parent()
            .unwrap_or_else(|| std::path::Path::new("."))
            .join("peers.disabled.yaml")
    } else {
        PathBuf::from(&args.disabled_conf)
    };
    let backup_dir = if args.backup_dir.is_empty() {
        db_path
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
            .unwrap_or_else(|| std::path::Path::new("."))
            .join("backups")
    } else {
        PathBuf::from(&args.backup_dir)
    };
    let paths = ConfigPaths {
        enabled: PathBuf::from(&args.conf),
        disabled,
        backup_dir,
    };

    let runtime = tokio::runtime::Runtime::new().context("create tokio runtime")?;
    runtime.block_on(async move {
        let history = History::spawn(store.clone());
        let events = std::sync::Arc::new(EventLog::new(2000));
        let backend = ControlBackend::new(
            paths,
            PathBuf::from(&args.control),
            args.listen.clone(),
            history.clone(),
            events,
            store.clone(),
            args.script_dir.iter().map(PathBuf::from).collect(),
        );
        backend.start_subscription();
        let options = AdminOptions {
            secure_cookies: args.cookie_secure,
            script_dirs: args.script_dir.iter().map(PathBuf::from).collect(),
        };
        let state = AdminState::new(backend, store, history, options);
        let listener = tokio::net::TcpListener::bind(&args.listen)
            .await
            .with_context(|| format!("bind admin {}", args.listen))?;
        eprintln!("Listening on admin: {}", args.listen);
        if !is_loopback_bind(&args.listen) {
            eprintln!("warning: admin endpoint is not bound to loopback; use TLS and a firewall");
        }
        serve(listener, state).await
    })
}

fn is_loopback_bind(addr: &str) -> bool {
    let host = addr
        .rsplit_once(':')
        .map(|(host, _)| host)
        .unwrap_or(addr)
        .trim_start_matches('[')
        .trim_end_matches(']');
    host == "127.0.0.1" || host == "::1" || host == "localhost"
}
