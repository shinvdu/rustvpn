//! Tauri 2 shell for the RustVPN desktop client.
//!
//! The tunnel lives in `rustvpn-clientd`; this process is unprivileged and
//! only talks to it over the local Unix socket.

#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use rustvpn_client_ipc::{Client, EngineStatus, EventStream, LogLine, ProfileSpec};
use tauri::menu::{Menu, MenuItem};
use tauri::tray::{MouseButton, MouseButtonState, TrayIconBuilder, TrayIconEvent};
use tauri::{Emitter, Manager, WindowEvent};

const KEYRING_SERVICE: &str = "rustvpn-client";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum UiLang {
    Zh,
    En,
    Ru,
}

impl UiLang {
    fn parse(tag: &str) -> Self {
        let tag = tag.trim().to_ascii_lowercase();
        if tag.starts_with("zh") {
            Self::Zh
        } else if tag.starts_with("ru") {
            Self::Ru
        } else {
            Self::En
        }
    }

    fn tray_labels(self) -> [&'static str; 3] {
        match self {
            Self::Zh => ["打开 RustVPN", "断开", "退出"],
            Self::En => ["Open RustVPN", "Disconnect", "Quit"],
            Self::Ru => ["Открыть RustVPN", "Отключить", "Выйти"],
        }
    }
}

fn initial_language() -> UiLang {
    ["LC_ALL", "LC_MESSAGES", "LANG"]
        .iter()
        .find_map(|name| std::env::var(name).ok())
        .map(|value| UiLang::parse(&value))
        .unwrap_or(UiLang::En)
}

struct TrayItems {
    show: MenuItem<tauri::Wry>,
    disconnect: MenuItem<tauri::Wry>,
    quit: MenuItem<tauri::Wry>,
}

struct AppState {
    socket: PathBuf,
    tray_available: Arc<AtomicBool>,
    tray_items: Mutex<Option<TrayItems>>,
    language: Mutex<UiLang>,
    /// Profiles found on disk that could not be parsed.  Kept so the UI can
    /// report them instead of silently hiding the files.
    profile_errors: Mutex<Vec<ProfileLoadError>>,
}

#[derive(Clone, Debug, serde::Serialize)]
struct ProfileLoadError {
    path: String,
    message: String,
}

static TEMP_COUNTER: AtomicU64 = AtomicU64::new(0);

#[tauri::command]
async fn daemon_info(state: tauri::State<'_, AppState>) -> Result<serde_json::Value, String> {
    let socket = rustvpn_client_ipc::candidate_socket_paths()
        .into_iter()
        .find(|path| path.exists())
        .unwrap_or_else(|| state.socket.clone());
    Ok(serde_json::json!({
        "socket": socket.to_string_lossy(),
        "version": env!("CARGO_PKG_VERSION"),
    }))
}

#[tauri::command]
async fn get_status() -> Result<EngineStatus, String> {
    let mut client = ipc_client(Duration::from_secs(2)).await?;
    tokio::time::timeout(Duration::from_secs(2), client.status())
        .await
        .map_err(|_| "daemon status timed out".to_string())?
        .map_err(|error| error.to_string())
}

#[tauri::command]
async fn connect(profile: ProfileSpec, password: String) -> Result<(), String> {
    if password.is_empty() {
        return Err("passphrase is empty".into());
    }
    let mut client = ipc_client(Duration::from_secs(3)).await?;
    tokio::time::timeout(
        Duration::from_secs(5),
        client.connect_profile(profile, password),
    )
    .await
    .map_err(|_| "daemon did not answer".to_string())?
    .map_err(|error| error.to_string())
}

#[tauri::command]
async fn disconnect() -> Result<(), String> {
    let mut client = ipc_client(Duration::from_secs(3)).await?;
    tokio::time::timeout(Duration::from_secs(5), client.disconnect())
        .await
        .map_err(|_| "daemon did not answer".to_string())?
        .map_err(|error| error.to_string())
}

#[tauri::command]
async fn get_logs(limit: u32) -> Result<Vec<LogLine>, String> {
    let mut client = ipc_client(Duration::from_secs(2)).await?;
    tokio::time::timeout(Duration::from_secs(3), client.logs(limit))
        .await
        .map_err(|_| "daemon logs timed out".to_string())?
        .map_err(|error| error.to_string())
}

#[tauri::command]
async fn get_password(profile_name: String) -> Result<Option<String>, String> {
    tokio::task::spawn_blocking(move || {
        let entry = keyring_entry(&profile_name)?;
        match entry.get_password() {
            Ok(password) => Ok(Some(password)),
            Err(keyring::Error::NoEntry) => Ok(None),
            Err(error) => Err(error.to_string()),
        }
    })
    .await
    .map_err(|error| error.to_string())?
}

#[tauri::command]
async fn save_password(profile_name: String, password: String) -> Result<(), String> {
    let password = zeroize::Zeroizing::new(password);
    tokio::task::spawn_blocking(move || {
        keyring_entry(&profile_name)?
            .set_password(password.as_str())
            .map_err(|error| error.to_string())
    })
    .await
    .map_err(|error| error.to_string())?
}

#[tauri::command]
async fn delete_password(profile_name: String) -> Result<(), String> {
    tokio::task::spawn_blocking(
        move || match keyring_entry(&profile_name)?.delete_credential() {
            Ok(()) | Err(keyring::Error::NoEntry) => Ok(()),
            Err(error) => Err(error.to_string()),
        },
    )
    .await
    .map_err(|error| error.to_string())?
}

#[tauri::command]
fn system_language(state: tauri::State<'_, AppState>) -> String {
    match state.language.lock().map(|language| *language) {
        Ok(UiLang::Zh) => "zh".into(),
        Ok(UiLang::Ru) => "ru".into(),
        _ => "en".into(),
    }
}

#[tauri::command]
fn set_ui_language(lang: String, state: tauri::State<'_, AppState>) -> Result<(), String> {
    let language = UiLang::parse(&lang);
    if let Ok(mut current) = state.language.lock() {
        *current = language;
    }
    let [show, disconnect, quit] = language.tray_labels();
    if let Ok(items) = state.tray_items.lock() {
        if let Some(items) = items.as_ref() {
            items
                .show
                .set_text(show)
                .map_err(|error| error.to_string())?;
            items
                .disconnect
                .set_text(disconnect)
                .map_err(|error| error.to_string())?;
            items
                .quit
                .set_text(quit)
                .map_err(|error| error.to_string())?;
        }
    }
    Ok(())
}

fn updater_settings_ready(value: &serde_json::Value) -> bool {
    let endpoints_ready = value
        .get("endpoints")
        .and_then(|endpoints| endpoints.as_array())
        .is_some_and(|endpoints| {
            endpoints.iter().any(|endpoint| {
                endpoint
                    .as_str()
                    .is_some_and(|text| !text.trim().is_empty())
            })
        });
    let pubkey_ready = value
        .get("pubkey")
        .and_then(|key| key.as_str())
        .is_some_and(|text| !text.trim().is_empty());
    endpoints_ready && pubkey_ready
}

#[tauri::command]
fn updater_info(app: tauri::AppHandle) -> serde_json::Value {
    let configured = app
        .config()
        .plugins
        .0
        .get("updater")
        .is_some_and(updater_settings_ready);
    serde_json::json!({
        "enabled": cfg!(feature = "updater") && configured,
        "version": env!("CARGO_PKG_VERSION"),
    })
}

#[cfg(feature = "updater")]
#[tauri::command]
async fn check_update(app: tauri::AppHandle) -> Result<serde_json::Value, String> {
    use tauri_plugin_updater::UpdaterExt;
    let update = app
        .updater()
        .map_err(|error| error.to_string())?
        .check()
        .await
        .map_err(|error| error.to_string())?;
    Ok(match update {
        Some(update) => serde_json::json!({
            "available": true,
            "version": update.version,
        }),
        None => serde_json::json!({ "available": false }),
    })
}

#[cfg(not(feature = "updater"))]
#[tauri::command]
async fn check_update() -> Result<serde_json::Value, String> {
    Err("updater is not enabled in this build".into())
}

#[cfg(feature = "updater")]
#[tauri::command]
async fn install_update(app: tauri::AppHandle) -> Result<(), String> {
    use tauri_plugin_updater::UpdaterExt;
    let update = app
        .updater()
        .map_err(|error| error.to_string())?
        .check()
        .await
        .map_err(|error| error.to_string())?
        .ok_or_else(|| "no update available".to_string())?;
    update
        .download_and_install(|_, _| {}, || {})
        .await
        .map_err(|error| error.to_string())
}

#[cfg(not(feature = "updater"))]
#[tauri::command]
async fn install_update() -> Result<(), String> {
    Err("updater is not enabled in this build".into())
}

#[tauri::command]
fn autostart_enabled() -> bool {
    autostart_path().is_some_and(|path| path.exists())
}

#[tauri::command]
fn set_autostart(enabled: bool) -> Result<(), String> {
    let path =
        autostart_path().ok_or_else(|| "cannot determine autostart directory".to_string())?;
    if !enabled {
        match std::fs::remove_file(&path) {
            Ok(()) => return Ok(()),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
            Err(error) => return Err(error.to_string()),
        }
    }
    let exe = std::env::current_exe().map_err(|error| error.to_string())?;
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|error| error.to_string())?;
    }
    let exec = exe.to_string_lossy().replace('"', "\\\"");
    let desktop = format!(
        "[Desktop Entry]\nType=Application\nName=RustVPN\nExec=\"{exec}\"\nTerminal=false\nX-GNOME-Autostart-enabled=true\n"
    );
    std::fs::write(path, desktop).map_err(|error| error.to_string())
}

fn keyring_entry(profile_name: &str) -> Result<keyring::Entry, String> {
    keyring::Entry::new(KEYRING_SERVICE, profile_name).map_err(|error| error.to_string())
}

fn autostart_path() -> Option<PathBuf> {
    let base = if let Some(dir) = std::env::var_os("XDG_CONFIG_HOME") {
        PathBuf::from(dir)
    } else {
        PathBuf::from(std::env::var_os("HOME")?).join(".config")
    };
    Some(base.join("autostart").join("rustvpn-client.desktop"))
}

#[tauri::command]
fn list_profiles(state: tauri::State<'_, AppState>) -> Result<Vec<ProfileSpec>, String> {
    let (profiles, errors) = collect_profiles(&profiles_dir())?;
    if let Ok(mut slot) = state.profile_errors.lock() {
        *slot = errors;
    }
    Ok(profiles)
}

/// Return the parse failures recorded by the most recent `list_profiles`.
#[tauri::command]
fn profile_errors(state: tauri::State<'_, AppState>) -> Vec<ProfileLoadError> {
    state
        .profile_errors
        .lock()
        .map(|errors| errors.clone())
        .unwrap_or_default()
}

fn collect_profiles(dir: &Path) -> Result<(Vec<ProfileSpec>, Vec<ProfileLoadError>), String> {
    if !dir.exists() {
        return Ok((Vec::new(), Vec::new()));
    }
    let entries = std::fs::read_dir(dir).map_err(|error| error.to_string())?;
    let mut profiles = Vec::new();
    let mut errors = Vec::new();
    for entry in entries.flatten() {
        let path = entry.path();
        if !matches!(
            path.extension().and_then(|value| value.to_str()),
            Some("yaml" | "yml")
        ) {
            continue;
        }
        match read_profile(&path) {
            Ok(profile) => profiles.push(profile),
            Err(error) => {
                let message = describe_profile_error(&error);
                eprintln!("profile {} not loaded: {message}", path.display());
                errors.push(ProfileLoadError {
                    path: path.display().to_string(),
                    message,
                });
            }
        }
    }
    profiles.sort_by_key(|a| a.name.to_lowercase());
    errors.sort_by(|a, b| a.path.cmp(&b.path));
    Ok((profiles, errors))
}

/// Make legacy `mtu: auto`/`mtu: 0` failures actionable instead of a generic
/// parse error.  These files were valid in older builds but v1 requires a
/// numeric two-sided wire MTU.
fn describe_profile_error(error: &str) -> String {
    if error.contains("mtu: auto") || error.contains("mtu: 0") {
        format!(
            "legacy profile rejected: {error}. Migrate it to the numeric wire MTU shared \
             with the server (for example 1515); see docs/client-ui.md"
        )
    } else {
        error.to_string()
    }
}

#[tauri::command]
async fn save_profile(profile: ProfileSpec, previous_name: Option<String>) -> Result<(), String> {
    tokio::task::spawn_blocking(move || {
        let dir = profiles_dir();
        save_profile_at(&dir, &profile, previous_name.as_deref())?;
        if let Some(previous) = previous_name.as_deref() {
            if previous != profile.name {
                let _ = keyring_entry(previous).and_then(|entry| match entry.delete_credential() {
                    Ok(()) | Err(keyring::Error::NoEntry) => Ok(()),
                    Err(error) => Err(error.to_string()),
                });
            }
        }
        Ok(())
    })
    .await
    .map_err(|error| error.to_string())?
}

fn save_profile_at(
    dir: &Path,
    profile: &ProfileSpec,
    previous_name: Option<&str>,
) -> Result<(), String> {
    if profile.name.trim().is_empty() {
        return Err("profile name is empty".into());
    }
    if profile.remote.trim().is_empty() {
        return Err("remote address is empty".into());
    }
    if profile.verifier.trim().is_empty() {
        return Err("verifier is empty".into());
    }
    // Defense in depth before serializer/file IO: the daemon is still the
    // authoritative validator, but a compromised webview must not persist a
    // non-numeric or out-of-range MTU (and serialization itself rejects 0).
    profile.validate_mtu()?;
    std::fs::create_dir_all(dir).map_err(|error| error.to_string())?;
    set_dir_private(dir);

    let stem = file_stem(&profile.name)?;
    let file = dir.join(format!("{stem}.yaml"));
    if file.exists() {
        if let Ok(existing) = read_profile(&file) {
            if existing.name != profile.name && Some(existing.name.as_str()) != previous_name {
                return Err(format!(
                    "profile file name collides with existing profile {:?}",
                    existing.name
                ));
            }
        }
    }

    let yaml = serde_yaml_ng::to_string(profile).map_err(|error| error.to_string())?;
    let tmp = dir.join(format!(
        ".{}.{}.tmp",
        std::process::id(),
        TEMP_COUNTER.fetch_add(1, Ordering::Relaxed)
    ));
    std::fs::write(&tmp, yaml).map_err(|error| error.to_string())?;
    set_file_private(&tmp);
    if let Err(error) = std::fs::rename(&tmp, &file) {
        let _ = std::fs::remove_file(&tmp);
        return Err(error.to_string());
    }

    if let Some(previous) = previous_name {
        if previous != profile.name {
            if let Ok(previous_stem) = file_stem(previous) {
                let old = dir.join(format!("{previous_stem}.yaml"));
                if old != file {
                    let _ = std::fs::remove_file(old);
                }
            }
        }
    }
    Ok(())
}

#[tauri::command]
async fn delete_profile(name: String) -> Result<(), String> {
    tokio::task::spawn_blocking(move || {
        let file = profile_path(&profiles_dir(), &name)?;
        if file.exists() {
            std::fs::remove_file(file).map_err(|error| error.to_string())?;
        }
        let _ = keyring_entry(&name).and_then(|entry| match entry.delete_credential() {
            Ok(()) | Err(keyring::Error::NoEntry) => Ok(()),
            Err(error) => Err(error.to_string()),
        });
        Ok(())
    })
    .await
    .map_err(|error| error.to_string())?
}

fn profile_path(dir: &Path, name: &str) -> Result<PathBuf, String> {
    Ok(dir.join(format!("{}.yaml", file_stem(name)?)))
}

fn read_profile(path: &Path) -> Result<ProfileSpec, String> {
    let text = std::fs::read_to_string(path).map_err(|error| error.to_string())?;
    serde_yaml_ng::from_str(&text).map_err(|error| error.to_string())
}

async fn ipc_client(timeout: Duration) -> Result<Client, String> {
    let mut last_error = "client daemon is not reachable".to_string();
    for path in rustvpn_client_ipc::candidate_socket_paths() {
        match tokio::time::timeout(timeout, Client::connect(&path)).await {
            Ok(Ok(client)) => return Ok(client),
            Ok(Err(error)) => last_error = format!("{}: {error}", path.display()),
            Err(_) => last_error = format!("{}: timed out", path.display()),
        }
    }
    Err(last_error)
}

fn spawn_event_listener(app: tauri::AppHandle) {
    tauri::async_runtime::spawn(async move {
        loop {
            let mut connected = false;
            for path in rustvpn_client_ipc::candidate_socket_paths() {
                let subscribed =
                    tokio::time::timeout(Duration::from_secs(3), EventStream::subscribe(&path))
                        .await;
                let Ok(Ok(mut stream)) = subscribed else {
                    continue;
                };
                connected = true;
                eprintln!("daemon event subscription established: {}", path.display());
                let _ = app.emit("daemon-online", ());
                loop {
                    match stream.next().await {
                        Ok(Some(event)) => {
                            if let Err(error) = app.emit("daemon-event", event) {
                                eprintln!("emit daemon event: {error}");
                            }
                        }
                        Ok(None) => {
                            eprintln!("daemon event stream closed");
                            break;
                        }
                        Err(error) => {
                            eprintln!("daemon event stream failed: {error}");
                            break;
                        }
                    }
                }
                break;
            }
            if !connected {
                eprintln!("daemon event subscription failed for all socket candidates");
            }
            let _ = app.emit("daemon-offline", ());
            tokio::time::sleep(Duration::from_secs(2)).await;
        }
    });
}

fn profiles_dir() -> PathBuf {
    if let Some(dir) = std::env::var_os("XDG_CONFIG_HOME") {
        if !dir.is_empty() {
            return PathBuf::from(dir).join("rustvpn").join("profiles");
        }
    }
    let home = std::env::var_os("HOME").unwrap_or_else(|| "/tmp".into());
    PathBuf::from(home)
        .join(".config")
        .join("rustvpn")
        .join("profiles")
}

fn file_stem(name: &str) -> Result<String, String> {
    let mut stem = String::new();
    for ch in name.trim().chars() {
        if ch.is_alphanumeric() || matches!(ch, '-' | '_' | '.') {
            stem.push(ch);
        } else {
            stem.push('-');
        }
        if stem.len() >= 64 {
            break;
        }
    }
    if stem.is_empty() || stem == "." || stem == ".." {
        return Err("profile name cannot be used as a file name".into());
    }
    Ok(stem)
}

fn set_file_private(path: &std::path::Path) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if let Ok(meta) = std::fs::metadata(path) {
            let mut perms = meta.permissions();
            perms.set_mode(0o600);
            let _ = std::fs::set_permissions(path, perms);
        }
    }
}

fn set_dir_private(dir: &std::path::Path) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if let Ok(meta) = std::fs::metadata(dir) {
            let mut perms = meta.permissions();
            perms.set_mode(0o700);
            let _ = std::fs::set_permissions(dir, perms);
        }
    }
}

fn main() {
    let socket = rustvpn_client_ipc::default_socket_path();
    let builder =
        tauri::Builder::default().plugin(tauri_plugin_single_instance::init(|app, _argv, _cwd| {
            show_main(app);
        }));
    #[cfg(feature = "updater")]
    let builder = builder.plugin(tauri_plugin_updater::Builder::new().build());
    builder
        .setup(move |app| {
            let state = AppState {
                socket: socket.clone(),
                tray_available: Arc::new(AtomicBool::new(false)),
                tray_items: Mutex::new(None),
                language: Mutex::new(initial_language()),
                profile_errors: Mutex::new(Vec::new()),
            };
            app.manage(state);
            if let Err(error) = setup_tray(app) {
                eprintln!("tray unavailable: {error}");
            }
            spawn_event_listener(app.handle().clone());
            Ok(())
        })
        .on_window_event(|window, event| {
            if let WindowEvent::CloseRequested { api, .. } = event {
                let tray = window
                    .app_handle()
                    .state::<AppState>()
                    .tray_available
                    .load(Ordering::Relaxed);
                if tray {
                    api.prevent_close();
                    let _ = window.hide();
                }
            }
        })
        .invoke_handler(tauri::generate_handler![
            daemon_info,
            get_status,
            connect,
            disconnect,
            get_logs,
            list_profiles,
            profile_errors,
            save_profile,
            delete_profile,
            get_password,
            save_password,
            delete_password,
            autostart_enabled,
            set_autostart,
            system_language,
            set_ui_language,
            updater_info,
            check_update,
            install_update
        ])
        .run(tauri::generate_context!())
        .expect("error while running RustVPN client");
}

fn setup_tray(app: &tauri::App) -> tauri::Result<()> {
    let language = app
        .state::<AppState>()
        .language
        .lock()
        .map(|lang| *lang)
        .unwrap_or(UiLang::En);
    let [show_label, disconnect_label, quit_label] = language.tray_labels();
    let show = MenuItem::with_id(app, "show", show_label, true, None::<&str>)?;
    let disconnect = MenuItem::with_id(app, "disconnect", disconnect_label, true, None::<&str>)?;
    let quit = MenuItem::with_id(app, "quit", quit_label, true, None::<&str>)?;
    let menu = Menu::with_items(app, &[&show, &disconnect, &quit])?;
    let Some(icon) = app.default_window_icon().cloned() else {
        return Ok(());
    };
    TrayIconBuilder::with_id("main")
        .icon(icon)
        .tooltip("RustVPN")
        .menu(&menu)
        .on_menu_event(|app, event| match event.id().as_ref() {
            "show" => show_main(app),
            "disconnect" => spawn_disconnect(app),
            "quit" => quit_app(app),
            _ => {}
        })
        .on_tray_icon_event(|tray, event| {
            if let TrayIconEvent::Click {
                button: MouseButton::Left,
                button_state: MouseButtonState::Up,
                ..
            } = event
            {
                show_main(tray.app_handle());
            }
        })
        .build(app)?;
    let state = app.state::<AppState>();
    state.tray_available.store(true, Ordering::Relaxed);
    if let Ok(mut slot) = state.tray_items.lock() {
        *slot = Some(TrayItems {
            show,
            disconnect,
            quit,
        });
    }
    Ok(())
}

fn show_main(app: &tauri::AppHandle) {
    if let Some(window) = app.get_webview_window("main") {
        let _ = window.show();
        let _ = window.unminimize();
        let _ = window.set_focus();
    }
}

fn spawn_disconnect(_app: &tauri::AppHandle) {
    tauri::async_runtime::spawn(async move {
        disconnect_any().await;
    });
}

async fn disconnect_any() {
    for path in rustvpn_client_ipc::candidate_socket_paths() {
        if let Ok(Ok(mut client)) =
            tokio::time::timeout(Duration::from_secs(2), Client::connect(&path)).await
        {
            let _ = client.disconnect().await;
            return;
        }
    }
}

fn quit_app(app: &tauri::AppHandle) {
    let app = app.clone();
    tauri::async_runtime::spawn(async move {
        disconnect_any().await;
        app.exit(0);
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn locale_tags_map_to_supported_languages() {
        assert_eq!(UiLang::parse("zh_CN.UTF-8"), UiLang::Zh);
        assert_eq!(UiLang::parse("ru-RU"), UiLang::Ru);
        assert_eq!(UiLang::parse("en_GB"), UiLang::En);
        assert_eq!(UiLang::parse("de_DE"), UiLang::En);
    }

    #[test]
    fn updater_requires_both_endpoint_and_pubkey() {
        let empty = serde_json::json!({ "endpoints": [], "pubkey": "" });
        assert!(!updater_settings_ready(&empty));
        let endpoint_only =
            serde_json::json!({ "endpoints": ["https://example.test/{{current_version}}"] });
        assert!(!updater_settings_ready(&endpoint_only));
        let ready = serde_json::json!({
            "endpoints": ["https://example.test/{{current_version}}"],
            "pubkey": "RW..."
        });
        assert!(updater_settings_ready(&ready));
    }

    #[test]
    fn every_language_has_tray_labels() {
        for language in [UiLang::Zh, UiLang::En, UiLang::Ru] {
            let labels = language.tray_labels();
            assert!(labels.iter().all(|label| !label.trim().is_empty()));
            assert_ne!(labels[0], labels[2]);
        }
    }

    fn profile(name: &str) -> ProfileSpec {
        ProfileSpec {
            name: name.into(),
            remote: "vpn.example.com:1194".into(),
            verifier: "$argon2d$m=1024,t=4,p=1$AAECAwQFBgcICQoLDA0ODw".into(),
            ..ProfileSpec::default()
        }
    }

    fn temp_dir() -> PathBuf {
        std::env::temp_dir().join(format!(
            "rustvpn-gui-test-{}-{}",
            std::process::id(),
            TEMP_COUNTER.fetch_add(1, Ordering::Relaxed)
        ))
    }

    #[test]
    fn rename_with_colliding_stem_keeps_profile() {
        let dir = temp_dir();
        std::fs::create_dir_all(&dir).unwrap();
        save_profile_at(&dir, &profile("office lab"), None).unwrap();
        let renamed = profile("office-lab");
        save_profile_at(&dir, &renamed, Some("office lab")).unwrap();
        let saved = read_profile(&profile_path(&dir, "office-lab").unwrap()).unwrap();
        assert_eq!(saved.name, "office-lab");
        assert!(profile_path(&dir, "office-lab").unwrap().exists());
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn rejects_collision_with_another_profile() {
        let dir = temp_dir();
        std::fs::create_dir_all(&dir).unwrap();
        save_profile_at(&dir, &profile("other lab"), None).unwrap();
        let error = save_profile_at(&dir, &profile("other-lab"), None).unwrap_err();
        assert!(error.contains("collides"));
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn saves_a_valid_numeric_mtu_profile() {
        let dir = temp_dir();
        let mut spec = profile("valid");
        spec.mtu = 1515;
        save_profile_at(&dir, &spec, None).unwrap();
        let path = profile_path(&dir, "valid").unwrap();
        let saved = read_profile(&path).unwrap();
        assert_eq!(saved.mtu, 1515);
        let text = std::fs::read_to_string(&path).unwrap();
        assert!(text.contains("mtu: 1515"), "{text}");
        assert!(!text.contains("auto"), "{text}");
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn rejects_zero_and_out_of_range_mtu_before_writing() {
        let dir = temp_dir();
        for mtu in [0, 67, 9016] {
            let mut spec = profile("bad-mtu");
            spec.mtu = mtu;
            let error = save_profile_at(&dir, &spec, None).unwrap_err();
            assert!(
                error.contains("MTU") || error.contains("mtu"),
                "unexpected error for {mtu}: {error}"
            );
            assert!(
                !profile_path(&dir, "bad-mtu").unwrap().exists(),
                "invalid MTU {mtu} must not be written"
            );
        }
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn rejects_padded_mode_mtu_below_the_mode_minimum() {
        let dir = temp_dir();
        for padded in [true, false] {
            let mut spec = profile("padded");
            spec.noise = padded;
            spec.encless = !padded;
            spec.mtu = 119;
            let error = save_profile_at(&dir, &spec, None).unwrap_err();
            assert!(error.contains("noise"), "unexpected error: {error}");
            assert!(!profile_path(&dir, "padded").unwrap().exists());
        }
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn collect_profiles_reports_legacy_mtu_auto_instead_of_hiding_it() {
        let dir = temp_dir();
        std::fs::create_dir_all(&dir).unwrap();
        let valid = serde_yaml_ng::to_string(&profile("valid")).unwrap();
        std::fs::write(dir.join("valid.yaml"), valid).unwrap();
        for (name, mtu) in [("legacy-auto", "auto"), ("legacy-zero", "0")] {
            let yaml =
                format!("name: {name}\nremote: vpn.example.com:1194\nverifier: v\nmtu: {mtu}\n");
            std::fs::write(dir.join(format!("{name}.yaml")), yaml).unwrap();
        }

        let (profiles, errors) = collect_profiles(&dir).unwrap();
        assert_eq!(profiles.len(), 1);
        assert_eq!(errors.len(), 2);
        for error in &errors {
            assert!(
                error.message.contains("legacy profile rejected"),
                "{}",
                error.message
            );
            assert!(error.message.contains("1515"), "{}", error.message);
        }
        let _ = std::fs::remove_dir_all(dir);
    }
}
