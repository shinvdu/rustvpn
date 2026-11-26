//! Tauri 2 shell for the RustVPN desktop client.
//!
//! The tunnel lives in `rustvpn-clientd`; this process is unprivileged and
//! only talks to it over the local Unix socket.

#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use rustvpn_client_ipc::{Client, EngineStatus, EventStream, LogLine, ProfileSpec};
use tauri::menu::{Menu, MenuItem};
use tauri::tray::{MouseButton, MouseButtonState, TrayIconBuilder, TrayIconEvent};
use tauri::{Emitter, Manager, WindowEvent};

const KEYRING_SERVICE: &str = "rustvpn-client";

struct AppState {
    socket: PathBuf,
    tray_available: Arc<AtomicBool>,
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
fn list_profiles() -> Result<Vec<ProfileSpec>, String> {
    let dir = profiles_dir();
    if !dir.exists() {
        return Ok(Vec::new());
    }
    let entries = std::fs::read_dir(&dir).map_err(|error| error.to_string())?;
    let mut profiles = Vec::new();
    for entry in entries.flatten() {
        let path = entry.path();
        if !matches!(
            path.extension().and_then(|value| value.to_str()),
            Some("yaml" | "yml")
        ) {
            continue;
        }
        match std::fs::read_to_string(&path)
            .map_err(|error| error.to_string())
            .and_then(|text| {
                serde_yaml_ng::from_str::<ProfileSpec>(&text).map_err(|error| error.to_string())
            }) {
            Ok(profile) => profiles.push(profile),
            Err(error) => eprintln!("skip profile {}: {error}", path.display()),
        }
    }
    profiles.sort_by_key(|a| a.name.to_lowercase());
    Ok(profiles)
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
    tauri::Builder::default()
        .plugin(tauri_plugin_single_instance::init(|app, _argv, _cwd| {
            show_main(app);
        }))
        .setup(move |app| {
            let state = AppState {
                socket: socket.clone(),
                tray_available: Arc::new(AtomicBool::new(false)),
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
            save_profile,
            delete_profile,
            get_password,
            save_password,
            delete_password,
            autostart_enabled,
            set_autostart
        ])
        .run(tauri::generate_context!())
        .expect("error while running RustVPN client");
}

fn setup_tray(app: &tauri::App) -> tauri::Result<()> {
    let show = MenuItem::with_id(app, "show", "打开 RustVPN", true, None::<&str>)?;
    let disconnect = MenuItem::with_id(app, "disconnect", "断开", true, None::<&str>)?;
    let quit = MenuItem::with_id(app, "quit", "退出", true, None::<&str>)?;
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
    app.state::<AppState>()
        .tray_available
        .store(true, Ordering::Relaxed);
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
}
