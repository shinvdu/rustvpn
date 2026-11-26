//! Tauri 2 shell for the RustVPN desktop client.
//!
//! The tunnel lives in `rustvpn-clientd`; this process is unprivileged and
//! only talks to it over the local Unix socket.

#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use rustvpn_client_ipc::{Client, EngineStatus, EventStream, LogLine, ProfileSpec};
use tauri::{Emitter, Manager};

struct AppState {
    socket: PathBuf,
}

static TEMP_COUNTER: AtomicU64 = AtomicU64::new(0);

#[tauri::command]
async fn daemon_info(state: tauri::State<'_, AppState>) -> Result<serde_json::Value, String> {
    Ok(serde_json::json!({
        "socket": state.socket.to_string_lossy(),
        "version": env!("CARGO_PKG_VERSION"),
    }))
}

#[tauri::command]
async fn get_status(state: tauri::State<'_, AppState>) -> Result<EngineStatus, String> {
    let mut client = ipc_client(&state, Duration::from_secs(2)).await?;
    tokio::time::timeout(Duration::from_secs(2), client.status())
        .await
        .map_err(|_| "daemon status timed out".to_string())?
        .map_err(|error| error.to_string())
}

#[tauri::command]
async fn connect(
    profile: ProfileSpec,
    password: String,
    state: tauri::State<'_, AppState>,
) -> Result<(), String> {
    if password.is_empty() {
        return Err("passphrase is empty".into());
    }
    let mut client = ipc_client(&state, Duration::from_secs(3)).await?;
    tokio::time::timeout(
        Duration::from_secs(5),
        client.connect_profile(profile, password),
    )
    .await
    .map_err(|_| "daemon did not answer".to_string())?
    .map_err(|error| error.to_string())
}

#[tauri::command]
async fn disconnect(state: tauri::State<'_, AppState>) -> Result<(), String> {
    let mut client = ipc_client(&state, Duration::from_secs(3)).await?;
    tokio::time::timeout(Duration::from_secs(5), client.disconnect())
        .await
        .map_err(|_| "daemon did not answer".to_string())?
        .map_err(|error| error.to_string())
}

#[tauri::command]
async fn get_logs(limit: u32, state: tauri::State<'_, AppState>) -> Result<Vec<LogLine>, String> {
    let mut client = ipc_client(&state, Duration::from_secs(2)).await?;
    tokio::time::timeout(Duration::from_secs(3), client.logs(limit))
        .await
        .map_err(|_| "daemon logs timed out".to_string())?
        .map_err(|error| error.to_string())
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
fn save_profile(profile: ProfileSpec, previous_name: Option<String>) -> Result<(), String> {
    save_profile_at(&profiles_dir(), &profile, previous_name.as_deref())
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
fn delete_profile(name: String) -> Result<(), String> {
    let file = profile_path(&profiles_dir(), &name)?;
    if file.exists() {
        std::fs::remove_file(file).map_err(|error| error.to_string())?;
    }
    Ok(())
}

fn profile_path(dir: &Path, name: &str) -> Result<PathBuf, String> {
    Ok(dir.join(format!("{}.yaml", file_stem(name)?)))
}

fn read_profile(path: &Path) -> Result<ProfileSpec, String> {
    let text = std::fs::read_to_string(path).map_err(|error| error.to_string())?;
    serde_yaml_ng::from_str(&text).map_err(|error| error.to_string())
}

async fn ipc_client(state: &AppState, timeout: Duration) -> Result<Client, String> {
    tokio::time::timeout(timeout, Client::connect(&state.socket))
        .await
        .map_err(|_| "client daemon is not reachable".to_string())?
        .map_err(|error| error.to_string())
}

fn spawn_event_listener(app: tauri::AppHandle, socket: PathBuf) {
    tauri::async_runtime::spawn(async move {
        loop {
            match EventStream::subscribe(&socket).await {
                Ok(mut stream) => {
                    eprintln!("daemon event subscription established");
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
                }
                Err(error) => {
                    eprintln!("daemon event subscription failed: {error}");
                }
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
        .setup(move |app| {
            app.manage(AppState {
                socket: socket.clone(),
            });
            spawn_event_listener(app.handle().clone(), socket.clone());
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            daemon_info,
            get_status,
            connect,
            disconnect,
            get_logs,
            list_profiles,
            save_profile,
            delete_profile
        ])
        .run(tauri::generate_context!())
        .expect("error while running RustVPN client");
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
