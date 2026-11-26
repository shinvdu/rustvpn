//! Safe editing of `peers.yaml` / `peers.disabled.yaml`.
//!
//! The server remains the only component that *loads* `peers.yaml`; this
//! module renders, validates, backs up and atomically replaces the file, then
//! asks the server reloader to pick it up.

use std::collections::{BTreeMap, HashMap};
use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::SystemTime;

use rustvpn_crypto::blake2b;
use rustvpn_crypto::verifier::Verifier;
use rustvpn_net::config::{ConfigSet, PeerYaml};
use rustvpn_proto::{MTU_MAX, MTU_MIN, MTU_MIN_NOISE};

use crate::model::{
    rfc3339, BackupInfo, ConfigError, ConfigFiles, ConfigSnapshot, PeerId, PreviewReport,
};

const HEADER: &str = "# Managed by rustvpn-admin. Edits are validated; comments are not preserved.";

#[derive(Clone, Debug)]
pub struct ConfigPaths {
    pub enabled: PathBuf,
    pub disabled: PathBuf,
    pub backup_dir: PathBuf,
}

#[derive(Clone, Debug)]
pub struct LoadedConfig {
    pub files: ConfigFiles,
    pub enabled_raw: String,
    pub disabled_raw: String,
}

impl LoadedConfig {
    pub fn etag(&self) -> String {
        etag(&self.enabled_raw, &self.disabled_raw)
    }

    pub fn snapshot(&self) -> ConfigSnapshot {
        ConfigSnapshot {
            enabled_yaml: self.enabled_raw.clone(),
            disabled_yaml: self.disabled_raw.clone(),
            etag: self.etag(),
            files: self.files.clone(),
        }
    }
}

#[derive(Clone, Debug)]
pub struct CommitReport {
    pub backups: Vec<String>,
    pub etag: String,
    pub warnings: Vec<String>,
}

pub fn etag(enabled: &str, disabled: &str) -> String {
    hex::encode(blake2b::hash_parts(&[
        enabled.as_bytes(),
        b"\0",
        disabled.as_bytes(),
    ]))
}

pub fn load(paths: &ConfigPaths) -> Result<LoadedConfig, ConfigError> {
    let enabled_raw = fs::read_to_string(&paths.enabled)
        .map_err(|e| ConfigError::Io(format!("read {}: {e}", paths.enabled.display())))?;
    let disabled_raw = match fs::read_to_string(&paths.disabled) {
        Ok(raw) => raw,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => String::new(),
        Err(e) => {
            return Err(ConfigError::Io(format!(
                "read {}: {e}",
                paths.disabled.display()
            )))
        }
    };
    let enabled = parse_map(&enabled_raw, "peers.yaml")?;
    let disabled = parse_map(&disabled_raw, "peers.disabled.yaml")?;
    let files = ConfigFiles { enabled, disabled };
    files.validate()?;
    Ok(LoadedConfig {
        files,
        enabled_raw,
        disabled_raw,
    })
}

pub fn parse_files(enabled_yaml: &str, disabled_yaml: &str) -> Result<ConfigFiles, ConfigError> {
    let files = ConfigFiles {
        enabled: parse_map(enabled_yaml, "peers.yaml")?,
        disabled: parse_map(disabled_yaml, "peers.disabled.yaml")?,
    };
    files.validate()?;
    Ok(files)
}

fn parse_map(raw: &str, what: &str) -> Result<BTreeMap<String, PeerYaml>, ConfigError> {
    if raw.trim().is_empty() {
        return Ok(BTreeMap::new());
    }
    serde_yaml_ng::from_str(raw).map_err(|e| ConfigError::Invalid(format!("parse {what}: {e}")))
}

impl ConfigFiles {
    pub fn render(&self) -> Result<(String, String), ConfigError> {
        let enabled = render_map(&self.enabled, "peers.yaml")?;
        let disabled = render_map(&self.disabled, "peers.disabled.yaml")?;
        Ok((enabled, disabled))
    }

    pub fn validate(&self) -> Result<Vec<String>, ConfigError> {
        let (enabled, disabled) = self.render()?;
        // Reuse the server's exact parser so an admin write can never introduce
        // a configuration the daemon would reject.
        ConfigSet::from_str(&enabled)
            .map_err(|e| ConfigError::Invalid(format!("peers.yaml: {e:#}")))?;
        ConfigSet::from_str(&disabled)
            .map_err(|e| ConfigError::Invalid(format!("peers.disabled.yaml: {e:#}")))?;

        let mut names: HashMap<&str, &str> = HashMap::new();
        let mut ids: HashMap<PeerId, &str> = HashMap::new();
        let mut warnings = Vec::new();
        for (map, label) in [(&self.enabled, "enabled"), (&self.disabled, "disabled")] {
            for (name, peer) in map {
                if let Some(other) = names.insert(name.as_str(), label) {
                    return Err(ConfigError::Invalid(format!(
                        "peer name {name:?} appears in both {other} and {label} files"
                    )));
                }
                validate_peer_name(name)?;
                let verifier = Verifier::from_string(&peer.verifier)
                    .map_err(|e| ConfigError::Invalid(format!("{name}: invalid verifier: {e}")))?;
                if let Some(other) = ids.insert(verifier.id, label) {
                    return Err(ConfigError::Invalid(format!(
                        "peer identity {} appears in both {other} and {label} files",
                        hex::encode(verifier.id)
                    )));
                }
                validate_peer_settings(name, peer)?;
            }
        }

        let enabled_ifaces: HashMap<&str, &str> = self
            .enabled
            .iter()
            .filter(|(_, peer)| !peer.iface.is_empty())
            .map(|(name, peer)| (peer.iface.as_str(), name.as_str()))
            .collect();
        for (name, peer) in &self.disabled {
            if let Some(other) = enabled_ifaces.get(peer.iface.as_str()) {
                warnings.push(format!(
                    "{name} (disabled) shares interface {} with enabled peer {other}; enabling it will fail",
                    peer.iface
                ));
            }
        }
        Ok(warnings)
    }
}

fn render_map(map: &BTreeMap<String, PeerYaml>, what: &str) -> Result<String, ConfigError> {
    let body = serde_yaml_ng::to_string(map)
        .map_err(|e| ConfigError::Invalid(format!("render {what}: {e}")))?;
    Ok(format!("{HEADER}\n{body}"))
}

pub fn validate_peer_name(name: &str) -> Result<(), ConfigError> {
    if name.is_empty() || name.len() > 64 {
        return Err(ConfigError::Invalid(
            "peer name must be 1..=64 characters".into(),
        ));
    }
    if !name
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.'))
    {
        return Err(ConfigError::Invalid(
            "peer name may contain only [A-Za-z0-9_.-]".into(),
        ));
    }
    if name == "." || name == ".." {
        return Err(ConfigError::Invalid("invalid peer name".into()));
    }
    Ok(())
}

pub fn validate_peer_settings(name: &str, peer: &PeerYaml) -> Result<(), ConfigError> {
    if peer.iface.is_empty() && peer.up.is_empty() {
        return Err(ConfigError::Invalid(format!(
            "{name}: either iface or up script is required"
        )));
    }
    if peer.mtu != 0 && !(MTU_MIN..=MTU_MAX).contains(&peer.mtu) {
        return Err(ConfigError::Invalid(format!(
            "{name}: mtu must be between {MTU_MIN} and {MTU_MAX} (or 0 for the default)"
        )));
    }
    if (peer.noise || peer.encless) && peer.mtu != 0 && peer.mtu < MTU_MIN_NOISE {
        return Err(ConfigError::Invalid(format!(
            "{name}: noise/encless requires mtu >= {MTU_MIN_NOISE}"
        )));
    }
    if peer.timesync < 0 {
        return Err(ConfigError::Invalid(format!(
            "{name}: timesync must not be negative"
        )));
    }
    if peer.timeout < 0 {
        return Err(ConfigError::Invalid(format!(
            "{name}: timeout must not be negative"
        )));
    }
    if peer.timeout > 86_400 {
        return Err(ConfigError::Invalid(format!(
            "{name}: timeout must be at most 86400 seconds"
        )));
    }
    if peer.cpr > 1_000_000 {
        return Err(ConfigError::Invalid(format!(
            "{name}: cpr is unreasonably large"
        )));
    }
    for (field, value) in [("up", &peer.up), ("down", &peer.down)] {
        if value.is_empty() {
            continue;
        }
        let path = Path::new(value);
        if !path.is_absolute() {
            return Err(ConfigError::Invalid(format!(
                "{name}: {field} must be an absolute path"
            )));
        }
        if path
            .components()
            .any(|c| matches!(c, std::path::Component::ParentDir))
        {
            return Err(ConfigError::Invalid(format!(
                "{name}: {field} must not contain '..'"
            )));
        }
    }
    Ok(())
}

pub fn validate_script_allowlist(
    name: &str,
    peer: &PeerYaml,
    allowed_dirs: &[PathBuf],
) -> Result<(), ConfigError> {
    if allowed_dirs.is_empty() {
        return Ok(());
    }
    for (field, value) in [("up", &peer.up), ("down", &peer.down)] {
        if value.is_empty() {
            continue;
        }
        let path = Path::new(value);
        if !allowed_dirs.iter().any(|dir| path.starts_with(dir)) {
            return Err(ConfigError::Invalid(format!(
                "{name}: {field} must be under one of the configured script directories"
            )));
        }
    }
    Ok(())
}

pub fn commit(paths: &ConfigPaths, files: &ConfigFiles) -> Result<CommitReport, ConfigError> {
    let warnings = files.validate()?;
    let (enabled_text, disabled_text) = files.render()?;

    // Validate exactly what will be written, including YAML round-tripping.
    ConfigSet::from_str(&enabled_text)
        .map_err(|e| ConfigError::Invalid(format!("peers.yaml: {e:#}")))?;
    ConfigSet::from_str(&disabled_text)
        .map_err(|e| ConfigError::Invalid(format!("peers.disabled.yaml: {e:#}")))?;

    let backups = backup_existing(paths)?;
    write_atomic(&paths.enabled, enabled_text.as_bytes())?;
    if let Err(e) = write_atomic(&paths.disabled, disabled_text.as_bytes()) {
        // Best effort rollback of the first file.
        if let Some(name) = backups
            .iter()
            .find(|name| name.starts_with("peers-"))
            .cloned()
        {
            let _ = restore(paths, &name);
        }
        return Err(e);
    }
    Ok(CommitReport {
        backups,
        etag: etag(&enabled_text, &disabled_text),
        warnings,
    })
}

fn backup_existing(paths: &ConfigPaths) -> Result<Vec<String>, ConfigError> {
    fs::create_dir_all(&paths.backup_dir).map_err(|e| {
        ConfigError::Io(format!(
            "create backup dir {}: {e}",
            paths.backup_dir.display()
        ))
    })?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = fs::set_permissions(&paths.backup_dir, fs::Permissions::from_mode(0o750));
    }
    let base = chrono::Utc::now().format("%Y%m%d-%H%M%S").to_string();
    // Both files share one stamp so a restore can recover a consistent pair.
    let mut stamp = base.clone();
    let mut attempt = 0;
    while paths
        .backup_dir
        .join(format!("peers-{stamp}.yaml"))
        .exists()
        || paths
            .backup_dir
            .join(format!("peers.disabled-{stamp}.yaml"))
            .exists()
    {
        attempt += 1;
        stamp = format!("{base}-{attempt}");
    }
    let mut backups = Vec::new();
    for (path, prefix) in [
        (&paths.enabled, "peers"),
        (&paths.disabled, "peers.disabled"),
    ] {
        if !path.exists() {
            continue;
        }
        let name = format!("{prefix}-{stamp}.yaml");
        let target = paths.backup_dir.join(&name);
        fs::copy(path, &target)
            .map_err(|e| ConfigError::Io(format!("backup {}: {e}", path.display())))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = fs::set_permissions(&target, fs::Permissions::from_mode(0o640));
        }
        backups.push(name);
    }
    Ok(backups)
}

fn write_atomic(path: &Path, bytes: &[u8]) -> Result<(), ConfigError> {
    let dir = path
        .parent()
        .ok_or_else(|| ConfigError::Io(format!("{} has no parent directory", path.display())))?;
    let name = path
        .file_name()
        .and_then(|n| n.to_str())
        .ok_or_else(|| ConfigError::Io(format!("invalid path {}", path.display())))?;
    let tmp = dir.join(format!(
        ".{name}.tmp.{}.{}",
        std::process::id(),
        random_suffix()
    ));
    {
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o640);
        }
        let mut file = options
            .open(&tmp)
            .map_err(|e| ConfigError::Io(format!("create {}: {e}", tmp.display())))?;
        file.write_all(bytes)
            .map_err(|e| ConfigError::Io(format!("write {}: {e}", tmp.display())))?;
        file.sync_all()
            .map_err(|e| ConfigError::Io(format!("sync {}: {e}", tmp.display())))?;
    }
    fs::rename(&tmp, path).map_err(|e| {
        let _ = fs::remove_file(&tmp);
        ConfigError::Io(format!("replace {}: {e}", path.display()))
    })?;
    if let Ok(dir_file) = File::open(dir) {
        let _ = dir_file.sync_all();
    }
    Ok(())
}

fn random_suffix() -> String {
    let mut buf = [0u8; 4];
    let _ = getrandom::getrandom(&mut buf);
    hex::encode(buf)
}

pub fn list_backups(paths: &ConfigPaths) -> Result<Vec<BackupInfo>, ConfigError> {
    let entries = match fs::read_dir(&paths.backup_dir) {
        Ok(entries) => entries,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => {
            return Err(ConfigError::Io(format!(
                "read {}: {e}",
                paths.backup_dir.display()
            )))
        }
    };
    let mut out = Vec::new();
    for entry in entries {
        let entry = entry.map_err(|e| ConfigError::Io(format!("read backup dir: {e}")))?;
        let name = entry.file_name().to_string_lossy().to_string();
        if !name.starts_with("peers-") || !name.ends_with(".yaml") {
            continue;
        }
        let meta = entry
            .metadata()
            .map_err(|e| ConfigError::Io(format!("stat {name}: {e}")))?;
        let modified = meta
            .modified()
            .ok()
            .and_then(|t| t.duration_since(SystemTime::UNIX_EPOCH).ok())
            .map(|d| rfc3339(d.as_secs() as i64))
            .unwrap_or_default();
        out.push(BackupInfo {
            name,
            size: meta.len(),
            modified,
        });
    }
    out.sort_by(|a, b| b.name.cmp(&a.name));
    Ok(out)
}

pub struct RestorePlan {
    files: ConfigFiles,
    enabled_raw: Option<String>,
    disabled_raw: Option<String>,
}

pub fn plan_restore(paths: &ConfigPaths, name: &str) -> Result<RestorePlan, ConfigError> {
    if name.contains('/') || name.contains('\\') || name.contains("..") {
        return Err(ConfigError::Invalid("invalid backup name".into()));
    }
    let stamp = if let Some(rest) = name.strip_prefix("peers.disabled-") {
        rest
    } else if let Some(rest) = name.strip_prefix("peers-") {
        rest
    } else {
        return Err(ConfigError::Invalid("unrecognized backup name".into()));
    };
    let stamp = stamp
        .strip_suffix(".yaml")
        .ok_or_else(|| ConfigError::Invalid("unrecognized backup name".into()))?;
    let enabled_source = paths.backup_dir.join(format!("peers-{stamp}.yaml"));
    let disabled_source = paths
        .backup_dir
        .join(format!("peers.disabled-{stamp}.yaml"));
    if !enabled_source.exists() && !disabled_source.exists() {
        return Err(ConfigError::Io(format!("backup {name} not found")));
    }
    let enabled_raw = read_optional(&enabled_source)?;
    let disabled_raw = read_optional(&disabled_source)?;
    // Validate the result against the *current* other file before writing, so
    // restoring one half of a pair can never leave duplicate names/ids behind.
    let enabled_text = match &enabled_raw {
        Some(raw) => raw.clone(),
        None => fs::read_to_string(&paths.enabled).unwrap_or_default(),
    };
    let disabled_text = match &disabled_raw {
        Some(raw) => raw.clone(),
        None => fs::read_to_string(&paths.disabled).unwrap_or_default(),
    };
    let files = ConfigFiles {
        enabled: parse_map(&enabled_text, "peers.yaml")?,
        disabled: parse_map(&disabled_text, "peers.disabled.yaml")?,
    };
    files.validate()?;
    Ok(RestorePlan {
        files,
        enabled_raw,
        disabled_raw,
    })
}

pub fn restore(paths: &ConfigPaths, name: &str) -> Result<(), ConfigError> {
    let plan = plan_restore(paths, name)?;
    write_restore(paths, &plan)
}

/// Restore a backup after checking that every script path stays inside the
/// admin's allow-list.  The server applies its own ownership/permission
/// checks on reload.
pub fn restore_checked(
    paths: &ConfigPaths,
    name: &str,
    allowed_dirs: &[PathBuf],
) -> Result<(), ConfigError> {
    let plan = plan_restore(paths, name)?;
    for (name, peer) in plan.files.enabled.iter().chain(plan.files.disabled.iter()) {
        validate_script_allowlist(name, peer, allowed_dirs)?;
    }
    write_restore(paths, &plan)
}

fn write_restore(paths: &ConfigPaths, plan: &RestorePlan) -> Result<(), ConfigError> {
    if let Some(raw) = &plan.enabled_raw {
        write_atomic(&paths.enabled, raw.as_bytes())?;
    }
    if let Some(raw) = &plan.disabled_raw {
        write_atomic(&paths.disabled, raw.as_bytes())?;
    }
    Ok(())
}

fn read_optional(path: &Path) -> Result<Option<String>, ConfigError> {
    match fs::read_to_string(path) {
        Ok(raw) => Ok(Some(raw)),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(ConfigError::Io(format!("read {}: {e}", path.display()))),
    }
}

pub fn find_peer<'a>(files: &'a ConfigFiles, id: &PeerId) -> Option<(&'a str, &'a PeerYaml, bool)> {
    for (enabled, map) in [(&true, &files.enabled), (&false, &files.disabled)] {
        for (name, peer) in map {
            if crate::model::peer_id_of(peer).as_ref() == Some(id) {
                return Some((name.as_str(), peer, *enabled));
            }
        }
    }
    None
}

pub fn diff(
    current: &ConfigFiles,
    next: &ConfigFiles,
) -> (Vec<String>, Vec<String>, Vec<String>, Vec<String>) {
    let mut added = Vec::new();
    let mut removed = Vec::new();
    let mut changed = Vec::new();
    let mut revoked = Vec::new();
    let current_flat: HashMap<&str, &PeerYaml> = current
        .enabled
        .iter()
        .chain(current.disabled.iter())
        .map(|(name, peer)| (name.as_str(), peer))
        .collect();
    let next_flat: HashMap<&str, &PeerYaml> = next
        .enabled
        .iter()
        .chain(next.disabled.iter())
        .map(|(name, peer)| (name.as_str(), peer))
        .collect();
    for name in next_flat.keys() {
        if !current_flat.contains_key(name) {
            added.push((*name).to_string());
        }
    }
    for (name, peer) in &current_flat {
        match next_flat.get(name) {
            None => {
                removed.push((*name).to_string());
                revoked.push((*name).to_string());
            }
            Some(next_peer) => {
                if *peer != *next_peer {
                    changed.push((*name).to_string());
                    revoked.push((*name).to_string());
                }
            }
        }
    }
    added.sort();
    removed.sort();
    changed.sort();
    revoked.sort();
    revoked.dedup();
    (added, removed, changed, revoked)
}

pub fn preview(
    current: &LoadedConfig,
    enabled_yaml: &str,
    disabled_yaml: &str,
) -> Result<PreviewReport, ConfigError> {
    match parse_files(enabled_yaml, disabled_yaml) {
        Ok(next) => {
            let warnings = next.validate()?;
            let (added, removed, changed, revoked) = diff(&current.files, &next);
            Ok(PreviewReport {
                valid: true,
                errors: Vec::new(),
                warnings,
                added,
                removed,
                changed,
                revoked,
            })
        }
        Err(err) => Ok(PreviewReport {
            valid: false,
            errors: vec![err.to_string()],
            warnings: Vec::new(),
            added: Vec::new(),
            removed: Vec::new(),
            changed: Vec::new(),
            revoked: Vec::new(),
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustvpn_crypto::verifier::Verifier;

    fn peer(name: &str, iface: &str) -> PeerYaml {
        let mut verifier = Verifier::new(1024, 2, 1, [name.len() as u8; 16]);
        verifier.password_apply(name).unwrap();
        PeerYaml {
            iface: iface.into(),
            mtu: 1515,
            timeout: 60,
            verifier: verifier.long_form().unwrap(),
            ..PeerYaml::default()
        }
    }

    #[test]
    fn render_validate_and_etag() {
        let mut files = ConfigFiles::default();
        files.enabled.insert("alice".into(), peer("alice", "tap0"));
        files.disabled.insert("bob".into(), peer("bob", "tap1"));
        let warnings = files.validate().unwrap();
        assert!(warnings.is_empty());
        let (enabled, disabled) = files.render().unwrap();
        assert!(enabled.contains("alice:"));
        assert!(disabled.contains("bob:"));
        let parsed = parse_files(&enabled, &disabled).unwrap();
        assert_eq!(parsed.enabled.len(), 1);
        assert_eq!(parsed.disabled.len(), 1);
        assert_ne!(etag(&enabled, &disabled), etag(&enabled, ""));
    }

    #[test]
    fn rejects_duplicate_names_and_bad_mtu() {
        let mut files = ConfigFiles::default();
        files.enabled.insert("alice".into(), peer("alice", "tap0"));
        files.disabled.insert("alice".into(), peer("alice", "tap1"));
        assert!(files.validate().is_err());

        let mut bad = peer("bob", "tap0");
        bad.mtu = 10;
        let mut files = ConfigFiles::default();
        files.enabled.insert("bob".into(), bad);
        assert!(files.validate().is_err());
    }

    #[test]
    fn atomic_commit_and_restore() {
        let dir = tempfile::tempdir().unwrap();
        let paths = ConfigPaths {
            enabled: dir.path().join("peers.yaml"),
            disabled: dir.path().join("peers.disabled.yaml"),
            backup_dir: dir.path().join("backups"),
        };
        let mut files = ConfigFiles::default();
        files.enabled.insert("alice".into(), peer("alice", "tap0"));
        let report = commit(&paths, &files).unwrap();
        assert!(report.backups.is_empty()); // nothing existed yet
        let loaded = load(&paths).unwrap();
        assert_eq!(loaded.files.enabled.len(), 1);

        files
            .disabled
            .insert("alice".into(), files.enabled.remove("alice").unwrap());
        let report = commit(&paths, &files).unwrap();
        assert!(!report.backups.is_empty());
        assert!(load(&paths).unwrap().files.enabled.is_empty());

        let enabled_backup = report
            .backups
            .iter()
            .find(|name| name.starts_with("peers-") && !name.starts_with("peers.disabled-"))
            .unwrap();
        let disabled_backup = report
            .backups
            .iter()
            .find(|name| name.starts_with("peers.disabled-"))
            .unwrap();
        restore(&paths, enabled_backup).unwrap();
        restore(&paths, disabled_backup).unwrap();
        let loaded = load(&paths).unwrap();
        assert_eq!(loaded.files.enabled.len(), 1);
        assert!(loaded.files.disabled.is_empty());
    }

    #[test]
    fn restore_checked_rejects_scripts_outside_allowlist() {
        let dir = tempfile::tempdir().unwrap();
        let paths = ConfigPaths {
            enabled: dir.path().join("peers.yaml"),
            disabled: dir.path().join("peers.disabled.yaml"),
            backup_dir: dir.path().join("backups"),
        };
        std::fs::write(&paths.enabled, "").unwrap();
        std::fs::create_dir_all(&paths.backup_dir).unwrap();
        let allowed = dir.path().join("scripts");
        std::fs::create_dir_all(&allowed).unwrap();

        let mut files = ConfigFiles::default();
        let mut entry = peer("alice", "tap0");
        entry.up = "/outside/up.sh".into();
        files.enabled.insert("alice".into(), entry);
        let (enabled, _) = files.render().unwrap();
        let name = "peers-20261126-000000.yaml";
        std::fs::write(paths.backup_dir.join(name), enabled).unwrap();

        let error = restore_checked(&paths, name, &[allowed]).unwrap_err();
        assert!(error.to_string().contains("must be under"));
        assert_eq!(std::fs::read_to_string(&paths.enabled).unwrap(), "");
    }
}
