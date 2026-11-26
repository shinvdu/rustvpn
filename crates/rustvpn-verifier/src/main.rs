//! GoVPN 5.7-compatible verifier generator/validator.

use std::env;
use std::fs;
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::process;

use rand_core::RngCore;
use rustvpn_crypto::egd::EgDRng;
use rustvpn_crypto::verifier::{Verifier, DEFAULT_M, DEFAULT_P, DEFAULT_T, ID_SIZE};

const WARRANTY: &str = r#"This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>."#;

struct Args {
    key: Option<String>,
    verifier: Option<String>,
    m: u32,
    t: u32,
    p: u32,
    egd: Option<String>,
    warranty: bool,
    // One-step onboarding (all optional; no password is ever written).
    profile: Option<String>,
    profile_out: Option<String>,
    qr: Option<String>,
    remote: Option<String>,
    proto: String,
    mtu: String,
    iface: Option<String>,
    address: Option<String>,
    gateway: Option<String>,
    dns: Vec<String>,
    routes: Vec<String>,
    noise: bool,
    encless: bool,
    kill_switch: bool,
    mss_clamp: bool,
    keepalive: u64,
    rekey_time: u64,
    rekey_jitter: u64,
}

fn usage() -> ! {
    eprintln!(
        "Usage of rustvpn-verifier:\n\
         \x20 -egd string\n\
         \x20   Optional path to EGD socket\n\
         \x20 -key string\n\
         \x20   Path to passphrase file\n\
         \x20 -m int\n\
         \x20   Argon2d memory parameter (KiBs) (default {DEFAULT_M})\n\
         \x20 -p int\n\
         \x20   Argon2d parallelizm parameter (default {DEFAULT_P})\n\
         \x20 -t int\n\
         \x20   Argon2d iteration parameter (default {DEFAULT_T})\n\
         \x20 -verifier string\n\
         \x20   Optional verifier\n\
         \x20 -warranty\n\
         \x20   Print warranty information\n\
         \n\
         One-step onboarding (no password is written to any file):\n\
         \x20 -profile name      Write a client profile YAML (0600)\n\
         \x20 -profile-out path  Override the profile output path\n\
         \x20 -qr path           Write a QR PNG (uses qrencode if installed)\n\
         \x20 -remote host:port  Client profile remote address\n\
         \x20 -proto string      Client profile protocol (default \"udp\")\n\
         \x20 -mtu value         Numeric wire MTU shared with the server (default 1515;\n\
         \x20                    \"auto\" is rejected in v1)\n\
         \x20 -iface string      Client profile interface (default \"rsvpn-gui\")\n\
         \x20 -address cidr      Client profile TAP address (default 10.88.0.2/24)\n\
         \x20 -gateway ip        Client profile gateway (default 10.88.0.1)\n\
         \x20 -dns ip            DNS server (repeatable; default 10.88.0.1)\n\
         \x20 -routes cidr       Route (repeatable; default \"default\")\n\
         \x20 -noise             Enable noise padding in the profile\n\
         \x20 -encless           Enable encless mode in the profile (forces noise)\n\
         \x20 -kill-switch        Enable the full-tunnel kill switch\n\
         \x20 -mss-clamp          Enable MSS clamping on the tunnel interface\n\
         \x20 -keepalive int     Idle keepalive seconds (0 off; 25 recommended)\n\
         \x20 -rekey-time int    Time-driven rekey seconds (0 off; default 1800)\n\
         \x20 -rekey-jitter int  Random jitter seconds added to rekey-time"
    );
    process::exit(2);
}

fn parse_args() -> Args {
    let mut args = Args {
        key: None,
        verifier: None,
        m: DEFAULT_M,
        t: DEFAULT_T,
        p: DEFAULT_P,
        egd: None,
        warranty: false,
        profile: None,
        profile_out: None,
        qr: None,
        remote: None,
        proto: "udp".into(),
        mtu: "1515".into(),
        iface: None,
        address: None,
        gateway: None,
        dns: Vec::new(),
        routes: Vec::new(),
        noise: false,
        encless: false,
        kill_switch: false,
        mss_clamp: false,
        keepalive: 0,
        rekey_time: 1800,
        rekey_jitter: 0,
    };
    let mut it = env::args().skip(1);
    while let Some(arg) = it.next() {
        let (name, inline) = match arg.split_once('=') {
            Some((n, v)) => (n.trim_start_matches('-').to_string(), Some(v.to_string())),
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
            "key" => args.key = Some(take("key")),
            "verifier" => args.verifier = Some(take("verifier")),
            "egd" => args.egd = Some(take("egd")),
            "m" => args.m = parse_u32("m", &take("m")),
            "t" => args.t = parse_u32("t", &take("t")),
            "p" => args.p = parse_u32("p", &take("p")),
            "profile" => args.profile = Some(take("profile")),
            "profile-out" => args.profile_out = Some(take("profile-out")),
            "qr" => args.qr = Some(take("qr")),
            "remote" => args.remote = Some(take("remote")),
            "proto" => args.proto = take("proto"),
            "mtu" => args.mtu = take("mtu"),
            "iface" => args.iface = Some(take("iface")),
            "address" => args.address = Some(take("address")),
            "gateway" => args.gateway = Some(take("gateway")),
            "dns" => args.dns.push(take("dns")),
            "routes" => args.routes.push(take("routes")),
            "noise" => args.noise = true,
            "encless" => args.encless = true,
            "kill-switch" => args.kill_switch = true,
            "mss-clamp" => args.mss_clamp = true,
            "keepalive" => args.keepalive = parse_u64("keepalive", &take("keepalive")),
            "rekey-time" => args.rekey_time = parse_u64("rekey-time", &take("rekey-time")),
            "rekey-jitter" => args.rekey_jitter = parse_u64("rekey-jitter", &take("rekey-jitter")),
            "warranty" => args.warranty = true,
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

fn parse_u32(name: &str, s: &str) -> u32 {
    s.parse().unwrap_or_else(|_| {
        eprintln!("invalid value {s:?} for flag -{name}");
        usage()
    })
}

fn parse_u64(name: &str, s: &str) -> u64 {
    s.parse().unwrap_or_else(|_| {
        eprintln!("invalid value {s:?} for flag -{name}");
        usage()
    })
}

fn read_passphrase(path: &Option<String>) -> String {
    match path {
        Some(path) => {
            let raw = fs::read_to_string(path).unwrap_or_else(|e| {
                eprintln!("Unable to read the key: {e}");
                process::exit(1);
            });
            raw.trim_end_matches('\n').to_string()
        }
        None => rpassword::prompt_password("Passphrase:").unwrap_or_else(|e| {
            eprintln!("Unable to read passphrase: {e}");
            process::exit(1);
        }),
    }
}

fn random_id(egd: &Option<String>) -> [u8; ID_SIZE] {
    let mut id = [0u8; ID_SIZE];
    match egd {
        Some(path) => EgDRng::new(path).fill_bytes(&mut id),
        None => getrandom::getrandom(&mut id).unwrap_or_else(|e| {
            eprintln!("Unable to obtain random identity: {e}");
            process::exit(1);
        }),
    }
    id
}

fn sanitize_stem(name: &str) -> Result<String, String> {
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

fn profiles_dir() -> Result<PathBuf, String> {
    profiles_dir_from(env::var_os("XDG_CONFIG_HOME"), env::var_os("HOME"))
}

fn profiles_dir_from(
    xdg: Option<std::ffi::OsString>,
    home: Option<std::ffi::OsString>,
) -> Result<PathBuf, String> {
    if let Some(dir) = xdg {
        if !dir.is_empty() {
            return Ok(PathBuf::from(dir).join("rustvpn").join("profiles"));
        }
    }
    let home = home.filter(|value| !value.is_empty()).ok_or_else(|| {
        "HOME is not set; refusing to write a client profile under /tmp. \
         Set HOME/XDG_CONFIG_HOME or pass -profile-out"
            .to_string()
    })?;
    Ok(PathBuf::from(home)
        .join(".config")
        .join("rustvpn")
        .join("profiles"))
}

/// Parent directory to create, skipping a bare relative filename whose
/// `parent()` is the empty path.
fn creation_parent(path: &Path) -> Option<&Path> {
    path.parent()
        .filter(|parent| !parent.as_os_str().is_empty())
}

fn write_private_file(path: &Path, data: &[u8]) -> Result<(), String> {
    use std::os::unix::fs::PermissionsExt;
    if let Some(parent) = creation_parent(path) {
        if !parent.exists() {
            // Remember every directory we are about to create so each one
            // (not just the leaf) is owner-only.  A pre-existing XDG_CONFIG_HOME
            // is left untouched.
            let mut created = Vec::new();
            let mut current = parent;
            while !current.exists() {
                created.push(current.to_path_buf());
                match current.parent() {
                    Some(next) => current = next,
                    None => break,
                }
            }
            fs::create_dir_all(parent)
                .map_err(|error| format!("create {}: {error}", parent.display()))?;
            for dir in created {
                fs::set_permissions(&dir, fs::Permissions::from_mode(0o700))
                    .map_err(|error| format!("chmod {}: {error}", dir.display()))?;
            }
        }
    }

    // Reserve a unique owner-only temporary file with O_EXCL: an attacker
    // cannot pre-create a symlink at the name we then write through.
    let (tmp, mut file) = create_private_temp(path)?;
    let write_result = file
        .write_all(data)
        .and_then(|_| file.sync_all())
        .map_err(|error| format!("write {}: {error}", tmp.display()));
    drop(file);
    if let Err(error) = write_result {
        let _ = fs::remove_file(&tmp);
        return Err(error);
    }
    fs::set_permissions(&tmp, fs::Permissions::from_mode(0o600))
        .map_err(|error| format!("chmod {}: {error}", tmp.display()))?;
    if let Err(error) = fs::rename(&tmp, path) {
        let _ = fs::remove_file(&tmp);
        return Err(format!("rename {}: {error}", path.display()));
    }
    fs::set_permissions(path, fs::Permissions::from_mode(0o600))
        .map_err(|error| format!("chmod {}: {error}", path.display()))?;
    Ok(())
}

fn create_private_temp(path: &Path) -> Result<(PathBuf, fs::File), String> {
    use std::os::unix::fs::OpenOptionsExt;
    let file_name = path
        .file_name()
        .and_then(|value| value.to_str())
        .unwrap_or("profile");
    for _ in 0..8 {
        let mut random = [0u8; 8];
        getrandom::getrandom(&mut random)
            .map_err(|error| format!("random suffix for {}: {error}", path.display()))?;
        let suffix: String = random.iter().map(|byte| format!("{byte:02x}")).collect();
        let candidate = path.with_file_name(format!(".{file_name}.{}.{suffix}.tmp", process::id()));
        match fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&candidate)
        {
            Ok(file) => return Ok((candidate, file)),
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(error) => {
                return Err(format!(
                    "create temporary file {}: {error}",
                    candidate.display()
                ))
            }
        }
    }
    Err(format!(
        "could not reserve a unique temporary file next to {}",
        path.display()
    ))
}

fn yaml_string(value: &str) -> String {
    let escaped = value
        .replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace('\n', "\\n")
        .replace('\r', "\\r")
        .replace('\t', "\\t");
    format!("\"{escaped}\"")
}

fn percent_encode(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for byte in value.as_bytes() {
        if byte.is_ascii_alphanumeric() || matches!(*byte, b'-' | b'_' | b'.' | b'~') {
            out.push(*byte as char);
        } else {
            out.push_str(&format!("%{byte:02X}"));
        }
    }
    out
}

fn find_qrencode() -> Option<PathBuf> {
    if let Some(path) = env::var_os("RUSTVPN_QRENCODE_BIN") {
        return Some(PathBuf::from(path));
    }
    let path = env::var_os("PATH")?;
    for dir in env::split_paths(&path) {
        let candidate = dir.join("qrencode");
        if candidate.is_file() {
            return Some(candidate);
        }
    }
    None
}

fn validate_profile_mtu(value: &str, noise: bool) -> Result<(), String> {
    let value = value.trim();
    if value.eq_ignore_ascii_case("auto") {
        return Err(
            "-mtu auto is not supported in v1; use the numeric wire MTU shared by the \
             server (for example 1515). Path-MTU negotiation is deferred to v2"
                .into(),
        );
    }
    let mtu: usize = value
        .parse()
        .map_err(|_| format!("invalid -mtu {value:?}; use a numeric value (for example 1515)"))?;
    if mtu == 0 {
        return Err("-mtu 0 is invalid; use a positive numeric wire MTU".into());
    }
    if !(68..=9015).contains(&mtu) {
        return Err(format!("MTU must be between 68 and 9015 (got {mtu})"));
    }
    if noise && mtu < 120 {
        return Err(format!("noise/encless requires MTU >= 120 (got {mtu})"));
    }
    // The generated profile must satisfy the same derived-TAP-IP-MTU contract
    // as the daemon: plain wire values below 83 derive an IP MTU below 68.
    if !noise {
        let derived = mtu.saturating_sub(1 + 14);
        if derived < 68 {
            return Err(format!(
                "MTU {mtu} derives TAP IP MTU {derived}, below the minimum 68; use at least 83"
            ));
        }
    }
    Ok(())
}

fn validate_tuning(args: &Args, noise: bool) -> Result<(), String> {
    if args.keepalive > 0 {
        let minimum = if noise { 25 } else { 10 };
        if args.keepalive < minimum {
            return Err(format!(
                "keepalive must be 0 (off) or at least {minimum}s for this mode"
            ));
        }
        if args.keepalive > 3600 || args.keepalive >= 60 {
            return Err("keepalive must be <= 3600s and shorter than timeout (60s)".into());
        }
    }
    if args.rekey_time > 0 {
        if !(60..=86_400).contains(&args.rekey_time)
            || args.rekey_jitter > 3600
            || args.rekey_jitter > args.rekey_time
        {
            return Err(
                "rekey-time must be 60..=86400s and rekey-jitter 0..=min(rekey-time,3600)".into(),
            );
        }
    } else if args.rekey_jitter > 0 {
        return Err("rekey-jitter requires a non-zero rekey-time".into());
    }
    Ok(())
}

fn onboarding_profile(args: &Args, verifier: &Verifier) -> Result<(String, String), String> {
    let name = args
        .profile
        .clone()
        .or_else(|| {
            args.profile_out
                .as_ref()
                .and_then(|path| Path::new(path).file_stem())
                .and_then(|stem| stem.to_str())
                .map(str::to_string)
        })
        .unwrap_or_else(|| "rustvpn".to_string());
    // Keep the profile name filesystem/YAML safe (no newlines or quotes).
    let name = sanitize_stem(&name)?;
    let remote = args
        .remote
        .as_deref()
        .filter(|value| !value.trim().is_empty())
        .ok_or_else(|| "-remote is required when writing a profile or QR".to_string())?;
    let proto = args.proto.to_ascii_lowercase();
    if proto != "udp" && proto != "tcp" {
        return Err(format!("unknown -proto {proto:?}; use udp or tcp"));
    }
    if args.encless && proto != "tcp" {
        return Err("encless mode works only with TCP".into());
    }
    let noise = args.noise || args.encless;
    validate_profile_mtu(&args.mtu, noise)?;
    validate_tuning(args, noise)?;
    let mtu = args.mtu.trim().to_string();
    if args.kill_switch
        && !args.routes.is_empty()
        && !args
            .routes
            .iter()
            .any(|route| matches!(route.as_str(), "default" | "0.0.0.0/0"))
    {
        return Err("-kill-switch requires a full-tunnel profile (default route)".into());
    }

    let iface = args.iface.clone().unwrap_or_else(|| "rsvpn-gui".into());
    let address = args
        .address
        .clone()
        .unwrap_or_else(|| "10.88.0.2/24".into());
    let gateway = args.gateway.clone().unwrap_or_else(|| "10.88.0.1".into());
    let dns = if args.dns.is_empty() {
        vec!["10.88.0.1".to_string()]
    } else {
        args.dns.clone()
    };
    let routes = if args.routes.is_empty() {
        vec!["default".to_string()]
    } else {
        args.routes.clone()
    };
    let mss_clamp = args.mss_clamp;

    let mut yaml = String::new();
    yaml.push_str(&format!("name: {}\n", yaml_string(&name)));
    yaml.push_str(&format!("remote: {}\n", yaml_string(remote)));
    yaml.push_str(&format!("proto: {}\n", yaml_string(&proto)));
    yaml.push_str(&format!(
        "verifier: {}\n",
        yaml_string(&verifier.short_form())
    ));
    yaml.push_str(&format!("mtu: {mtu}\n"));
    yaml.push_str(&format!("mss_clamp: {mss_clamp}\n"));
    yaml.push_str(&format!("kill_switch: {}\n", args.kill_switch));
    yaml.push_str(&format!("keepalive: {}\n", args.keepalive));
    yaml.push_str(&format!("rekey_time: {}\n", args.rekey_time));
    yaml.push_str(&format!("rekey_jitter: {}\n", args.rekey_jitter));
    yaml.push_str("timeout: 60\ntimesync: 0\n");
    yaml.push_str(&format!("noise: {}\n", noise && !args.encless));
    yaml.push_str(&format!("encless: {}\n", args.encless));
    yaml.push_str("cpr: 0\n");
    yaml.push_str(&format!("iface: {}\n", yaml_string(&iface)));
    yaml.push_str(&format!("address: {}\n", yaml_string(&address)));
    yaml.push_str(&format!("gateway: {}\n", yaml_string(&gateway)));
    yaml.push_str(&format!(
        "dns: [{}]\n",
        dns.iter()
            .map(|value| yaml_string(value))
            .collect::<Vec<_>>()
            .join(", ")
    ));
    yaml.push_str(&format!(
        "routes: [{}]\n",
        routes
            .iter()
            .map(|value| yaml_string(value))
            .collect::<Vec<_>>()
            .join(", ")
    ));
    yaml.push_str("ipv6: false\n");

    // The URI carries every non-secret profile field so it is a faithful
    // reference, but v1 ships no automatic importer: it is informational and
    // the YAML file remains the canonical profile.
    let uri = format!(
        "rustvpn://profile?name={}&remote={}&proto={}&verifier={}&mtu={}&iface={}\
         &address={}&gateway={}&dns={}&routes={}&noise={}&encless={}\
         &keepalive={}&rekey_time={}&rekey_jitter={}&mss_clamp={}&kill_switch={}",
        percent_encode(&name),
        percent_encode(remote),
        percent_encode(&proto),
        percent_encode(&verifier.short_form()),
        percent_encode(&mtu),
        percent_encode(&iface),
        percent_encode(&address),
        percent_encode(&gateway),
        percent_encode(&dns.join(",")),
        percent_encode(&routes.join(",")),
        noise && !args.encless,
        args.encless,
        args.keepalive,
        args.rekey_time,
        args.rekey_jitter,
        mss_clamp,
        args.kill_switch
    );
    Ok((yaml, uri))
}

fn emit_onboarding(args: &Args, verifier: &Verifier) -> Result<(), String> {
    let wants_profile = args.profile.is_some() || args.profile_out.is_some();
    let (yaml, uri) = onboarding_profile(args, verifier)?;
    if wants_profile {
        let path = match &args.profile_out {
            Some(path) => PathBuf::from(path),
            None => {
                let name = args.profile.as_deref().unwrap_or("rustvpn");
                profiles_dir()?.join(format!("{}.yaml", sanitize_stem(name)?))
            }
        };
        write_private_file(&path, yaml.as_bytes())?;
        eprintln!("profile -> {} (0600; contains no password)", path.display());
    }
    if let Some(qr) = &args.qr {
        if let Some(qrencode) = find_qrencode() {
            let output = PathBuf::from(qr);
            // Reserve an owner-only unique sibling first, then let qrencode
            // write it and atomically rename into place.  This prevents a
            // predictable `-o` path from following an attacker's symlink.
            let (tmp, reserved) = create_private_temp(&output)?;
            drop(reserved);
            let tmp_str = tmp.display().to_string();
            let result = process::Command::new(&qrencode)
                .args(["-o", tmp_str.as_str(), "-t", "PNG", uri.as_str()])
                .output();
            let output_result = match result {
                Ok(result) if result.status.success() => Ok(()),
                Ok(result) => Err(format!(
                    "qrencode failed: {}",
                    String::from_utf8_lossy(&result.stderr).trim()
                )),
                Err(error) => Err(format!("run {}: {error}", qrencode.display())),
            };
            if let Err(error) = output_result {
                let _ = fs::remove_file(&tmp);
                return Err(error);
            }
            use std::os::unix::fs::PermissionsExt;
            let _ = fs::set_permissions(&tmp, fs::Permissions::from_mode(0o600));
            if let Err(error) = fs::rename(&tmp, &output) {
                let _ = fs::remove_file(&tmp);
                return Err(format!("rename {}: {error}", output.display()));
            }
            let _ = fs::set_permissions(&output, fs::Permissions::from_mode(0o600));
            eprintln!(
                "QR -> {} (0600; verifier id only, no password)",
                output.display()
            );
        } else {
            eprintln!(
                "QR not written: `qrencode` not found; install it or set RUSTVPN_QRENCODE_BIN"
            );
            eprintln!("verifier URI: {uri}");
        }
    }
    eprintln!(
        "server: add the LONG verifier (first stdout line) to peers.yaml, then distribute the profile or QR"
    );
    Ok(())
}

fn main() {
    let args = parse_args();
    if args.warranty {
        println!("{WARRANTY}");
        return;
    }
    let password = read_passphrase(&args.key);
    if password.is_empty() {
        eprintln!("Empty passphrase submitted");
        process::exit(1);
    }
    let wants_onboarding =
        args.profile.is_some() || args.profile_out.is_some() || args.qr.is_some();
    if wants_onboarding && args.verifier.is_some() {
        eprintln!("-verifier validates an existing verifier and cannot be combined with profile/QR output");
        process::exit(2);
    }

    if let Some(raw) = args.verifier.as_ref() {
        let mut verifier = Verifier::from_string(raw).unwrap_or_else(|e| {
            eprintln!("Can not decode verifier: {e}");
            process::exit(1);
        });
        let public = verifier.public.unwrap_or_else(|| {
            eprintln!("Verifier does not contain public key");
            process::exit(1);
        });
        verifier.password_apply(&password).unwrap_or_else(|e| {
            eprintln!("Unable to apply passphrase: {e}");
            process::exit(1);
        });
        if verifier.public == Some(public) {
            println!("true");
        } else {
            println!("false");
            process::exit(1);
        }
        return;
    }

    let id = random_id(&args.egd);
    let mut verifier = Verifier::new(args.m, args.t, args.p, id);
    verifier.password_apply(&password).unwrap_or_else(|e| {
        eprintln!("Unable to apply passphrase: {e}");
        process::exit(1);
    });
    println!("{}", verifier.long_form().unwrap());
    println!("{}", verifier.short_form());
    let _ = io::stdout().flush();

    if wants_onboarding {
        if let Err(error) = emit_onboarding(&args, &verifier) {
            eprintln!("onboarding: {error}");
            process::exit(1);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn base_args() -> Args {
        Args {
            key: None,
            verifier: None,
            m: DEFAULT_M,
            t: DEFAULT_T,
            p: DEFAULT_P,
            egd: None,
            warranty: false,
            profile: Some("office".into()),
            profile_out: None,
            qr: None,
            remote: Some("vpn.example.com:1194".into()),
            proto: "udp".into(),
            mtu: "1515".into(),
            iface: None,
            address: None,
            gateway: None,
            dns: Vec::new(),
            routes: Vec::new(),
            noise: false,
            encless: false,
            kill_switch: false,
            mss_clamp: false,
            keepalive: 0,
            rekey_time: 1800,
            rekey_jitter: 0,
        }
    }

    fn verifier() -> Verifier {
        let mut verifier = Verifier::new(1024, 4, 1, [7u8; ID_SIZE]);
        verifier.password_apply("secret").unwrap();
        verifier
    }

    #[test]
    fn profile_contains_no_password_and_uses_short_verifier() {
        let (yaml, uri) = onboarding_profile(&base_args(), &verifier()).unwrap();
        assert!(yaml.contains("mtu: 1515"));
        assert!(yaml.contains("mss_clamp: false"));
        assert!(yaml.contains("kill_switch: false"));
        assert!(yaml.contains("rekey_time: 1800"));
        let short = verifier().short_form();
        assert!(yaml.contains(&short));
        assert!(!yaml.contains("secret"));
        assert!(!yaml.to_ascii_lowercase().contains("password"));
        assert!(uri.starts_with("rustvpn://profile?"));
        assert!(uri.contains("mtu=1515"));
        // The URI is informational only, but carries the network fields.
        assert!(uri.contains("address=10.88.0.2%2F24"));
        assert!(uri.contains("routes=default"));
        assert!(!uri.contains("secret"));
        // The long form (public key) is for the server, not the client file.
        assert!(!yaml.contains("$") || yaml.matches("$argon2d$").count() == 1);
    }

    #[test]
    fn rejects_auto_and_zero_mtu() {
        let mut args = base_args();
        args.mtu = "auto".into();
        let error = onboarding_profile(&args, &verifier()).unwrap_err();
        assert!(error.contains("auto"), "{error}");
        args.mtu = "0".into();
        let error = onboarding_profile(&args, &verifier()).unwrap_err();
        assert!(error.contains("0 is invalid"), "{error}");

        let error = validate_profile_mtu("68", false).unwrap_err();
        assert!(error.contains("derives TAP IP MTU 53"), "{error}");
        assert!(validate_profile_mtu("83", false).is_ok());
        assert!(validate_profile_mtu("120", true).is_ok());
    }

    #[test]
    fn profile_emits_keepalive_and_rekey_settings() {
        let mut args = base_args();
        args.keepalive = 25;
        args.rekey_time = 1800;
        args.rekey_jitter = 30;
        let (yaml, _) = onboarding_profile(&args, &verifier()).unwrap();
        assert!(yaml.contains("keepalive: 25"));
        assert!(yaml.contains("rekey_time: 1800"));
        assert!(yaml.contains("rekey_jitter: 30"));

        args.keepalive = 10; // below the 25s padded-mode floor
        args.noise = true;
        assert!(onboarding_profile(&args, &verifier()).is_err());
        args.keepalive = 25;
        assert!(onboarding_profile(&args, &verifier()).is_ok());
    }

    #[test]
    fn encless_requires_tcp_and_kill_switch_requires_full_tunnel() {
        let mut args = base_args();
        args.encless = true;
        assert!(onboarding_profile(&args, &verifier()).is_err());
        args.proto = "tcp".into();
        assert!(onboarding_profile(&args, &verifier()).is_ok());

        let mut args = base_args();
        args.kill_switch = true;
        args.routes = vec!["10.0.0.0/8".into()];
        assert!(onboarding_profile(&args, &verifier()).is_err());
    }

    #[test]
    fn percent_encoding_is_query_safe() {
        assert_eq!(
            percent_encode("$argon2d$m=1,t=2&x=1"),
            "%24argon2d%24m%3D1%2Ct%3D2%26x%3D1"
        );
        assert_eq!(
            percent_encode("vpn.example.com:1194"),
            "vpn.example.com%3A1194"
        );
    }

    #[test]
    fn private_files_are_owner_only() {
        use std::os::unix::fs::PermissionsExt;
        let dir = std::env::temp_dir().join(format!("rustvpn-verifier-test-{}", process::id()));
        let path = dir.join("profile.yaml");
        write_private_file(&path, b"name: x\n").unwrap();
        assert_eq!(
            fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
        assert_eq!(
            fs::metadata(&dir).unwrap().permissions().mode() & 0o777,
            0o700
        );
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn sanitizes_profile_names() {
        assert_eq!(sanitize_stem("office lab").unwrap(), "office-lab");
        assert!(sanitize_stem("..").is_err());
    }

    #[test]
    fn bare_relative_profile_out_has_no_creation_parent() {
        assert_eq!(creation_parent(Path::new("office.yaml")), None);
        assert_eq!(
            creation_parent(Path::new("./office.yaml")),
            Some(Path::new("."))
        );
        assert_eq!(
            creation_parent(Path::new("/tmp/x/office.yaml")),
            Some(Path::new("/tmp/x"))
        );
        // The actual write must work for a bare relative name (in cwd).
        let dir = tempfile::tempdir().unwrap();
        let cwd = std::env::current_dir().unwrap();
        std::env::set_current_dir(dir.path()).unwrap();
        let result = write_private_file(Path::new("office.yaml"), b"name: x\n");
        let metadata = result.and_then(|_| {
            fs::metadata("office.yaml")
                .map_err(|error| format!("stat: {error}"))
                .map(|meta| {
                    use std::os::unix::fs::PermissionsExt;
                    meta.permissions().mode() & 0o777
                })
        });
        std::env::set_current_dir(cwd).unwrap();
        assert_eq!(metadata.unwrap(), 0o600);
    }

    #[test]
    fn profiles_dir_requires_home_and_prefers_xdg() {
        use std::ffi::OsString;
        assert!(profiles_dir_from(None, None).is_err());
        assert!(profiles_dir_from(None, Some(OsString::new())).is_err());
        assert_eq!(
            profiles_dir_from(Some(OsString::from("/xdg")), None).unwrap(),
            PathBuf::from("/xdg/rustvpn/profiles")
        );
        assert_eq!(
            profiles_dir_from(None, Some(OsString::from("/home/alice"))).unwrap(),
            PathBuf::from("/home/alice/.config/rustvpn/profiles")
        );
    }

    #[test]
    fn private_temp_is_unique_and_owner_only() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("qr.png");
        let (first, file) = create_private_temp(&target).unwrap();
        drop(file);
        let (second, second_file) = create_private_temp(&target).unwrap();
        drop(second_file);
        assert_ne!(first, second);
        assert_eq!(
            fs::metadata(&first).unwrap().permissions().mode() & 0o777,
            0o600
        );
        let _ = fs::remove_file(first);
        let _ = fs::remove_file(second);
    }
}
