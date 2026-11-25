//! Create or reset an admin account for `rustvpn-server -admin`.

use std::env;
use std::path::PathBuf;
use std::process;

use rustvpn_admin::auth;
use rustvpn_admin::store::Store;

struct Args {
    db: PathBuf,
    user: String,
    role: String,
    password_file: Option<PathBuf>,
    help: bool,
}

fn usage() -> ! {
    eprintln!(
        "Usage of rustvpn-admin-passwd:\n\
         \x20 -db PATH          admin database (default /var/lib/rustvpn/admin.db)\n\
         \x20 -user NAME        admin username (default admin)\n\
         \x20 -role ROLE        admin|viewer (default admin)\n\
         \x20 -password-file P  read the passphrase from a file (for automation)\n\
         \x20 -h                show this help"
    );
    process::exit(2);
}

fn parse_args() -> Args {
    let mut args = Args {
        db: PathBuf::from("/var/lib/rustvpn/admin.db"),
        user: "admin".into(),
        role: "admin".into(),
        password_file: None,
        help: false,
    };
    let mut it = env::args().skip(1);
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
            "db" => args.db = PathBuf::from(take("db")),
            "user" => args.user = take("user"),
            "role" => args.role = take("role"),
            "password-file" => args.password_file = Some(PathBuf::from(take("password-file"))),
            "h" | "help" => args.help = true,
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
    if args.help {
        usage();
    }
    if args.user.is_empty() || args.user.len() > 64 {
        eprintln!("invalid username");
        process::exit(1);
    }
    if args.role != "admin" && args.role != "viewer" {
        eprintln!("role must be admin or viewer");
        process::exit(1);
    }

    let password = match &args.password_file {
        Some(path) => std::fs::read_to_string(path)
            .unwrap_or_else(|e| {
                eprintln!("unable to read {}: {e}", path.display());
                process::exit(1);
            })
            .trim_end_matches('\n')
            .to_string(),
        None => {
            let password =
                rpassword::prompt_password("New admin passphrase: ").unwrap_or_else(|e| {
                    eprintln!("unable to read passphrase: {e}");
                    process::exit(1);
                });
            let confirm = rpassword::prompt_password("Repeat passphrase: ").unwrap_or_else(|e| {
                eprintln!("unable to read passphrase: {e}");
                process::exit(1);
            });
            if password != confirm {
                eprintln!("passphrases do not match");
                process::exit(1);
            }
            password
        }
    };
    if password.len() < 12 {
        eprintln!("passphrase must be at least 12 characters");
        process::exit(1);
    }

    let store = Store::open(&args.db).unwrap_or_else(|e| {
        eprintln!("{e}");
        process::exit(1);
    });
    let (salt, hash) =
        auth::hash_password(&password, auth::DEFAULT_M, auth::DEFAULT_T, auth::DEFAULT_P)
            .unwrap_or_else(|e| {
                eprintln!("{e}");
                process::exit(1);
            });
    store
        .upsert_admin(
            &args.user,
            &args.role,
            &salt,
            &hash,
            auth::DEFAULT_M,
            auth::DEFAULT_T,
            auth::DEFAULT_P,
        )
        .unwrap_or_else(|e| {
            eprintln!("{e}");
            process::exit(1);
        });
    println!(
        "admin user {} ({}) written to {}",
        args.user,
        args.role,
        args.db.display()
    );
}
