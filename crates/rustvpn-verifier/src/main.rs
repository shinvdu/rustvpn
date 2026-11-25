//! GoVPN 5.7-compatible verifier generator/validator.

use std::env;
use std::fs;
use std::io::{self, Write};
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
         \x20   Print warranty information"
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

    if let Some(raw) = args.verifier {
        let mut verifier = Verifier::from_string(&raw).unwrap_or_else(|e| {
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
}
