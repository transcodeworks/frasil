//! Frasil's always-on peer service.
//!
//! Specified by `docs/spec/peers.md`, and by `docs/spec/transport.md`,
//! section 3.15 (The server binding) and section 3.16 (The iroh binding).
//!
//! `frasil-relay` reads its settings from `FRASIL_*` variables (see
//! `frasil_relay::Config::from_env`) and serves until SIGTERM or Ctrl-C.
//! `frasil-relay check` reads the settings and exits; `frasil-relay
//! ticket` prints a library ticket signed by the operator's own issuer, and
//! the same ticket as a link; `frasil-relay --help` lists the commands and
//! the extensions `FRASIL_EXTENSIONS` turns on.

use frasil_libraries::{LibraryId, Purpose};
use frasil_relay::libraries::TicketRequest;
use std::process::ExitCode;

const USAGE: &str = "\
usage: frasil-relay [serve | check | ticket [options]]

serve   run the peer (the default)
check   read the FRASIL_* settings, print them without credentials, and exit
ticket  print a library ticket signed by the operator's own issuer, and the
        same ticket as a link to FRASIL_ORIGIN, for one person or team to
        attach one space; it reads the issuer's key from the data directory
        (issuer.key) or derives it from FRASIL_CLUSTER_KEY, and needs no
        running peer

ticket options:
  --library ID     the library to name; the default library otherwise
  --purpose P      create (the default), import, move, or deposit (a deposit
                   grant, with deposit-tokens on)
  --tokens N       a deposit grant's tokens, 1 to 256
  --lifetime S     seconds until the ticket expires, 1 to 86400 (the default)
  --origin URL     the origin the link names, in place of FRASIL_ORIGIN

Settings come from FRASIL_* environment variables (docs/self-hosting.md).
FRASIL_EXTENSIONS names the extensions on, separated by spaces or commas,
or `none`; `libraries` and `deposit-tokens` by default. Every extension
is built in:

  ephemeral       ext-ephemeral.md: each space's ephemeral channel
                  (FRASIL_EPHEMERAL_FRAMES_PER_SECOND)
  file-versions   ext-file-versions.md: superseded objects kept
                  (FRASIL_MAX_FILE_VERSIONS, FRASIL_FILE_VERSION_RETENTION)
  invite-links    ext-invite-links.md: invite drops, mailbox kind 4
  libraries       ext-libraries.md: libraries, tickets and ledgers; a space
                  is hosted once a ticket attached it, under the operator's
                  own issuer unless FRASIL_LIBRARY_ISSUERS names others
  deposit-tokens  ext-deposit-tokens.md: anonymous deposit tokens; needs
                  libraries
";

/// Reads `ticket`'s options.
fn ticket_request(args: &[String]) -> Result<(TicketRequest, Option<String>), String> {
    let mut request = TicketRequest::default();
    let mut origin = None;
    let mut args = args.iter();
    while let Some(name) = args.next() {
        let value = args.next().ok_or_else(|| format!("{name} needs a value"))?;
        match name.as_str() {
            "--library" => {
                request.library = Some(
                    LibraryId::new(value).map_err(|_| format!("{value} is not a library ID"))?,
                );
            }
            "--purpose" => {
                request.purpose = match value.as_str() {
                    "deposit" => Purpose::Deposit,
                    other => Purpose::from_name(other)
                        .filter(|purpose| purpose.attaches())
                        .ok_or_else(|| format!("{other} is not create, import, move or deposit"))?,
                };
            }
            "--tokens" => {
                request.tokens = Some(
                    value
                        .parse()
                        .map_err(|_| format!("{value} is not a count of tokens"))?,
                );
            }
            "--lifetime" => {
                request.lifetime = value
                    .parse()
                    .map_err(|_| format!("{value} is not a count of seconds"))?;
            }
            "--origin" => origin = Some(value.clone()),
            other => return Err(format!("{other} is not an option of ticket")),
        }
    }
    Ok((request, origin))
}

/// `frasil-relay ticket`: the ticket on standard output as two lines, its
/// text and its link, and what it is on standard error.
fn ticket(config: &frasil_relay::Config, args: &[String]) -> Result<(), String> {
    let (request, origin) = ticket_request(args)?;
    let settings = &config.settings;
    if !settings.extensions.libraries {
        return Err("the libraries extension is off: the peer takes no ticket".into());
    }
    if !settings.libraries.issuers.is_empty() {
        return Err(
            "FRASIL_LIBRARY_ISSUERS names the issuers this peer trusts: tickets come from them, \
             not from the operator's own issuer"
                .into(),
        );
    }
    if request.purpose == Purpose::Deposit && !settings.extensions.deposit_tokens {
        return Err("a deposit grant needs the deposit-tokens extension on".into());
    }
    let issuer = frasil_relay::operator_issuer(config).map_err(|error| error.0)?;
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|_| "the wall clock is before 1970".to_owned())?
        .as_secs();
    let origin = origin.or_else(|| settings.origin.clone());
    let issued =
        frasil_relay::libraries::operator::issue(&issuer, &request, origin.as_deref(), now)
            .map_err(|error| error.0)?;
    eprintln!(
        "library {}, purpose {}, expires at {} (seconds since 1970)",
        issued.library, issued.purpose, issued.not_after
    );
    println!("ticket: {}", issued.text());
    match &issued.link {
        Some(link) => println!("link: {link}"),
        None => eprintln!("no link: set FRASIL_ORIGIN, or pass --origin"),
    }
    Ok(())
}

#[tokio::main]
async fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let command = args.first().cloned();
    if matches!(command.as_deref(), Some("help" | "--help" | "-h")) {
        print!("{USAGE}");
        return ExitCode::SUCCESS;
    }
    let config = match frasil_relay::Config::from_env() {
        Ok(config) => config,
        Err(error) => {
            eprintln!("frasil-relay: {error}");
            return ExitCode::from(2);
        }
    };
    match command.as_deref() {
        None | Some("serve") => match frasil_relay::run(config).await {
            Ok(()) => ExitCode::SUCCESS,
            Err(error) => {
                eprintln!("frasil-relay: {error}");
                ExitCode::FAILURE
            }
        },
        Some("check") => {
            println!("extensions on: {}", config.settings.extensions);
            println!("{config:#?}");
            ExitCode::SUCCESS
        }
        Some("ticket") => match ticket(&config, &args[1..]) {
            Ok(()) => ExitCode::SUCCESS,
            Err(error) => {
                eprintln!("frasil-relay ticket: {error}");
                ExitCode::from(2)
            }
        },
        Some(_) => {
            eprint!("{USAGE}");
            ExitCode::from(2)
        }
    }
}
