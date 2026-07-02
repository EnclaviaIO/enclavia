//! Thin clap dispatcher over the `enclavia_cli` library. Library calls
//! return typed values; this binary is the only place that prints to the
//! terminal.

use std::io::{IsTerminal, Read, Write};

use clap::{Parser, Subcommand, ValueEnum};

use enclavia_cli::api::{ApiClient, EnclaveSummary};
use enclavia_cli::commands::{
    auth, enclave as enclave_cmds, key as key_cmds, push, reproduce, secrets, upgrade,
};
use enclavia_cli::error::CliError;

/// Local clap-friendly mirror of the lib's `InstanceTypeArg`. We can't
/// derive `ValueEnum` on the lib type without making the lib clap-aware
/// (the only consumer that actually wants clap is this binary), so we
/// keep a tiny wrapper here.
#[derive(Clone, Copy, ValueEnum)]
enum InstanceTypeArg {
    Small,
    Medium,
    Large,
}

impl From<InstanceTypeArg> for enclavia_cli::InstanceTypeArg {
    fn from(v: InstanceTypeArg) -> Self {
        match v {
            InstanceTypeArg::Small => Self::Small,
            InstanceTypeArg::Medium => Self::Medium,
            InstanceTypeArg::Large => Self::Large,
        }
    }
}

#[derive(Parser)]
#[command(name = "enclavia", about = "Enclavia CLI — manage your enclaves")]
struct Cli {
    /// Emit machine-readable JSON on stdout instead of human-readable text.
    /// On success a single JSON value (object or array) is printed and the
    /// process exits 0; on failure a single `{"error": ..., "kind": ...}`
    /// object is printed and the process exits non-zero. Progress lines,
    /// prompts (the OAuth login URL), and diagnostics go to stderr, so
    /// stdout is always exactly one parseable JSON value. Global: works on
    /// every subcommand and in either position (`enclavia --json enclave
    /// list` or `enclavia enclave list --json`).
    #[arg(long, global = true)]
    json: bool,
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Authenticate with Enclavia
    Auth {
        #[command(subcommand)]
        cmd: AuthCmd,
    },
    /// Manage enclaves
    Enclave {
        #[command(subcommand)]
        cmd: EnclaveCmd,
    },
    /// Push a local Docker image into the registry repo for one of your
    /// enclaves. Each enclave owns its own repo (`<your-handle>/<uuid>`),
    /// so the push is scoped by enclave id rather than a free-form name.
    Push {
        /// Local image reference (the source for `docker tag`), e.g.
        /// `myapp:dev` or `localhost/myapp:dev`.
        local_image: String,
        /// Target enclave id. Accepts a unique prefix as long as it
        /// resolves to exactly one of your enclaves.
        enclave_id: String,
    },
    /// Rebuild an enclave's EIF locally and verify the resulting PCRs
    /// match the ones the backend recorded. Pulls the image by its
    /// pinned digest so a later push to the same tag can't drift the
    /// build out from under you. Owners can reproduce any of their
    /// enclaves; non-owners can reproduce only `public` enclaves
    /// (registry-enforced).
    ///
    /// Pass `--upgrade <upgrade-id>` to reproduce a SUPERSEDED or pending
    /// version instead of the current one: the staged upgrade's recorded
    /// digest, PCRs, and source revs drive the rebuild, so every version
    /// in the public upgrade chain stays deterministically reproducible,
    /// not just the one running now.
    Reproduce {
        /// Target enclave id. Accepts a unique prefix as long as it
        /// resolves to exactly one of your enclaves.
        enclave_id: String,
        /// Reproduce this staged upgrade (from `upgrade list`) rather than
        /// the enclave's current version. The enclave's version-invariant
        /// build parameters (port, storage, control key, egress policy)
        /// are still read from the enclave row.
        #[arg(long, value_name = "UPGRADE_ID")]
        upgrade: Option<String>,
    },
    /// Manage per-enclave environment-variable secrets. Values are
    /// encrypted at rest with the backend's master key and injected
    /// into the workload's `process.env` at boot. Changes don't take
    /// effect until the next `enclavia enclave restart <id>`.
    Secret {
        #[command(subcommand)]
        cmd: SecretCmd,
    },
    /// Inspect an enclave's public upgrade chain (#47). The chain is
    /// the append-only, attested log of every boot / upgrade /
    /// revocation the enclave has recorded. The CLI re-validates each
    /// link locally with the same rules the backend ingest applies,
    /// so the "verified" badge in the output reflects this client's
    /// own check, not a server claim.
    Upgrade {
        #[command(subcommand)]
        cmd: UpgradeCmd,
    },
    /// Manage local control keys for self-hosted custody (#48). A
    /// self-hosted enclave's upgrade confirmations and revocations are
    /// signed by a key YOU hold (today: a YubiKey PIV slot); the
    /// backend never sees the private half. Keys are recorded in
    /// `~/.config/enclavia/keys/index.json` and referenced by name at
    /// create time (`enclave create --control-key <name>`).
    Key {
        #[command(subcommand)]
        cmd: KeyCmd,
    },
}

#[derive(Subcommand)]
enum KeyCmd {
    /// Generate a new ECDSA P-256 control key. With --yubikey the key
    /// is generated ON-DEVICE in a PIV slot and is never extractable;
    /// signing later requires the device (PIN + touch). A
    /// passphrase-protected keyfile backend will follow; --yubikey is
    /// required for now.
    Generate {
        /// Generate on a YubiKey (PIV, ECDSA/P256). Required for now.
        #[arg(long)]
        yubikey: bool,
        /// Name the key is stored under in the local index.
        #[arg(long, default_value = "default")]
        name: String,
        /// PIV slot to generate into (9a, 9c, 9d, 9e). 9c is the
        /// Digital Signature slot. Any existing key in the slot is
        /// REPLACED.
        #[arg(long, default_value = "9c")]
        slot: String,
        /// When the device requires a physical touch: on every
        /// signature (always), cached for 15s (cached), or never.
        #[arg(long, value_enum, default_value = "always")]
        touch_policy: TouchPolicyArg,
        /// When the device requires the PIN: once per session (once),
        /// before every signature (always), or never.
        #[arg(long, value_enum, default_value = "once")]
        pin_policy: PinPolicyArg,
        /// YubiKey serial number, to disambiguate when several devices
        /// are connected.
        #[arg(long)]
        serial: Option<u32>,
    },
    /// List the keys in the local index (name, backend, device, public
    /// key fingerprint).
    List,
}

/// Clap mirror of the YubiKey touch policy (the lib takes plain strings
/// so it stays clap-free, like `InstanceTypeArg`).
#[derive(Clone, Copy, ValueEnum)]
enum TouchPolicyArg {
    Always,
    Cached,
    Never,
}

impl TouchPolicyArg {
    fn as_str(self) -> &'static str {
        match self {
            TouchPolicyArg::Always => "always",
            TouchPolicyArg::Cached => "cached",
            TouchPolicyArg::Never => "never",
        }
    }
}

/// Clap mirror of the YubiKey PIN policy.
#[derive(Clone, Copy, ValueEnum)]
enum PinPolicyArg {
    Once,
    Always,
    Never,
}

impl PinPolicyArg {
    fn as_str(self) -> &'static str {
        match self {
            PinPolicyArg::Once => "once",
            PinPolicyArg::Always => "always",
            PinPolicyArg::Never => "never",
        }
    }
}

#[derive(Subcommand)]
enum AuthCmd {
    /// Authorize this device by approving from the web UI.
    ///
    /// The CLI prints a URL; open it in a browser where you're already
    /// signed in to Enclavia, label the session, and click Approve.
    Login,
}

#[derive(Subcommand)]
enum EnclaveCmd {
    /// Create a new enclave. Each enclave owns its own private registry
    /// repo at `<your-handle>/<enclave-uuid>`; push to it with
    /// `enclavia push <local-image> <enclave-id-prefix>` to start the
    /// build.
    Create {
        /// Instance type (small, medium, large)
        #[arg(long, default_value = "small")]
        instance_type: InstanceTypeArg,
        /// Port the container listens on inside the enclave. The proxy
        /// forwards plaintext HTTP to localhost:<port>.
        #[arg(long)]
        container_port: Option<u16>,
        /// Persistent encrypted storage size in bytes. Minimum 134217728
        /// (128 MiB); typical 268435456 (256 MiB). Omit or set to 0 to
        /// provision the enclave without storage.
        #[arg(long)]
        storage_size_bytes: Option<u64>,
        /// Optional freeform display name (max 64 chars). Shown in the
        /// dashboard header and `enclavia enclave list`. Empty / omitted
        /// gets an auto-generated `<adjective>-<animal>-<NNN>` name.
        #[arg(long)]
        name: Option<String>,
        /// Registry visibility for anonymous pulls: `private` (default)
        /// or `public`. Public lets anyone pull the enclave's image
        /// without auth. Owner pulls/pushes are governed by ownership.
        #[arg(long)]
        visibility: Option<String>,
        /// Allow outbound traffic to `HOST:PORT[/PROTO]`. Repeatable.
        /// HOST is an IPv4 literal, an IPv4 CIDR (e.g. `10.0.0.0/8`),
        /// or a hostname. PROTO defaults to `tcp`. Without any of the
        /// egress flags the enclave denies all outbound traffic.
        /// Mutually exclusive with `--egress-config`.
        #[arg(long = "egress-allow", value_name = "HOST:PORT[/PROTO]")]
        egress_allow: Vec<String>,
        /// DNS resolver IPv4 address used by the in-enclave validating
        /// resolver to resolve hostname allowlist entries. Repeatable.
        /// Mutually exclusive with `--egress-config`.
        #[arg(long = "egress-resolver", value_name = "IPV4")]
        egress_resolver: Vec<String>,
        /// Path to a pre-written egress allowlist JSON document.
        /// Mutually exclusive with `--egress-allow` /
        /// `--egress-resolver`.
        #[arg(long = "egress-config", value_name = "PATH")]
        egress_config: Option<std::path::PathBuf>,
        /// Mark this enclave as upgradable (#47). The backend mints an
        /// ECDSA P-256 control keypair, bakes the public half into every
        /// EIF for this enclave, and accepts staged v2+ pushes against
        /// it. Without this flag the enclave is non-upgradable: it has
        /// a single genesis push, no control pubkey is baked in, and
        /// the in-enclave server refuses every signed control command.
        /// Immutable post-create.
        #[arg(long)]
        upgradable: bool,
        /// Launch as a PRODUCTION enclave (real EC2 Nitro) instead of the
        /// default debug enclave (local QEMU). The deployment's launcher
        /// must support production and the account must be entitled (a paid
        /// plan), or the backend rejects the create. Immutable post-create.
        #[arg(long)]
        production: bool,
        /// Self-hosted control-key custody (#48): register the named
        /// local key (see `enclavia key generate/list`) as this
        /// enclave's control key. The backend then cannot confirm or
        /// revoke upgrades on its own; `enclavia upgrade confirm/revoke`
        /// sign with your key. Implies --upgradable. Immutable
        /// post-create; plain --upgradable stays managed custody.
        #[arg(long, value_name = "KEY_NAME")]
        control_key: Option<String>,
    },
    /// List your enclaves
    List {
        /// Include enclaves that were destroyed more than 30 minutes ago
        /// (archived). The default list view hides them (#67).
        #[arg(long, alias = "archived")]
        include_archived: bool,
    },
    /// Get enclave status and details
    Status {
        /// Enclave ID
        id: String,
    },
    /// Stop a running enclave
    Stop {
        /// Enclave ID
        id: String,
    },
    /// Start a previously-stopped enclave against its on-disk EIF + storage
    Start {
        /// Enclave ID
        id: String,
    },
    /// Restart a running (or stopped) enclave: server-side stop + start.
    /// Re-reads the secrets table so any pending `secret set` /
    /// `secret delete` changes land in the EIF on the next boot
    /// (#169 / #175).
    Restart {
        /// Enclave ID
        id: String,
    },
    /// Destroy an enclave
    Destroy {
        /// Enclave ID
        id: String,
    },
}

#[derive(Subcommand)]
enum SecretCmd {
    /// Create or rotate one or more secrets. Pass `NAME=value` pairs
    /// (repeatable), or use --from-stdin / --from-file for a single
    /// named secret whose value should not appear on the shell
    /// command-line.
    Set {
        /// Target enclave id. Accepts a unique prefix as long as it
        /// resolves to exactly one of your enclaves.
        enclave_id: String,
        /// `NAME=value` pairs. Names must match `^[A-Z_][A-Z0-9_]*$`,
        /// not start with `__`, and not collide with a small set of
        /// runtime-injected names (PATH, HOME, ...).
        pairs: Vec<String>,
        /// Read a single secret value from stdin. Requires --name.
        /// Mutually exclusive with positional pairs and --from-file.
        #[arg(long = "from-stdin", conflicts_with = "from_file")]
        from_stdin: bool,
        /// Read a single secret value from the contents of the given
        /// file. Requires --name. Mutually exclusive with --from-stdin.
        #[arg(long = "from-file", value_name = "PATH")]
        from_file: Option<std::path::PathBuf>,
        /// Secret name when used with --from-stdin or --from-file.
        #[arg(long)]
        name: Option<String>,
    },
    /// List secrets for an enclave (names + timestamps + pending flag).
    /// Values are never returned by the backend, so they are never
    /// printed here either.
    List {
        /// Target enclave id.
        enclave_id: String,
    },
    /// Delete one or more secrets by name. Asks for confirmation per
    /// name unless --yes is passed.
    Delete {
        /// Target enclave id.
        enclave_id: String,
        /// Names to delete.
        names: Vec<String>,
        /// Skip the per-name confirmation prompt.
        #[arg(long = "yes", short = 'y')]
        yes: bool,
    },
}

#[derive(Subcommand)]
enum UpgradeCmd {
    /// Fetch and pretty-print an enclave's public upgrade chain. Walks
    /// every link, re-validates locally against the enclave's recorded
    /// PCRs / image digest / control public key, and prints a tree of
    /// boot, upgrades, and revocations.
    Chain {
        /// Target enclave id. Accepts a unique prefix.
        enclave_id: String,
    },

    /// List all staged upgrades for an enclave, newest first. Shows the
    /// upgrade id, status, image reference, digest (truncated), valid_from
    /// time if set, and creation time.
    List {
        /// Target enclave id. Accepts a unique prefix.
        enclave_id: String,
    },

    /// Confirm a staged upgrade and schedule its effective time.
    ///
    /// When neither --at nor --immediate is supplied the server defaults
    /// to now + 7 days. The enclave swaps automatically once valid_from
    /// passes; no further CLI action is needed.
    ///
    /// --at and --immediate are mutually exclusive.
    Confirm {
        /// Target enclave id. Accepts a unique prefix.
        enclave_id: String,
        /// Upgrade id to confirm (from `upgrade list`).
        upgrade_id: String,
        /// Schedule the upgrade for this specific RFC 3339 timestamp, e.g.
        /// `2026-07-01T12:00:00Z`. Mutually exclusive with --immediate.
        #[arg(long, value_name = "RFC3339", conflicts_with = "immediate")]
        at: Option<String>,
        /// Schedule the upgrade to take effect immediately (sets valid_from
        /// to the current UTC time). Mutually exclusive with --at.
        #[arg(long, conflicts_with = "at")]
        immediate: bool,
    },

    /// Revoke a confirmed upgrade before it fires. The running enclave
    /// keeps its current version and a Revocation chain link is recorded.
    Revoke {
        /// Target enclave id. Accepts a unique prefix.
        enclave_id: String,
        /// Upgrade id to revoke (from `upgrade list`).
        upgrade_id: String,
    },
}

#[tokio::main]
async fn main() {
    let cli = Cli::parse();
    let json = cli.json;

    let result: Result<(), CliError> = match cli.command {
        Command::Auth { cmd } => match cmd {
            AuthCmd::Login => run_login(json).await,
        },
        Command::Enclave { cmd } => run_enclave(cmd, json).await,
        Command::Push { local_image, enclave_id } => {
            push::push(&local_image, &enclave_id, json).await
        }
        Command::Reproduce { enclave_id, upgrade } => {
            run_reproduce(&enclave_id, upgrade.as_deref(), json).await
        }
        Command::Secret { cmd } => run_secret(cmd, json).await,
        Command::Upgrade { cmd } => run_upgrade(cmd, json).await,
        Command::Key { cmd } => run_key(cmd, json),
    };

    if let Err(e) = result {
        if json {
            // The error path must still leave a single parseable JSON value
            // on stdout so an agent can branch purely on the exit code.
            print_json(&e.to_json());
        } else {
            eprintln!("Error: {e}");
        }
        std::process::exit(1);
    }
}

/// Print a value as pretty JSON to stdout. The single point where a
/// success/error JSON value reaches stdout in `--json` mode.
fn print_json<T: serde::Serialize>(value: &T) {
    match serde_json::to_string_pretty(value) {
        Ok(s) => println!("{s}"),
        Err(e) => {
            // Serialising our own output types should never fail; if it
            // somehow does, still leave a parseable error object behind.
            let fallback = serde_json::json!({
                "error": format!("failed to serialize output: {e}"),
                "kind": "error",
            });
            println!(
                "{}",
                serde_json::to_string(&fallback).unwrap_or_else(|_| {
                    "{\"error\":\"failed to serialize output\",\"kind\":\"error\"}".to_string()
                })
            );
        }
    }
}

/// Emit `value` as a single JSON document when `json` is set, otherwise run
/// the human-readable `human` closure (today's exact terminal output, kept
/// byte-for-byte so the default UX never regresses).
fn emit<T: serde::Serialize>(json: bool, value: &T, human: impl FnOnce()) {
    if json {
        print_json(value);
    } else {
        human();
    }
}

/// A human-facing progress / diagnostic line. In `--json` mode it goes to
/// stderr so stdout stays a single JSON value; otherwise stdout, preserving
/// the pre-`--json` behaviour exactly.
fn note(json: bool, msg: impl std::fmt::Display) {
    if json {
        eprintln!("{msg}");
    } else {
        println!("{msg}");
    }
}

/// Best-effort: does the enclave need a restart for pending secret changes
/// to land? Mirrors `print_pending_hint`: a `stopped` enclave picks the new
/// snapshot up on its next start (no restart), anything else (including a
/// status we couldn't fetch) needs one.
async fn restart_required(client: &ApiClient, enclave_id: &str) -> bool {
    let stopped = client
        .get_enclave(enclave_id)
        .await
        .ok()
        .and_then(|v| v["status"].as_str().map(|s| s == "stopped"))
        .unwrap_or(false);
    !stopped
}

async fn run_login(json: bool) -> Result<(), CliError> {
    let pending = auth::start_login().await?;
    // The URL + prompts are interactive progress: stderr under `--json`,
    // stdout otherwise (unchanged human flow).
    note(json, "");
    note(json, "Open this URL in your browser to authorize this device:");
    note(json, "");
    note(json, format!("  {}", pending.approval_url));
    note(json, "");
    note(json, "Waiting for approval...");

    // Best-effort browser launch — never fatal; the URL is already on the
    // screen if this fails.
    let _ = open::that(&pending.approval_url);

    pending.wait_for_token().await?;

    if json {
        // Surface the caller's handle (their registry namespace) so an agent
        // can confirm who it's acting as. Best-effort: a failure to fetch it
        // shouldn't fail an otherwise-successful login.
        let handle = match ApiClient::new() {
            Ok(c) => c.get_registry().await.ok().map(|r| r.namespace),
            Err(_) => None,
        };
        print_json(&serde_json::json!({
            "status": "logged_in",
            "handle": handle,
            "backend_url": enclavia_cli::config::backend_url(),
        }));
    } else {
        println!("Authorized. Credentials saved.");
    }
    Ok(())
}

async fn run_enclave(cmd: EnclaveCmd, json: bool) -> Result<(), CliError> {
    match cmd {
        EnclaveCmd::Create {
            instance_type,
            container_port,
            storage_size_bytes,
            name,
            visibility,
            egress_allow,
            egress_resolver,
            egress_config,
            upgradable,
            production,
            control_key,
        } => {
            // Validate the egress allowlist BEFORE constructing the API
            // client. The validator is purely local (parses --egress-allow
            // / --egress-config, runs the same checks the daemon would
            // run at boot). A logged-out user passing a bad allowlist
            // should see the actual local error (e.g. "UDP egress is not
            // supported yet"), not "not logged in" from ApiClient::new().
            let egress_inputs = enclave_cmds::EgressInputs {
                allows: egress_allow,
                resolvers: egress_resolver,
                config_path: egress_config,
            };
            let egress_allowlist = enclave_cmds::build_egress_allowlist(&egress_inputs)?;
            // Resolve the control key locally BEFORE creating anything:
            // a typo'd key name should error out, not create a managed
            // enclave. Registering the key implies --upgradable.
            let control_key_body = match control_key.as_deref() {
                Some(key_name) => {
                    if !upgradable {
                        note(json, format!(
                            "--control-key {key_name} implies --upgradable; creating an upgradable enclave."
                        ));
                    }
                    Some(key_cmds::control_key_body_for(key_name)?)
                }
                None => None,
            };
            let client = ApiClient::new()?;
            let res = enclave_cmds::create(
                &client,
                instance_type.into(),
                container_port,
                storage_size_bytes,
                name.as_deref(),
                visibility.as_deref(),
                egress_allowlist,
                upgradable,
                production,
                control_key_body,
            )
            .await?;
            // JSON: the created enclave object verbatim (id, status, and
            // every other backend field). The human "next step" hint stays
            // on the human path only.
            emit(json, &res.raw, || {
                println!("Enclave created:");
                println!("  ID:     {}", res.id);
                println!("  Status: {}", res.status);
                println!();
                println!("{}", res.next_step);
            });
            Ok(())
        }
        EnclaveCmd::List { include_archived } => {
            let client = ApiClient::new()?;
            let enclaves = enclave_cmds::list(&client, include_archived).await?;
            emit(json, &enclaves, || print_enclave_list(&enclaves, include_archived));
            Ok(())
        }
        EnclaveCmd::Status { id } => {
            let client = ApiClient::new()?;
            let e = enclave_cmds::status(&client, &id).await?;
            emit(json, &e, || print_enclave_status(&e));
            Ok(())
        }
        EnclaveCmd::Stop { id } => {
            let client = ApiClient::new()?;
            enclave_cmds::stop(&client, &id).await?;
            emit(
                json,
                &serde_json::json!({ "id": id.clone(), "status": "stopped" }),
                || println!("Enclave {id} stopped."),
            );
            Ok(())
        }
        EnclaveCmd::Start { id } => {
            let client = ApiClient::new()?;
            enclave_cmds::start(&client, &id).await?;
            emit(
                json,
                &serde_json::json!({ "id": id.clone(), "status": "started" }),
                || println!("Enclave {id} started."),
            );
            Ok(())
        }
        EnclaveCmd::Restart { id } => {
            let client = ApiClient::new()?;
            secrets::restart(&client, &id).await?;
            emit(
                json,
                &serde_json::json!({ "id": id.clone(), "status": "restart_requested" }),
                || println!("Enclave {id} restart requested."),
            );
            Ok(())
        }
        EnclaveCmd::Destroy { id } => {
            let client = ApiClient::new()?;
            enclave_cmds::destroy(&client, &id).await?;
            emit(
                json,
                &serde_json::json!({ "id": id.clone(), "status": "destroyed" }),
                || println!("Enclave {id} destroyed."),
            );
            Ok(())
        }
    }
}

async fn run_secret(cmd: SecretCmd, json: bool) -> Result<(), CliError> {
    match cmd {
        SecretCmd::Set {
            enclave_id,
            pairs,
            from_stdin,
            from_file,
            name,
        } => {
            let parsed_pairs = collect_set_pairs(pairs, from_stdin, from_file, name.as_deref())?;
            if parsed_pairs.is_empty() {
                return Err(CliError::Other(
                    "no secrets to set (pass NAME=value pairs, --from-stdin, or --from-file)".into(),
                ));
            }
            // Capture the names before `set` consumes the pairs; we never
            // echo the values back, not even in JSON.
            let names: Vec<String> = parsed_pairs.iter().map(|(n, _)| n.clone()).collect();
            let client = ApiClient::new()?;
            let n = secrets::set(&client, &enclave_id, parsed_pairs).await?;
            if json {
                let restart_required = restart_required(&client, &enclave_id).await;
                print_json(&serde_json::json!({
                    "enclave_id": enclave_id,
                    "set": names,
                    "updated": n,
                    "restart_required": restart_required,
                }));
            } else {
                print_pending_hint(&client, &enclave_id, n, "Run").await;
            }
            Ok(())
        }
        SecretCmd::List { enclave_id } => {
            let client = ApiClient::new()?;
            let rows = secrets::list(&client, &enclave_id).await?;
            // `SecretSummary` carries names + timestamps + the pending flag,
            // never values, so the JSON array is value-free by construction.
            emit(json, &rows, || print_secret_list(&rows));
            Ok(())
        }
        SecretCmd::Delete { enclave_id, names, yes } => {
            if names.is_empty() {
                return Err(CliError::Other(
                    "no secret names provided to delete".into(),
                ));
            }
            // Interactive per-name confirmation writes prose to stdout, which
            // would corrupt the single-JSON-value contract, so `--json`
            // requires the non-interactive `--yes`.
            if json && !yes {
                return Err(CliError::Other(
                    "refusing to prompt for confirmation in --json mode; pass --yes".into(),
                ));
            }
            // Per-name confirmation. The flag exists for the
            // non-interactive case (CI, scripts) where there's no TTY.
            let confirmed: Vec<String> = if yes {
                names
            } else {
                let mut keep = Vec::new();
                for n in names {
                    if confirm(&format!("Delete secret '{n}'?"))? {
                        keep.push(n);
                    } else {
                        println!("Skipped {n}.");
                    }
                }
                keep
            };
            if confirmed.is_empty() {
                emit(
                    json,
                    &serde_json::json!({
                        "enclave_id": enclave_id,
                        "deleted": Vec::<String>::new(),
                        "updated": 0,
                    }),
                    || println!("Nothing to do."),
                );
                return Ok(());
            }
            let client = ApiClient::new()?;
            let n = secrets::delete(&client, &enclave_id, &confirmed).await?;
            if json {
                let restart_required = restart_required(&client, &enclave_id).await;
                print_json(&serde_json::json!({
                    "enclave_id": enclave_id,
                    "deleted": confirmed,
                    "updated": n,
                    "restart_required": restart_required,
                }));
            } else {
                print_pending_hint(&client, &enclave_id, n, "Run").await;
            }
            Ok(())
        }
    }
}

/// Collect the `(name, value)` pairs from the three input shapes.
/// Returns an error if the user mixed positional pairs with the
/// single-value modes; clap's `conflicts_with` already blocks the
/// stdin/file combination.
fn collect_set_pairs(
    positional: Vec<String>,
    from_stdin: bool,
    from_file: Option<std::path::PathBuf>,
    name: Option<&str>,
) -> Result<Vec<(String, String)>, CliError> {
    let single_value_mode = from_stdin || from_file.is_some();
    if single_value_mode && !positional.is_empty() {
        return Err(CliError::Other(
            "positional NAME=value pairs are mutually exclusive with --from-stdin / --from-file".into(),
        ));
    }
    if single_value_mode {
        let n = name.ok_or_else(|| {
            CliError::Other("--from-stdin / --from-file requires --name NAME".into())
        })?;
        secrets::validate_name(n)?;
        let value = if from_stdin {
            let mut buf = String::new();
            std::io::stdin()
                .read_to_string(&mut buf)
                .map_err(|e| CliError::Other(format!("reading stdin: {e}")))?;
            // Trim a single trailing newline so `echo foo | enclavia
            // secret set --from-stdin --name FOO` lands as "foo" not
            // "foo\n". A user who genuinely wants the newline should
            // use --from-file with a hand-crafted payload.
            strip_one_trailing_newline(buf)
        } else {
            let path = from_file.as_ref().expect("from_file checked above");
            let bytes = std::fs::read(path).map_err(|e| {
                CliError::Other(format!("reading {}: {e}", path.display()))
            })?;
            String::from_utf8(bytes).map_err(|_| {
                CliError::Other(format!("{} is not valid UTF-8", path.display()))
            })?
        };
        return Ok(vec![(n.to_string(), value)]);
    }
    // Positional NAME=value pairs.
    let mut out = Vec::with_capacity(positional.len());
    for p in positional {
        out.push(secrets::parse_name_value(&p)?);
    }
    Ok(out)
}

fn strip_one_trailing_newline(mut s: String) -> String {
    if s.ends_with('\n') {
        s.pop();
        if s.ends_with('\r') {
            s.pop();
        }
    }
    s
}

fn confirm(prompt: &str) -> Result<bool, CliError> {
    // Non-interactive callers should be using --yes; bail loudly rather
    // than reading EOF and silently treating it as "no".
    if !std::io::stdin().is_terminal() {
        return Err(CliError::Other(format!(
            "{prompt} (no TTY available; pass --yes to skip confirmation)"
        )));
    }
    print!("{prompt} [y/N] ");
    std::io::stdout()
        .flush()
        .map_err(|e| CliError::Other(format!("flushing stdout: {e}")))?;
    let mut line = String::new();
    std::io::stdin()
        .read_line(&mut line)
        .map_err(|e| CliError::Other(format!("reading stdin: {e}")))?;
    let s = line.trim().to_ascii_lowercase();
    Ok(s == "y" || s == "yes")
}

/// If the enclave is not in the `stopped` state, hint at the restart
/// step. Best-effort: if the status fetch fails we just skip the
/// hint rather than failing the whole command (the change has
/// already been applied at this point).
async fn print_pending_hint(client: &ApiClient, enclave_id: &str, n: usize, lead_verb: &str) {
    if n == 0 {
        return;
    }
    let plural = if n == 1 { "" } else { "s" };
    let status = client.get_enclave(enclave_id).await.ok();
    let stopped = status
        .as_ref()
        .and_then(|v| v["status"].as_str())
        .map(|s| s == "stopped")
        .unwrap_or(false);
    if stopped {
        // Stopped enclaves pick the new snapshot up on the next start;
        // no restart needed.
        println!("{n} change{plural} applied. The new value{plural} will land on the next start.");
    } else {
        println!(
            "{n} change{plural} pending. {lead_verb} `enclavia enclave restart {enclave_id}` to apply."
        );
    }
}

fn print_secret_list(rows: &[secrets::SecretSummary]) {
    if rows.is_empty() {
        println!("No secrets defined for this enclave.");
        return;
    }
    println!("{:<32} {:<32} PENDING", "NAME", "LAST UPDATED");
    println!("{}", "-".repeat(80));
    for r in rows {
        let pending = if r.pending { "yes" } else { "no" };
        println!("{:<32} {:<32} {}", r.name, r.updated_at, pending);
    }
}

async fn run_reproduce(
    id_or_prefix: &str,
    upgrade_id: Option<&str>,
    json: bool,
) -> Result<(), CliError> {
    // Authenticated when possible (lets owners reproduce their own
    // private enclaves and resolve prefixes via the list endpoint),
    // anonymous fallback for users with no credentials reproducing a
    // public-visibility enclave by full UUID.
    let client = match ApiClient::new() {
        Ok(c) => c,
        Err(CliError::NotLoggedIn) => ApiClient::anonymous(),
        Err(e) => return Err(e),
    };
    let result = match upgrade_id {
        Some(uid) => reproduce::reproduce_upgrade(&client, id_or_prefix, uid).await?,
        None => reproduce::reproduce(&client, id_or_prefix).await?,
    };

    if json {
        // reproduce is a VERIFICATION command, so the PCR verdict maps onto the
        // exit code (like `diff` / `test`): exit 0 when the local build matches
        // the recorded PCRs, a distinct non-zero (2) when it diverges. The full
        // payload (including `reproducible` + `mismatches`) is printed to stdout
        // EITHER way, so a field-reading agent gets the detail while an
        // exit-code-only caller still fails closed. Operational errors are exit
        // 1 with an {"error"} object (handled in `main`), so 2 is unambiguously
        // "ran, but not reproducible". The human path below also exits non-zero
        // on divergence.
        let mut v = serde_json::to_value(&result)
            .map_err(|e| CliError::Other(format!("serialize reproduce result: {e}")))?;
        if let Some(uid) = upgrade_id {
            v["upgrade_id"] = serde_json::json!(uid);
        }
        let reproducible = result.is_reproducible();
        v["reproducible"] = serde_json::json!(reproducible);
        print_json(&v);
        if reproducible {
            return Ok(());
        }
        std::process::exit(2);
    }

    println!("Enclave:        {}", result.enclave_id);
    if let Some(uid) = upgrade_id {
        println!("Upgrade:        {uid}");
    }
    println!("Image digest:   {}", result.image_digest);
    if result.recorded_egress_allowlist.is_null() {
        println!("Egress policy:  none recorded (deny-all baked into EIF)");
    } else {
        // Pretty-print compactly: one entry per line is more useful
        // than the raw JSON dump for a quick sanity-check.
        let pretty = serde_json::to_string_pretty(&result.recorded_egress_allowlist)
            .unwrap_or_else(|_| result.recorded_egress_allowlist.to_string());
        println!("Egress policy:");
        for line in pretty.lines() {
            println!("  {line}");
        }
    }
    match (result.recorded_builder_rev.as_deref(), result.recorded_crates_rev.as_deref()) {
        (Some(b), Some(c)) => {
            println!("Recorded revs:  builder {b}");
            println!("                crates  {c}");
            println!(
                "  (the original build was pinned to these revs; if the local PCRs diverge,"
            );
            println!(
                "  re-run with a builder checked out to those revisions before reporting a failure.)"
            );
        }
        _ => {
            println!(
                "Recorded revs:  none (built by an older backend; can't pin local rebuild to source)"
            );
        }
    }
    println!();

    if result.is_reproducible() {
        println!("✓ Reproducible — local PCRs match the recorded build.");
        println!();
        println!("  PCR0: {}", result.actual.pcr0);
        println!("  PCR1: {}", result.actual.pcr1);
        println!("  PCR2: {}", result.actual.pcr2);
        Ok(())
    } else {
        println!("✗ NOT reproducible — {} PCR(s) diverged:", result.mismatches.len());
        println!();
        for m in &result.mismatches {
            println!("  {}", m.slot);
            println!("    expected: {}", m.expected);
            println!("    actual:   {}", m.actual);
        }
        Err(CliError::Other("local build does not match the recorded PCRs".into()))
    }
}

fn print_enclave_list(enclaves: &[EnclaveSummary], include_archived: bool) {
    if enclaves.is_empty() {
        if include_archived {
            println!("No enclaves found.");
        } else {
            println!("No enclaves found. Pass --include-archived to show destroyed enclaves.");
        }
        return;
    }

    println!(
        "{:<38} {:<24} {:<40} {:<12} {:<8} CREATED",
        "ID", "NAME", "IMAGE", "STATUS", "SIZE"
    );
    println!("{}", "-".repeat(140));
    for e in enclaves {
        let status_raw = e.status.as_deref().unwrap_or("-");
        let status =
            if e.archived { format!("{status_raw} (archived)") } else { status_raw.to_string() };
        println!(
            "{:<38} {:<24} {:<40} {:<12} {:<8} {}",
            e.id,
            e.name.as_deref().unwrap_or("-"),
            e.docker_image.as_deref().unwrap_or("-"),
            status,
            e.instance_type.as_deref().unwrap_or("-"),
            e.created_at.as_deref().unwrap_or("-"),
        );
    }
}

fn print_enclave_status(e: &serde_json::Value) {
    println!("Enclave details:");
    println!("  ID:           {}", e["id"].as_str().unwrap_or("-"));
    if let Some(name) = e["name"].as_str() {
        println!("  Name:         {name}");
    }
    let status = e["status"].as_str().unwrap_or("-");
    if let Some(detail) = e["status_detail"].as_str() {
        println!("  Status:       {status} ({detail})");
    } else {
        println!("  Status:       {status}");
    }
    if let Some(mode) = e["mode"].as_str() {
        println!("  Mode:         {mode}");
    }
    if let Some(custody) = e["control_key_mode"].as_str() {
        println!("  Control key:  {custody}");
    }
    println!("  Instance:     {}", e["instance_type"].as_str().unwrap_or("-"));
    println!("  Image:        {}", e["docker_image"].as_str().unwrap_or("-"));
    println!("  vSock CID:    {}", e["vsock_cid"]);
    if let Some(endpoint) = e["endpoint"].as_str() {
        println!("  Endpoint:     {endpoint}");
    }
    println!("  Created:      {}", e["created_at"].as_str().unwrap_or("-"));
    if let Some(err) = e["error_message"].as_str() {
        println!("  Error:        {err}");
    }
    if let Some(pcrs) = e["pcrs"].as_object() {
        println!("  PCRs:");
        for (k, v) in pcrs {
            println!("    {k}: {}", v.as_str().unwrap_or("-"));
        }
    }
}

async fn run_upgrade(cmd: UpgradeCmd, json: bool) -> Result<(), CliError> {
    match cmd {
        UpgradeCmd::Chain { enclave_id } => {
            let client = ApiClient::new()?;
            let summary = upgrade::chain(&client, &enclave_id).await?;
            emit(json, &summary, || print_chain(&summary));
            Ok(())
        }
        UpgradeCmd::List { enclave_id } => {
            let client = ApiClient::new()?;
            let rows = upgrade::list_upgrades(&client, &enclave_id).await?;
            emit(json, &rows, || print_upgrade_list(&rows));
            Ok(())
        }
        UpgradeCmd::Confirm { enclave_id, upgrade_id, at, immediate } => {
            let valid_from: Option<chrono::DateTime<chrono::Utc>> = if immediate {
                Some(chrono::Utc::now())
            } else if let Some(ts) = at {
                let parsed = chrono::DateTime::parse_from_rfc3339(&ts).map_err(|e| {
                    CliError::Other(format!("invalid RFC 3339 timestamp {ts:?}: {e}"))
                })?;
                Some(parsed.with_timezone(&chrono::Utc))
            } else {
                None
            };
            let client = ApiClient::new()?;
            let result =
                upgrade::confirm_upgrade(&client, &enclave_id, &upgrade_id, valid_from)
                    .await?;
            emit(json, &result, || print_upgrade_confirm(&result));
            Ok(())
        }
        UpgradeCmd::Revoke { enclave_id, upgrade_id } => {
            let client = ApiClient::new()?;
            let result =
                upgrade::revoke_upgrade(&client, &enclave_id, &upgrade_id).await?;
            emit(json, &result, || print_upgrade_revoke(&result));
            Ok(())
        }
    }
}

/// Pretty-print a [`upgrade::ChainSummary`].
///
/// One section per link with kind, sequence, timestamp, decoded
/// payload fields, attestation/signature sizes, and a verdict line
/// summarising the local re-validation. Trailing "Chain is valid"
/// line iff every link verified.
fn print_chain(summary: &upgrade::ChainSummary) {
    println!();
    let n = summary.links.len();
    let label = if n == 1 { "link" } else { "links" };
    println!("Chain for enclave {} ({n} {label})", summary.enclave_id);
    if !summary.upgradable {
        println!("  upgradable:   no (only the genesis boot is valid)");
    }
    if summary.debug_mode {
        println!(
            "  mode:         debug (attestations checked structurally only, NOT rooted in AWS Nitro hardware)"
        );
    }
    println!();

    let mut verified = 0usize;
    for link in &summary.links {
        print_chain_link(link);
        if link.validation.is_ok() {
            verified += 1;
        }
        println!();
    }

    if verified == n && summary.tip_matches_row {
        println!("Chain is valid. {n} {label}, all verified locally; tip matches the enclave row.");
    } else if verified == n {
        println!(
            "Chain links all verified, but the chain tip does NOT match the enclave row \
             (stale chain or row drift); treat as unverified."
        );
    } else {
        let rejected = n - verified;
        println!(
            "Chain has rejected links: {verified}/{n} verified, {rejected} failed local validation."
        );
        if !summary.tip_matches_row {
            println!("Chain tip does not match the enclave row state.");
        }
    }
}

fn print_chain_link(link: &upgrade::VerifiedLink) {
    let seq = link
        .sequence
        .map(|s| format!("#{s}"))
        .unwrap_or_else(|| "#?".to_string());
    let kind = match link.kind {
        enclavia_protocol::chain::ChainLinkKind::Boot => "boot",
        enclavia_protocol::chain::ChainLinkKind::Upgrade => "upgrade",
        enclavia_protocol::chain::ChainLinkKind::Revocation => "revocation",
    };
    let when = link
        .created_at
        .map(|t| t.format("%Y-%m-%d %H:%M:%S UTC").to_string())
        .unwrap_or_else(|| "-".to_string());
    let badge = match &link.validation {
        Ok(_) => "[verified]",
        Err(_) => "[REJECTED]",
    };
    println!("  {seq:<4} {kind:<10} {when}  {badge}");

    match &link.payload {
        Some(upgrade::DecodedPayload::Boot(p)) => {
            println!("      image:       {}", p.image_digest);
            println!("      booted_at:   {}", p.booted_at.format("%Y-%m-%d %H:%M:%S UTC"));
            println!("      PCR0:        {}", p.pcrs.pcr0);
            println!("      PCR1:        {}", p.pcrs.pcr1);
            println!("      PCR2:        {}", p.pcrs.pcr2);
        }
        Some(upgrade::DecodedPayload::Upgrade(p)) => {
            println!("      target:      {}", p.image_digest);
            println!("      valid_from:  {}", p.valid_from.format("%Y-%m-%d %H:%M:%S UTC"));
            println!("      issued_at:   {}", p.issued_at.format("%Y-%m-%d %H:%M:%S UTC"));
            println!("      to.PCR0:     {}", p.to_pcrs.pcr0);
            println!("      to.PCR1:     {}", p.to_pcrs.pcr1);
            println!("      to.PCR2:     {}", p.to_pcrs.pcr2);
        }
        Some(upgrade::DecodedPayload::Revocation(p)) => {
            println!("      revokes:     {}", p.revokes);
            println!("      issued_at:   {}", p.issued_at.format("%Y-%m-%d %H:%M:%S UTC"));
        }
        None => {
            println!("      payload:     <undecodable>");
        }
    }

    println!("      attestation: {} bytes", link.attestation_bytes);
    if let Some(n) = link.signature_bytes {
        println!("      signature:   {n} bytes");
    }

    if let Err(msg) = &link.validation {
        println!("      validation error: {msg}");
    }
}

/// Print a table of staged upgrades. One row per upgrade, newest first.
fn print_upgrade_list(rows: &[upgrade::StagedUpgradeJson]) {
    if rows.is_empty() {
        println!("No staged upgrades for this enclave.");
        return;
    }
    // Header
    println!(
        "{:<38} {:<12} {:<44} {:<16} {:<26} CREATED",
        "UPGRADE ID", "STATUS", "IMAGE", "DIGEST", "VALID FROM",
    );
    println!("{}", "-".repeat(160));
    for r in rows {
        // Keep the image ref short: if it contains a slash, show only
        // the part after the last slash (the `repo:tag` portion). Full
        // ref on truncation would be confusing, so we shorten.
        let image_short = r
            .docker_image
            .rsplit('/')
            .next()
            .unwrap_or(&r.docker_image);
        // Digest: show the 12-char hex after "sha256:" for brevity.
        let digest_short = r
            .image_digest
            .as_deref()
            .and_then(|d| d.strip_prefix("sha256:"))
            .map(|h| format!("sha256:{}", &h[..h.len().min(12)]))
            .unwrap_or_else(|| "-".to_string());
        let valid_from = r
            .valid_from
            .map(|t| t.format("%Y-%m-%d %H:%M UTC").to_string())
            .unwrap_or_else(|| "-".to_string());
        let created = r.created_at.format("%Y-%m-%d %H:%M UTC").to_string();
        let status = format!("{:?}", r.status).to_lowercase();
        println!(
            "{:<38} {:<12} {:<44} {:<16} {:<26} {}",
            r.id, status, image_short, digest_short, valid_from, created,
        );
    }
}

/// Print the result of a successful `upgrade confirm` call.
fn print_upgrade_confirm(r: &upgrade::StagedUpgradeJson) {
    let status = format!("{:?}", r.status).to_lowercase();
    println!("Upgrade {} confirmed.", r.id);
    println!("  Status:     {status}");
    if let Some(vf) = r.valid_from {
        println!(
            "  Valid from: {}",
            vf.format("%Y-%m-%d %H:%M:%S UTC")
        );
        println!(
            "  The enclave will swap to the new version automatically at that time."
        );
    }
}

fn run_key(cmd: KeyCmd, json: bool) -> Result<(), CliError> {
    match cmd {
        KeyCmd::Generate { yubikey, name, slot, touch_policy, pin_policy, serial } => {
            if !yubikey {
                return Err(CliError::Other(
                    "only the YubiKey backend is available today; pass --yubikey (a \
                     passphrase-keyfile backend is planned)"
                        .into(),
                ));
            }
            let args = key_cmds::YubiKeyGenerateArgs {
                name,
                slot,
                touch_policy: touch_policy.as_str().into(),
                pin_policy: pin_policy.as_str().into(),
                serial,
            };
            let generated = key_cmds::generate_yubikey(&args)?;
            emit(json, &generated, || print_key_generated(&generated));
            Ok(())
        }
        KeyCmd::List => {
            let rows = key_cmds::list()?;
            emit(json, &rows, || print_key_list(&rows));
            Ok(())
        }
    }
}

fn print_key_generated(k: &key_cmds::GeneratedKey) {
    println!("Generated control key '{}' on YubiKey {} (slot {}).", k.name, k.serial, k.slot);
    println!("  Public key:  {}", k.public_key);
    println!("  Fingerprint: {}", k.fingerprint);
    println!();
    println!("The private key was generated on-device and cannot be extracted.");
    println!("Use it when creating an enclave:");
    println!("  enclavia enclave create --control-key {} ...", k.name);
}

fn print_key_list(rows: &[key_cmds::KeyListEntry]) {
    if rows.is_empty() {
        println!(
            "No control keys yet. Generate one with `enclavia key generate --yubikey --name <name>`."
        );
        return;
    }
    println!("{:<24} {:<10} {:<12} {:<6} FINGERPRINT", "NAME", "TYPE", "SERIAL", "SLOT");
    println!("{}", "-".repeat(80));
    for r in rows {
        println!(
            "{:<24} {:<10} {:<12} {:<6} {}",
            r.name,
            r.backend,
            r.serial.map(|s| s.to_string()).unwrap_or_else(|| "-".to_string()),
            r.slot.as_deref().unwrap_or("-"),
            r.fingerprint,
        );
    }
}

/// Print the result of a successful `upgrade revoke` call.
fn print_upgrade_revoke(r: &upgrade::StagedUpgradeJson) {
    let status = format!("{:?}", r.status).to_lowercase();
    println!("Upgrade {} revoked.", r.id);
    println!("  Status:     {status}");
    println!("  The upgrade has been cancelled; the enclave keeps running the current version.");
}
