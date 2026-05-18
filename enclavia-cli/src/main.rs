//! Thin clap dispatcher over the `enclavia_cli` library. Library calls
//! return typed values; this binary is the only place that prints to the
//! terminal.

use clap::{Parser, Subcommand, ValueEnum};

use enclavia_cli::api::{ApiClient, EnclaveSummary};
use enclavia_cli::commands::{auth, enclave as enclave_cmds, push, reproduce};
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
    Reproduce {
        /// Target enclave id. Accepts a unique prefix as long as it
        /// resolves to exactly one of your enclaves.
        enclave_id: String,
    },
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
    /// Destroy an enclave
    Destroy {
        /// Enclave ID
        id: String,
    },
}

#[tokio::main]
async fn main() {
    let cli = Cli::parse();

    let result: Result<(), CliError> = match cli.command {
        Command::Auth { cmd } => match cmd {
            AuthCmd::Login => run_login().await,
        },
        Command::Enclave { cmd } => run_enclave(cmd).await,
        Command::Push { local_image, enclave_id } => push::push(&local_image, &enclave_id).await,
        Command::Reproduce { enclave_id } => run_reproduce(&enclave_id).await,
    };

    if let Err(e) = result {
        eprintln!("Error: {e}");
        std::process::exit(1);
    }
}

async fn run_login() -> Result<(), CliError> {
    let pending = auth::start_login().await?;
    println!();
    println!("Open this URL in your browser to authorize this device:");
    println!();
    println!("  {}", pending.approval_url);
    println!();
    println!("Waiting for approval...");

    // Best-effort browser launch — never fatal; the URL is already on the
    // screen if this fails.
    let _ = open::that(&pending.approval_url);

    pending.wait_for_token().await?;
    println!("Authorized. Credentials saved.");
    Ok(())
}

async fn run_enclave(cmd: EnclaveCmd) -> Result<(), CliError> {
    let client = ApiClient::new()?;
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
        } => {
            let egress_inputs = enclave_cmds::EgressInputs {
                allows: egress_allow,
                resolvers: egress_resolver,
                config_path: egress_config,
            };
            let egress_allowlist = enclave_cmds::build_egress_allowlist(&egress_inputs)?;
            let res = enclave_cmds::create(
                &client,
                instance_type.into(),
                container_port,
                storage_size_bytes,
                name.as_deref(),
                visibility.as_deref(),
                egress_allowlist,
            )
            .await?;
            println!("Enclave created:");
            println!("  ID:     {}", res.id);
            println!("  Status: {}", res.status);
            println!();
            println!("{}", res.next_step);
            Ok(())
        }
        EnclaveCmd::List { include_archived } => {
            let enclaves = enclave_cmds::list(&client, include_archived).await?;
            print_enclave_list(&enclaves, include_archived);
            Ok(())
        }
        EnclaveCmd::Status { id } => {
            let e = enclave_cmds::status(&client, &id).await?;
            print_enclave_status(&e);
            Ok(())
        }
        EnclaveCmd::Stop { id } => {
            enclave_cmds::stop(&client, &id).await?;
            println!("Enclave {id} stopped.");
            Ok(())
        }
        EnclaveCmd::Start { id } => {
            enclave_cmds::start(&client, &id).await?;
            println!("Enclave {id} started.");
            Ok(())
        }
        EnclaveCmd::Destroy { id } => {
            enclave_cmds::destroy(&client, &id).await?;
            println!("Enclave {id} destroyed.");
            Ok(())
        }
    }
}

async fn run_reproduce(id_or_prefix: &str) -> Result<(), CliError> {
    // Authenticated when possible (lets owners reproduce their own
    // private enclaves and resolve prefixes via the list endpoint),
    // anonymous fallback for users with no credentials reproducing a
    // public-visibility enclave by full UUID.
    let client = match ApiClient::new() {
        Ok(c) => c,
        Err(CliError::NotLoggedIn) => ApiClient::anonymous(),
        Err(e) => return Err(e),
    };
    let result = reproduce::reproduce(&client, id_or_prefix).await?;

    println!("Enclave:        {}", result.enclave_id);
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
        "{:<38} {:<24} {:<40} {:<12} {:<8} {}",
        "ID", "NAME", "IMAGE", "STATUS", "SIZE", "CREATED"
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
