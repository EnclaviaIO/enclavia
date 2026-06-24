use std::sync::Arc;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::mpsc;
use tracing::{error, info};

use enclavia_egress::{
    inject_resolver_entries, run_supervisor, stack::run_stack, AllowlistConfig, Config,
    StaticAllowlistPolicy, UnboundClient, VsockTransport,
};

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "info".into()),
        )
        .with_ansi(false)
        .init();

    let config = Config::from_env();
    info!(
        tun_name = %config.tun_name,
        tun_local_ip = %config.tun_local_ip,
        prefix_len = config.tun_prefix_len,
        mtu = config.mtu,
        vsock_port = config.vsock_port,
        allowlist = %config.allowlist_path.display(),
        "Starting enclavia-egress",
    );

    if let Err(e) = run(config).await {
        error!("Fatal: {e}");
        std::process::exit(1);
    }
}

async fn run(config: Config) -> Result<(), Box<dyn std::error::Error>> {
    let mut tun_config = tun::Configuration::default();
    tun_config
        .tun_name(&config.tun_name)
        .address(config.tun_local_ip)
        .netmask(prefix_to_netmask(config.tun_prefix_len))
        .mtu(config.mtu as u16)
        .up();

    let dev = tun::create_as_async(&tun_config)?;
    let (tun_reader, tun_writer) = tokio::io::split(dev);

    // Probe the host CID at runtime (CID 3 on real Nitro, CID 2 under QEMU)
    // so one EIF boots in both. See enclavia_vsock::host_cid.
    let cid = enclavia_vsock::host_cid().await;
    info!(vsock_cid = cid, "resolved egress host vsock CID");
    let transport = Arc::new(VsockTransport {
        cid,
        port: config.vsock_port,
    });

    // Load the allowlist. Missing or empty file -> deny-all, which is
    // intentional: the epic acceptance criterion is that an unconfigured
    // egress daemon has no outbound network.
    let mut allowlist = match AllowlistConfig::load_or_empty(&config.allowlist_path) {
        Ok(a) => a,
        Err(e) => return Err(Box::<dyn std::error::Error>::from(format!("allowlist load failed: {e}"))),
    };
    info!(
        entries = allowlist.entries.len(),
        resolvers = allowlist.resolvers.len(),
        hostnames = allowlist.hostnames.len(),
        "Loaded egress allowlist",
    );

    // Auto-inject `resolvers[i]:53/tcp` into the IP allowlist so the
    // in-enclave unbound's own outbound forwarder traffic is permitted
    // through this daemon. Operators do not need to spell these out in
    // egress.json. Done before policy construction so the resolver
    // entries become part of the immutable config snapshot.
    let injected = inject_resolver_entries(&mut allowlist);
    if injected.is_empty() {
        info!(
            "No resolvers configured: unbound will be unable to reach upstream. \
             Hostname entries will always deny.",
        );
    } else {
        for r in &injected {
            info!(resolver = %r, "Auto-injected resolver into IP allowlist (TCP/53)");
        }
    }

    let resolver = Arc::new(UnboundClient::loopback());
    let policy = Arc::new(StaticAllowlistPolicy::new(allowlist, resolver));

    let (flows_tx, flows_rx) = mpsc::channel(64);

    let stack_task = tokio::spawn(run_stack(
        AsyncReadAdapter(tun_reader),
        AsyncWriteAdapter(tun_writer),
        config.mtu,
        config.tun_local_ip,
        config.tun_prefix_len,
        flows_tx,
    ));

    let supervisor_task = tokio::spawn(run_supervisor(flows_rx, transport, policy));

    tokio::select! {
        r = stack_task => {
            match r {
                Ok(Ok(())) => info!("Stack task ended"),
                Ok(Err(e)) => error!("Stack task error: {e}"),
                Err(e) => error!("Stack task panicked: {e}"),
            }
        }
        _ = supervisor_task => info!("Supervisor ended"),
        _ = tokio::signal::ctrl_c() => info!("Signal received, shutting down"),
    }

    Ok(())
}

fn prefix_to_netmask(prefix_len: u8) -> std::net::Ipv4Addr {
    let mask: u32 = if prefix_len == 0 {
        0
    } else {
        u32::MAX.checked_shl(32 - prefix_len as u32).unwrap_or(0)
    };
    std::net::Ipv4Addr::from(mask)
}

/// `tun::AsyncDevice`'s `ReadHalf` / `WriteHalf` are not `Unpin`-friendly
/// out of the box in some versions; wrap them in newtypes so the stack
/// task can hold them as `AsyncRead + Unpin`.
struct AsyncReadAdapter<T>(T);
struct AsyncWriteAdapter<T>(T);

impl<T: AsyncReadExt + Unpin + Send> tokio::io::AsyncRead for AsyncReadAdapter<T> {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.0).poll_read(cx, buf)
    }
}

impl<T: AsyncWriteExt + Unpin + Send> tokio::io::AsyncWrite for AsyncWriteAdapter<T> {
    fn poll_write(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        std::pin::Pin::new(&mut self.0).poll_write(cx, buf)
    }
    fn poll_flush(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.0).poll_flush(cx)
    }
    fn poll_shutdown(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.0).poll_shutdown(cx)
    }
}
