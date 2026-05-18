//! Userspace TCP/IP stack: TUN device on one side, smoltcp on the other.
//!
//! Single owning task drives smoltcp. New flows are surfaced over an
//! [`mpsc::Sender<AcceptedFlow>`] (see [`crate::AcceptedFlow`]); each
//! flow exposes itself as a [`FlowStream`] (a duplex byte channel) so
//! the rest of the crate can splice it to `egress-host` over the
//! transport without knowing anything about smoltcp.

use std::collections::HashMap;
use std::io;
use std::net::SocketAddrV4;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Instant;

use smoltcp::iface::{Config as IfaceConfig, Interface, SocketHandle, SocketSet};
use smoltcp::phy::{Device, DeviceCapabilities, Medium, RxToken, TxToken};
use smoltcp::socket::tcp;
use smoltcp::time::Instant as SmolInstant;
use smoltcp::wire::{HardwareAddress, IpAddress, IpCidr, IpListenEndpoint, Ipv4Packet, TcpPacket};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::sync::{mpsc, Mutex};
use tracing::{debug, warn};

use crate::AcceptedFlow;

/// Per-flow byte buffers between the smoltcp socket and the forwarder.
///
/// `to_socket` carries bytes the forwarder read from `egress-host` and
/// wants smoltcp to send to the workload. `from_socket` carries bytes
/// smoltcp read from the workload and the forwarder needs to ship to
/// `egress-host`.
///
/// 64 KiB matches one full smoltcp TCP socket buffer; anything more is
/// wasted because smoltcp won't accept past its own window.
const FLOW_CHANNEL_BYTES: usize = 64 * 1024;

/// Read/write buffer sizes inside smoltcp's TCP socket. Larger means
/// fewer poll wakeups and a bigger receive window advertised to the
/// peer; smaller saves heap. 64 KiB is the sweet spot for HTTP-class
/// payloads.
const SMOLTCP_RX_BUFFER: usize = 64 * 1024;
const SMOLTCP_TX_BUFFER: usize = 64 * 1024;

/// Build a smoltcp [`Interface`] on top of `device`, configured with
/// `local_ip/prefix_len`, a default route through `local_ip`, and
/// `any_ip` enabled so the workload can target arbitrary destinations.
pub fn build_interface<D: Device>(
    device: &mut D,
    local_ip: std::net::Ipv4Addr,
    prefix_len: u8,
) -> Interface {
    let mut iface = Interface::new(
        IfaceConfig::new(HardwareAddress::Ip),
        device,
        SmolInstant::from(Instant::now()),
    );
    iface.update_ip_addrs(|addrs| {
        addrs
            .push(IpCidr::new(IpAddress::Ipv4(local_ip), prefix_len))
            .unwrap();
    });
    // `any_ip` lets smoltcp accept packets whose destination is not one
    // of our addresses. The workload picks the destination IP, smoltcp
    // listens on that exact IP for the matching socket, so we need to
    // bypass the "is this address ours?" check on inbound. The route
    // gateway must still resolve to one of our addresses, hence the
    // default route via `local_ip`.
    iface.set_any_ip(true);
    iface
        .routes_mut()
        .add_default_ipv4_route(local_ip)
        .expect("smoltcp route table has space for the default route");
    iface
}

/// A bidirectional byte stream that bridges one smoltcp TCP socket.
///
/// Reads pull bytes the workload sent (smoltcp -> us). Writes push
/// bytes back to the workload (us -> smoltcp). The smoltcp side is
/// driven by the central stack task; this struct only owns the two
/// channel ends.
pub struct FlowStream {
    /// Bytes the workload sent us, ready for the forwarder to read and
    /// ship to `egress-host`.
    from_socket: mpsc::Receiver<Vec<u8>>,
    /// Holds leftover bytes from `from_socket` that did not fit into
    /// the last `poll_read`'s `ReadBuf`.
    read_carry: Option<(Vec<u8>, usize)>,
    /// Bytes we received from `egress-host` and want smoltcp to send.
    to_socket: mpsc::Sender<Vec<u8>>,
}

impl FlowStream {
    fn new(
        from_socket: mpsc::Receiver<Vec<u8>>,
        to_socket: mpsc::Sender<Vec<u8>>,
    ) -> Self {
        Self {
            from_socket,
            read_carry: None,
            to_socket,
        }
    }
}

impl AsyncRead for FlowStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if let Some((bytes, mut offset)) = self.read_carry.take() {
            let take = std::cmp::min(buf.remaining(), bytes.len() - offset);
            buf.put_slice(&bytes[offset..offset + take]);
            offset += take;
            if offset < bytes.len() {
                self.read_carry = Some((bytes, offset));
            }
            return Poll::Ready(Ok(()));
        }
        match self.from_socket.poll_recv(cx) {
            Poll::Ready(Some(bytes)) => {
                let take = std::cmp::min(buf.remaining(), bytes.len());
                buf.put_slice(&bytes[..take]);
                if take < bytes.len() {
                    self.read_carry = Some((bytes, take));
                }
                Poll::Ready(Ok(()))
            }
            Poll::Ready(None) => Poll::Ready(Ok(())),
            Poll::Pending => Poll::Pending,
        }
    }
}

impl AsyncWrite for FlowStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        data: &[u8],
    ) -> Poll<io::Result<usize>> {
        // tokio::sync::mpsc has no async-context poll_send; emulate via
        // permit reservation. `try_send` would lose backpressure.
        match self.to_socket.try_reserve() {
            Ok(permit) => {
                permit.send(data.to_vec());
                Poll::Ready(Ok(data.len()))
            }
            Err(mpsc::error::TrySendError::Full(_)) => {
                // Wake when capacity is freed. mpsc doesn't expose a
                // direct waker, but the central task drains this
                // channel whenever the socket has window; nudge by
                // yielding so we re-poll soon.
                cx.waker().wake_by_ref();
                Poll::Pending
            }
            Err(mpsc::error::TrySendError::Closed(_)) => {
                Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::BrokenPipe,
                    "flow closed",
                )))
            }
        }
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        // Dropping the sender end on shutdown lets the stack task notice
        // and close the smoltcp socket.
        Poll::Ready(Ok(()))
    }
}

/// One half of the per-flow plumbing held by the stack task: the
/// smoltcp socket handle plus the channel endpoints opposite the
/// [`FlowStream`].
struct StackFlow {
    #[allow(dead_code)]
    handle: SocketHandle,
    /// Send bytes received from the workload over to the forwarder.
    to_forwarder: mpsc::Sender<Vec<u8>>,
    /// Pull bytes the forwarder received from `egress-host`, for
    /// smoltcp to send to the workload.
    from_forwarder: mpsc::Receiver<Vec<u8>>,
    /// Carry-over bytes that did not fit into smoltcp's send buffer on
    /// the previous poll; pushed first next time.
    pending_send: Option<Vec<u8>>,
    /// Set once the flow has gone through smoltcp's `Established`
    /// state. We use it to detect a clean close on the workload side.
    saw_established: bool,
    dst: SocketAddrV4,
}

/// In-memory smoltcp `phy::Device` that buffers IPv4 packets between
/// the TUN reader/writer task and smoltcp's `poll`.
///
/// smoltcp drives I/O synchronously inside `poll`, so we cannot await
/// TUN reads/writes from inside its callback. Instead an outer task
/// shuttles packets between TUN and these two queues, and waits on a
/// notify whenever there's nothing to do.
pub struct ChannelDevice {
    /// IPv4 packets that arrived from the TUN, waiting for smoltcp to
    /// consume them via `receive()`.
    inbound: std::collections::VecDeque<Vec<u8>>,
    /// IPv4 packets smoltcp emitted via `transmit()`, waiting for the
    /// outer task to ship to TUN.
    outbound: std::collections::VecDeque<Vec<u8>>,
    mtu: usize,
}

impl ChannelDevice {
    pub fn new(mtu: usize) -> Self {
        Self {
            inbound: Default::default(),
            outbound: Default::default(),
            mtu,
        }
    }

    pub fn push_inbound(&mut self, packet: Vec<u8>) {
        self.inbound.push_back(packet);
    }

    pub fn pop_outbound(&mut self) -> Option<Vec<u8>> {
        self.outbound.pop_front()
    }

    pub fn inbound_is_empty(&self) -> bool {
        self.inbound.is_empty()
    }
}

impl Device for ChannelDevice {
    type RxToken<'a> = ChannelRxToken;
    type TxToken<'a> = ChannelTxToken<'a>;

    fn receive(&mut self, _ts: SmolInstant) -> Option<(Self::RxToken<'_>, Self::TxToken<'_>)> {
        let packet = self.inbound.pop_front()?;
        Some((
            ChannelRxToken { packet },
            ChannelTxToken {
                outbound: &mut self.outbound,
            },
        ))
    }

    fn transmit(&mut self, _ts: SmolInstant) -> Option<Self::TxToken<'_>> {
        Some(ChannelTxToken {
            outbound: &mut self.outbound,
        })
    }

    fn capabilities(&self) -> DeviceCapabilities {
        let mut caps = DeviceCapabilities::default();
        caps.medium = Medium::Ip;
        caps.max_transmission_unit = self.mtu;
        caps
    }
}

pub struct ChannelRxToken {
    packet: Vec<u8>,
}

impl RxToken for ChannelRxToken {
    fn consume<R, F>(self, f: F) -> R
    where
        F: FnOnce(&[u8]) -> R,
    {
        f(&self.packet)
    }
}

pub struct ChannelTxToken<'a> {
    outbound: &'a mut std::collections::VecDeque<Vec<u8>>,
}

impl<'a> TxToken for ChannelTxToken<'a> {
    fn consume<R, F>(self, len: usize, f: F) -> R
    where
        F: FnOnce(&mut [u8]) -> R,
    {
        let mut buf = vec![0u8; len];
        let r = f(&mut buf);
        self.outbound.push_back(buf);
        r
    }
}

/// One iteration of the smoltcp loop. Returns `true` if any progress
/// was made (caller can decide whether to immediately re-poll or wait
/// for an external event).
fn step(
    iface: &mut Interface,
    device: &mut ChannelDevice,
    sockets: &mut SocketSet<'static>,
    flows: &mut HashMap<SocketHandle, StackFlow>,
    closed: &mut Vec<SocketHandle>,
) -> bool {
    let poll_result = iface.poll(SmolInstant::from(Instant::now()), device, sockets);
    let progressed = !matches!(poll_result, smoltcp::iface::PollResult::None);

    closed.clear();
    for (handle, flow) in flows.iter_mut() {
        let socket = sockets.get_mut::<tcp::Socket>(*handle);

        if socket.state() == tcp::State::Established {
            flow.saw_established = true;
        }

        // Drain bytes the workload sent us into the forwarder channel.
        if socket.can_recv() {
            let mut chunk = vec![0u8; 16 * 1024];
            if let Ok(n) = socket.recv_slice(&mut chunk) {
                if n > 0 {
                    chunk.truncate(n);
                    if let Err(e) = flow.to_forwarder.try_send(chunk) {
                        match e {
                            mpsc::error::TrySendError::Full(_) => {
                                // Forwarder is slow; smoltcp's window will
                                // pace the peer until we drain.
                            }
                            mpsc::error::TrySendError::Closed(_) => {
                                socket.close();
                            }
                        }
                    }
                }
            }
        }

        // Push bytes the forwarder received from egress-host into smoltcp.
        // Carry-over first, then drain the channel non-blockingly.
        if let Some(pending) = flow.pending_send.take() {
            if socket.can_send() {
                match socket.send_slice(&pending) {
                    Ok(n) if n < pending.len() => {
                        flow.pending_send = Some(pending[n..].to_vec());
                    }
                    Ok(_) => {}
                    Err(_) => {
                        flow.pending_send = Some(pending);
                    }
                }
            } else {
                flow.pending_send = Some(pending);
            }
        }
        while flow.pending_send.is_none() && socket.can_send() {
            match flow.from_forwarder.try_recv() {
                Ok(data) => match socket.send_slice(&data) {
                    Ok(n) if n < data.len() => {
                        flow.pending_send = Some(data[n..].to_vec());
                    }
                    Ok(_) => {}
                    Err(_) => {
                        flow.pending_send = Some(data);
                    }
                },
                Err(mpsc::error::TryRecvError::Empty) => break,
                Err(mpsc::error::TryRecvError::Disconnected) => {
                    socket.close();
                    break;
                }
            }
        }

        // smoltcp closed (FIN ack'd both ways) -> tear the flow down.
        if flow.saw_established
            && matches!(
                socket.state(),
                tcp::State::Closed | tcp::State::TimeWait | tcp::State::CloseWait
            )
        {
            socket.close();
            closed.push(*handle);
        }
    }

    for handle in closed.drain(..) {
        sockets.remove(handle);
        flows.remove(&handle);
    }

    progressed
}

/// Run the stack: own the smoltcp + device + TUN read/write loops.
///
/// On every IPv4 TCP SYN that arrives at the TUN, a new smoltcp socket
/// is allocated, the SYN is injected into the device, and an
/// [`AcceptedFlow`] is sent over `accepted_tx` for the supervisor to
/// pick up.
///
/// `tun_io` is parameterised so tests can drive the stack without a
/// real TUN device (see the integration test for the synthetic
/// loopback).
pub async fn run_stack<R, W>(
    mut tun_rx: R,
    mut tun_tx: W,
    mtu: usize,
    local_ip: std::net::Ipv4Addr,
    prefix_len: u8,
    accepted_tx: mpsc::Sender<AcceptedFlow>,
) -> io::Result<()>
where
    R: AsyncRead + Unpin + Send + 'static,
    W: AsyncWrite + Unpin + Send + 'static,
{
    let device = Arc::new(Mutex::new(ChannelDevice::new(mtu)));
    let iface = {
        let mut dev = device.lock().await;
        build_interface(&mut *dev, local_ip, prefix_len)
    };
    let sockets = SocketSet::new(Vec::<smoltcp::iface::SocketStorage<'static>>::new());
    let flows: HashMap<SocketHandle, StackFlow> = HashMap::new();

    // Wrap shared state in a Mutex so the TUN reader task and the poll
    // task can both touch it. They alternate via the `tick` notifier so
    // contention is minimal.
    let shared = Arc::new(Mutex::new(StackState {
        iface,
        sockets,
        flows,
        closed_scratch: Vec::new(),
        accepted_tx,
    }));
    let tick = Arc::new(tokio::sync::Notify::new());

    let reader_device = device.clone();
    let reader_shared = shared.clone();
    let reader_tick = tick.clone();
    let reader = tokio::spawn(async move {
        let mut buf = vec![0u8; mtu + 64];
        loop {
            let n = match tokio::io::AsyncReadExt::read(&mut tun_rx, &mut buf).await {
                Ok(0) => return Ok::<(), io::Error>(()),
                Ok(n) => n,
                Err(e) => return Err(e),
            };
            let packet = buf[..n].to_vec();
            handle_inbound(&reader_shared, &reader_device, packet).await;
            reader_tick.notify_one();
        }
    });

    let writer_device = device.clone();
    let writer_tick = tick.clone();
    let writer_shared = shared.clone();
    let writer = tokio::spawn(async move {
        loop {
            let progressed = {
                let mut state = writer_shared.lock().await;
                let mut dev = writer_device.lock().await;
                let StackState {
                    iface,
                    sockets,
                    flows,
                    closed_scratch,
                    ..
                } = &mut *state;
                step(iface, &mut dev, sockets, flows, closed_scratch)
            };
            // Drain anything smoltcp produced.
            loop {
                let pkt = {
                    let mut dev = writer_device.lock().await;
                    dev.pop_outbound()
                };
                match pkt {
                    Some(pkt) => {
                        tokio::io::AsyncWriteExt::write_all(&mut tun_tx, &pkt).await?;
                    }
                    None => break,
                }
            }
            if !progressed {
                // No work; wait for the reader to push something or
                // bail out after a short poll-ahead so flow channels'
                // pending writes get noticed.
                tokio::select! {
                    _ = writer_tick.notified() => {}
                    _ = tokio::time::sleep(std::time::Duration::from_millis(10)) => {}
                }
            } else {
                tokio::task::yield_now().await;
            }
        }
    });

    tokio::select! {
        r = reader => match r {
            Ok(Ok(())) => Ok(()),
            Ok(Err(e)) => Err(e),
            Err(e) => Err(io::Error::other(e)),
        },
        w = writer => match w {
            Ok(Ok(())) => Ok(()),
            Ok(Err(e)) => Err(e),
            Err(e) => Err(io::Error::other(e)),
        },
    }
}

struct StackState {
    iface: Interface,
    sockets: SocketSet<'static>,
    flows: HashMap<SocketHandle, StackFlow>,
    closed_scratch: Vec<SocketHandle>,
    accepted_tx: mpsc::Sender<AcceptedFlow>,
}

async fn handle_inbound(
    shared: &Arc<Mutex<StackState>>,
    device: &Arc<Mutex<ChannelDevice>>,
    packet: Vec<u8>,
) {
    // Drop non-IPv4. The smoltcp stack we built only carries IPv4
    // anyway; the explicit check keeps the SYN demux below cheap.
    let is_ipv4 = matches!(packet.first(), Some(b) if (*b >> 4) == 4);
    if !is_ipv4 {
        debug!("Dropping non-IPv4 inbound packet");
        return;
    }

    // Inspect the packet for a TCP SYN that needs a new socket.
    if let Some((dst, src)) = parse_new_tcp_syn(&packet) {
        let mut state = shared.lock().await;
        if !flow_already_exists(&state, dst, src) {
            match allocate_flow(&mut state, dst) {
                Ok(flow_stream) => {
                    let _ = state
                        .accepted_tx
                        .send(AcceptedFlow {
                            dst,
                            stream: flow_stream,
                        })
                        .await;
                }
                Err(e) => warn!(%dst, "Failed to allocate flow socket: {e}"),
            }
        }
    }

    // Inject the packet regardless: the TCP three-way handshake's SYN
    // (and any retransmits) is what kicks smoltcp into accepting on
    // the newly-listening socket.
    let mut dev = device.lock().await;
    dev.push_inbound(packet);
}

fn parse_new_tcp_syn(packet: &[u8]) -> Option<(SocketAddrV4, SocketAddrV4)> {
    let ipv4 = Ipv4Packet::new_checked(packet).ok()?;
    if ipv4.next_header() != smoltcp::wire::IpProtocol::Tcp {
        return None;
    }
    let tcp = TcpPacket::new_checked(ipv4.payload()).ok()?;
    if !tcp.syn() || tcp.ack() {
        return None;
    }
    let dst = SocketAddrV4::new(ipv4.dst_addr(), tcp.dst_port());
    let src = SocketAddrV4::new(ipv4.src_addr(), tcp.src_port());
    Some((dst, src))
}

fn flow_already_exists(state: &StackState, dst: SocketAddrV4, _src: SocketAddrV4) -> bool {
    state.flows.values().any(|f| f.dst == dst)
}

fn allocate_flow(state: &mut StackState, dst: SocketAddrV4) -> io::Result<FlowStream> {
    let rx = vec![0u8; SMOLTCP_RX_BUFFER];
    let tx = vec![0u8; SMOLTCP_TX_BUFFER];
    let rx_buf = tcp::SocketBuffer::new(rx);
    let tx_buf = tcp::SocketBuffer::new(tx);
    let mut socket = tcp::Socket::new(rx_buf, tx_buf);
    socket
        .listen(IpListenEndpoint {
            addr: Some(IpAddress::Ipv4(*dst.ip())),
            port: dst.port(),
        })
        .map_err(|e| {
            io::Error::other(format!("smoltcp listen failed: {e:?}"))
        })?;
    let handle = state.sockets.add(socket);

    let (to_forwarder, from_socket) = mpsc::channel::<Vec<u8>>(FLOW_CHANNEL_BYTES / 1024);
    let (to_socket, from_forwarder) = mpsc::channel::<Vec<u8>>(FLOW_CHANNEL_BYTES / 1024);

    let stack_flow = StackFlow {
        handle,
        to_forwarder,
        from_forwarder,
        pending_send: None,
        saw_established: false,
        dst,
    };
    state.flows.insert(handle, stack_flow);

    Ok(FlowStream::new(from_socket, to_socket))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;
    use smoltcp::wire::{Ipv4Address, Ipv4Packet as Ipv4PacketMut, TcpPacket as TcpPacketMut};

    fn syn_packet(src: SocketAddrV4, dst: SocketAddrV4) -> Vec<u8> {
        let ip_hdr_len = 20usize;
        let tcp_hdr_len = 20usize;
        let total = ip_hdr_len + tcp_hdr_len;
        let mut buf = vec![0u8; total];

        {
            let mut ip = Ipv4PacketMut::new_unchecked(&mut buf);
            ip.set_version(4);
            ip.set_header_len(ip_hdr_len as u8);
            ip.set_total_len(total as u16);
            ip.set_dont_frag(true);
            ip.set_next_header(smoltcp::wire::IpProtocol::Tcp);
            ip.set_hop_limit(64);
            ip.set_src_addr(*src.ip());
            ip.set_dst_addr(*dst.ip());
            ip.fill_checksum();
        }
        let src_addr: Ipv4Address = *src.ip();
        let dst_addr: Ipv4Address = *dst.ip();
        let (_ip_buf, tcp_buf) = buf.split_at_mut(ip_hdr_len);
        let mut tcp = TcpPacketMut::new_unchecked(tcp_buf);
        tcp.set_src_port(src.port());
        tcp.set_dst_port(dst.port());
        tcp.set_seq_number(smoltcp::wire::TcpSeqNumber(0));
        tcp.set_ack_number(smoltcp::wire::TcpSeqNumber(0));
        tcp.set_header_len(tcp_hdr_len as u8);
        tcp.set_syn(true);
        tcp.set_window_len(8192);
        tcp.fill_checksum(&src_addr.into(), &dst_addr.into());
        buf
    }

    #[test]
    fn parse_new_tcp_syn_extracts_addrs() {
        let src = SocketAddrV4::new(Ipv4Addr::new(10, 99, 0, 2), 49152);
        let dst = SocketAddrV4::new(Ipv4Addr::new(1, 2, 3, 4), 443);
        let pkt = syn_packet(src, dst);
        let (parsed_dst, parsed_src) = parse_new_tcp_syn(&pkt).expect("should parse");
        assert_eq!(parsed_dst, dst);
        assert_eq!(parsed_src, src);
    }

    #[test]
    fn parse_new_tcp_syn_ignores_non_syn_packet() {
        let src = SocketAddrV4::new(Ipv4Addr::new(10, 99, 0, 2), 49152);
        let dst = SocketAddrV4::new(Ipv4Addr::new(1, 2, 3, 4), 443);
        let mut pkt = syn_packet(src, dst);
        // Clear the SYN flag.
        let ip_hdr_len = 20;
        let mut tcp = TcpPacketMut::new_unchecked(&mut pkt[ip_hdr_len..]);
        tcp.set_syn(false);
        let src_addr: Ipv4Address = *src.ip();
        let dst_addr: Ipv4Address = *dst.ip();
        tcp.fill_checksum(&src_addr.into(), &dst_addr.into());
        assert!(parse_new_tcp_syn(&pkt).is_none());
    }
}

