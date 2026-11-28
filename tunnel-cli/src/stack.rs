//! Userspace TCP/IP stack ([smoltcp](https://crates.io/crates/smoltcp))
//! bridged onto the tunnel's packet queues.
//!
//! The tunnel data plane carries raw IPv4 packets; the SOCKS5 front-end
//! needs TCP streams. This module runs a full userspace TCP stack on a
//! dedicated thread: packets arriving from the tunnel ([`TunnelClient::
//! recv_packet`]) are fed into smoltcp, and the packets smoltcp produces
//! ([`TunnelClient::send_packet`]) go back into the tunnel. TCP sockets of
//! the stack are exposed as [`Session`]s — bounded byte channels with
//! half-close support — so async code never touches the packet plane.
//!
//! No TUN device and no root: local applications talk TCP to the CLI
//! process, the stack turns that into tunnel packets. On a reconnect with
//! the same VIP the TCP sessions survive (both stacks keep their state and
//! TCP retransmits whatever was in flight); a new VIP aborts them — the
//! server drops packets with a foreign source address.

use std::collections::{HashMap, HashSet, VecDeque};
use std::net::Ipv4Addr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use smoltcp::iface::{Config, Interface, SocketHandle, SocketSet};
use smoltcp::phy::{Device, DeviceCapabilities, Medium, RxToken, TxToken};
use smoltcp::socket::tcp;
use smoltcp::time::Instant;
use smoltcp::wire::{HardwareAddress, IpAddress, IpCidr, IpEndpoint, IpListenEndpoint};
use tokio::sync::{mpsc, oneshot};
use tunnel_core::ffi::TunnelState;
use tunnel_core::TunnelClient;

use crate::error::StackError;

/// Per-session TCP buffer size (the receive window the far end may fill).
const TCP_BUFFER_SIZE: usize = 64 * 1024;
/// Chunk queue depth of a [`Session`] in each direction.
const SESSION_QUEUE_LEN: usize = 64;
/// Largest tunnel→stack batch per iteration (bounds one loop pass).
const RX_BURST_LIMIT: usize = 512;
/// Runner tick, ms: doubles as the blocking timeout of the next
/// `recv_packet`, so inbound traffic wakes the loop early.
const TICK_MS: u32 = 10;
/// Scratch size for one `recv_slice` pull (shared by all sessions).
const READ_CHUNK: usize = 16 * 1024;
/// How long a CONNECT may stay un-established before the runner fails it.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
/// First port of the ephemeral range used for outbound sessions (RFC 6335).
const EPHEMERAL_FIRST: u16 = 49152;
/// Size of the ephemeral port space.
const EPHEMERAL_COUNT: u16 = u16::MAX - EPHEMERAL_FIRST + 1;

// ---------------------------------------------------------------------------
// The smoltcp device over the tunnel's packet queues
// ---------------------------------------------------------------------------

/// The tunnel as a smoltcp device: `rx` holds packets arrived from the
/// tunnel, packets the stack emits land in `tx` and are flushed back into
/// the tunnel by the runner. `Medium::Ip` — raw datagrams, no Ethernet/ARP.
struct TunnelDevice {
    rx: VecDeque<Vec<u8>>,
    tx: VecDeque<Vec<u8>>,
    mtu: usize,
}

impl Device for TunnelDevice {
    type RxToken<'a> = TunnelRxToken<'a>;
    type TxToken<'a> = TunnelTxToken<'a>;

    fn receive(&mut self, _timestamp: Instant) -> Option<(Self::RxToken<'_>, Self::TxToken<'_>)> {
        if self.rx.is_empty() {
            return None;
        }
        Some((TunnelRxToken(&mut self.rx), TunnelTxToken(&mut self.tx, self.mtu)))
    }

    fn transmit(&mut self, _timestamp: Instant) -> Option<Self::TxToken<'_>> {
        Some(TunnelTxToken(&mut self.tx, self.mtu))
    }

    fn capabilities(&self) -> DeviceCapabilities {
        let mut caps = DeviceCapabilities::default();
        caps.medium = Medium::Ip;
        caps.max_transmission_unit = self.mtu;
        caps
    }
}

struct TunnelRxToken<'a>(&'a mut VecDeque<Vec<u8>>);

impl RxToken for TunnelRxToken<'_> {
    fn consume<R, F>(self, f: F) -> R
    where
        F: FnOnce(&[u8]) -> R,
    {
        // receive() returned Some only when the queue is non-empty.
        let packet = self.0.pop_front().unwrap_or_default();
        f(&packet)
    }
}

struct TunnelTxToken<'a>(&'a mut VecDeque<Vec<u8>>, usize);

impl TxToken for TunnelTxToken<'_> {
    fn consume<R, F>(self, len: usize, f: F) -> R
    where
        F: FnOnce(&mut [u8]) -> R,
    {
        let mut packet = vec![0u8; len];
        let result = f(&mut packet);
        // The interface is built with the negotiated MTU, so oversized
        // packets should not happen; drop them instead of letting QUIC
        // reject the whole datagram.
        if len <= self.1 {
            self.0.push_back(packet);
        } else {
            tracing::debug!(len, mtu = self.1, "oversized stack packet dropped");
        }
        result
    }
}

/// A TCP socket with heap-backed buffers (`'static`: the set outlives the
/// call site, so the buffers must not borrow from it).
fn new_tcp_socket() -> tcp::Socket<'static> {
    let rx = managed::ManagedSlice::from(vec![0u8; TCP_BUFFER_SIZE]);
    let tx = managed::ManagedSlice::from(vec![0u8; TCP_BUFFER_SIZE]);
    tcp::Socket::new(rx, tx)
}

/// Builds the point-to-point interface: the VIP as the only address. Routes
/// are not needed — the Ip medium delivers everything to the tunnel device,
/// and the source address selection falls back to the single interface
/// address.
fn build_interface(device: &mut TunnelDevice, vip: Ipv4Addr) -> Interface {
    let mut config = Config::new(HardwareAddress::Ip);
    config.random_seed = random_seed();
    let mut iface = Interface::new(config, device, Instant::now());
    iface.update_ip_addrs(|addrs| {
        let _ = addrs.push(IpCidr::new(IpAddress::Ipv4(vip), 32));
    });
    iface
}

/// A per-boot random seed for TCP sequence numbers (not cryptographic).
fn random_seed() -> u64 {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|since| since.as_nanos() as u64)
        .unwrap_or(0);
    nanos ^ (u64::from(std::process::id()) << 32)
}

// ---------------------------------------------------------------------------
// Public handles: Stack and Session
// ---------------------------------------------------------------------------

/// Handle of a running stack. Cloneable; [`Stack::connect`] opens a TCP
/// session through the tunnel, [`Stack::listen`] accepts connections from it.
#[derive(Clone)]
pub struct Stack {
    commands: mpsc::Sender<Command>,
    live: Arc<AtomicUsize>,
}

impl Stack {
    /// Spawns the runner thread. Safe to call before the tunnel is
    /// established: the runner waits for the first `Connected` state (the
    /// interface needs the VIP and the MTU from the server `Welcome`).
    pub fn spawn(client: Arc<TunnelClient>) -> Result<Self, StackError> {
        let (commands, rx) = mpsc::channel(64);
        let live = Arc::new(AtomicUsize::new(0));
        let counter = Arc::clone(&live);
        std::thread::Builder::new()
            .name("tunnel-cli-stack".to_owned())
            .spawn(move || runner(client, rx, counter))
            .map_err(|_| StackError::ThreadSpawn)?;
        Ok(Self { commands, live })
    }

    /// Opens a TCP session to `dst:port` through the tunnel. The local
    /// (client-side) port is allocated from the ephemeral range.
    pub async fn connect(&self, dst: Ipv4Addr, port: u16) -> Result<Session, StackError> {
        let (reply, answer) = oneshot::channel();
        self.commands
            .send(Command::Connect { dst, port, reply })
            .await
            .map_err(|_| StackError::Shutdown)?;
        // The runner fails the session when the socket closes or its
        // deadline fires; this timeout is the backstop for a silent path.
        match tokio::time::timeout(CONNECT_TIMEOUT, answer).await {
            Ok(Ok(result)) => result,
            Ok(Err(_runner_gone)) => Err(StackError::Shutdown),
            Err(_deadline) => Err(StackError::ConnectFailed),
        }
    }

    /// Exposes a TCP listener on the tunnel: incoming connections arrive as
    /// [`Session`]s. Used by the E2E far end and available for embedding
    /// (e.g. publishing a local service into the virtual network).
    pub async fn listen(&self, port: u16) -> Result<mpsc::Receiver<Session>, StackError> {
        let (reply, answer) = oneshot::channel();
        self.commands
            .send(Command::Listen { port, reply })
            .await
            .map_err(|_| StackError::Shutdown)?;
        answer.await.map_err(|_| StackError::Shutdown)?
    }

    /// Number of live (established) TCP sessions.
    pub fn live_sessions(&self) -> usize {
        self.live.load(Ordering::Relaxed)
    }
}

/// One TCP session through the tunnel, both directions. Dropping it closes
/// the TCP connection (a FIN); [`Session::send_half_close`] delivers only
/// the write-side EOF.
pub struct Session {
    id: u64,
    local_port: u16,
    outbound: mpsc::Sender<Vec<u8>>,
    inbound: mpsc::Receiver<Vec<u8>>,
    control: mpsc::UnboundedSender<Control>,
}

impl Session {
    /// Sends a chunk to the remote. Awaits capacity — the bounded queue is
    /// the backpressure path from the TCP window down to the application.
    pub async fn send(&self, chunk: Vec<u8>) -> Result<(), StackError> {
        self.outbound.send(chunk).await.map_err(|_| StackError::Shutdown)
    }

    /// Receives the next chunk from the remote; `None` — the session is
    /// over (the remote closed, or the stack dropped it).
    pub async fn recv(&mut self) -> Option<Vec<u8>> {
        self.inbound.recv().await
    }

    /// Signals EOF in the application→remote direction: the FIN is sent,
    /// the remote may keep sending (half-close).
    pub fn send_half_close(&self) {
        let _ = self.control.send(Control::HalfClose);
    }

    /// The local TCP port of the session (the SOCKS5 `BND.PORT` value).
    pub fn local_port(&self) -> u16 {
        self.local_port
    }

    /// The session identifier (diagnostics).
    pub fn id(&self) -> u64 {
        self.id
    }
}

enum Control {
    /// The application finished writing; deliver a FIN, keep reading.
    HalfClose,
}

enum Command {
    Connect {
        dst: Ipv4Addr,
        port: u16,
        reply: oneshot::Sender<Result<Session, StackError>>,
    },
    Listen {
        port: u16,
        reply: oneshot::Sender<Result<mpsc::Receiver<Session>, StackError>>,
    },
}

/// Fails a command with `error` (used while the tunnel is down).
fn fail_command_with(command: Command, error: StackError) {
    match command {
        Command::Connect { reply, .. } => {
            let _ = reply.send(Err(error));
        }
        Command::Listen { reply, .. } => {
            let _ = reply.send(Err(error));
        }
    }
}

// ---------------------------------------------------------------------------
// Runner state
// ---------------------------------------------------------------------------

/// A tracked socket: an outbound/inbound session or a tunnel-side listener.
enum Entry {
    Outbound(Box<Outbound>),
    Listener {
        handle: SocketHandle,
        port: u16,
        inbound: mpsc::Sender<Session>,
    },
}

/// Runner-side state of one established or connecting TCP session.
struct Outbound {
    handle: SocketHandle,
    local_port: u16,
    /// Present while the TCP handshake is in flight: the reply to the
    /// application plus the [`Session`] it will receive.
    connecting: Option<(oneshot::Sender<Result<Session, StackError>>, Session)>,
    connecting_since: std::time::Instant,
    established: bool,
    /// Application → remote chunks (the runner owns the receiver side).
    outbound_rx: mpsc::Receiver<Vec<u8>>,
    /// Remote → application chunks; `None` — the remote is done and the
    /// application has been told (the channel is closed).
    inbound_tx: Option<mpsc::Sender<Vec<u8>>>,
    /// Control messages (`HalfClose`).
    control_rx: mpsc::UnboundedReceiver<Control>,
    /// Chunks the application sent but the socket cannot absorb yet.
    pending_out: VecDeque<Vec<u8>>,
    /// Chunks pulled from the socket while the application queue was full.
    pending_in: VecDeque<Vec<u8>>,
}

/// Ephemeral port allocator for outbound sessions.
struct Ports {
    next: u16,
    used: HashSet<u16>,
}

impl Ports {
    fn new() -> Self {
        Self {
            next: EPHEMERAL_FIRST,
            used: HashSet::new(),
        }
    }

    /// Allocates a free ephemeral port, wrapping around the range once.
    fn alloc(&mut self) -> Option<u16> {
        for _ in 0..EPHEMERAL_COUNT {
            let port = self.next;
            self.next = if self.next == u16::MAX {
                EPHEMERAL_FIRST
            } else {
                self.next + 1
            };
            if self.used.insert(port) {
                return Some(port);
            }
        }
        None
    }

    fn free(&mut self, port: u16) {
        self.used.remove(&port);
    }
}

// ---------------------------------------------------------------------------
// The runner loop
// ---------------------------------------------------------------------------

/// The stack thread: pumps packets both ways, processes commands, polls
/// smoltcp and moves data between sockets and session channels.
fn runner(client: Arc<TunnelClient>, mut commands: mpsc::Receiver<Command>, live: Arc<AtomicUsize>) {
    // The interface needs the VIP and the MTU of the first session.
    // Commands are NOT drained here: the state check runs first, so a
    // request sent just after the caller saw `Connected` is processed by
    // the main loop instead of being failed by the race.
    let (mut vip, mtu) = loop {
        match client.state() {
            TunnelState::Connected { vip, mtu } => match vip.parse::<Ipv4Addr>() {
                Ok(vip) => break (vip, usize::from(mtu)),
                Err(_) => {
                    tracing::error!(vip = %vip, "the server issued an unparseable VIP");
                    while let Ok(command) = commands.try_recv() {
                        fail_command_with(command, StackError::Shutdown);
                    }
                    return;
                }
            },
            TunnelState::Stopped => {
                tracing::debug!("the tunnel stopped; the stack exits");
                while let Ok(command) = commands.try_recv() {
                    fail_command_with(command, StackError::Shutdown);
                }
                return;
            }
            _ => std::thread::sleep(Duration::from_millis(20)),
        }
    };

    let mut device = TunnelDevice {
        rx: VecDeque::new(),
        tx: VecDeque::new(),
        mtu,
    };
    let mut iface = build_interface(&mut device, vip);
    let mut sockets = SocketSet::new(vec![]);
    let mut entries: HashMap<u64, Entry> = HashMap::new();
    let mut ports = Ports::new();
    let mut next_id = 0u64;
    let mut scratch = vec![0u8; READ_CHUNK];
    tracing::debug!(%vip, mtu, "userspace TCP stack is up");

    loop {
        // Tunnel → stack.
        for _ in 0..RX_BURST_LIMIT {
            match client.recv_packet(0) {
                Some(packet) => device.rx.push_back(packet),
                None => break,
            }
        }

        // Commands.
        while let Ok(command) = commands.try_recv() {
            handle_command(
                &mut iface,
                &mut sockets,
                &mut entries,
                &mut ports,
                &mut next_id,
                command,
            );
        }

        // Reconnect handling: with the same VIP the TCP sessions survive
        // (both stacks keep their state, only in-flight packets were lost —
// TCP retransmits); a new VIP makes every packet's source foreign,
        // so the sessions are aborted.
        if let TunnelState::Connected { vip: state_vip, mtu } = client.state() {
            device.mtu = usize::from(mtu);
            if let Ok(new_vip) = state_vip.parse::<Ipv4Addr>() {
                if new_vip != vip {
                    tracing::warn!(from = %vip, to = %new_vip, "VIP changed: aborting the TCP sessions");
                    abort_all(&mut sockets, &mut entries, &mut ports, &live);
                    iface.update_ip_addrs(|addrs| {
                        addrs.clear();
                        let _ = addrs.push(IpCidr::new(IpAddress::Ipv4(new_vip), 32));
                    });
                    vip = new_vip;
                }
            }
        }

        // Stack processing.
        iface.poll(Instant::now(), &mut device, &mut sockets);
        pump_entries(&mut sockets, &mut entries, &mut ports, &live, &mut scratch);

        // Stack → tunnel.
        while let Some(packet) = device.tx.pop_front() {
            if !client.send_packet(packet) {
                tracing::debug!("the tunnel queue is full: a stack packet was dropped");
            }
        }

        // Tick: block briefly on the next inbound packet — the sleep and the
        // traffic wake-up in one call. The packet, if any, goes to the
        // device: discarding it here would eat exactly the packets that
        // arrive while the stack is otherwise idle.
        if let Some(packet) = client.recv_packet(TICK_MS) {
            device.rx.push_back(packet);
        }
    }
}

/// Handles one command from the async side.
fn handle_command(
    iface: &mut Interface,
    sockets: &mut SocketSet,
    entries: &mut HashMap<u64, Entry>,
    ports: &mut Ports,
    next_id: &mut u64,
    command: Command,
) {
    match command {
        Command::Connect { dst, port, reply } => {
            let Some(local_port) = ports.alloc() else {
                let _ = reply.send(Err(StackError::PortUnavailable));
                return;
            };
            let mut socket = new_tcp_socket();
            let remote = IpEndpoint {
                addr: IpAddress::Ipv4(dst),
                port,
            };
            let local = IpListenEndpoint {
                addr: None,
                port: local_port,
            };
            if let Err(err) = socket.connect(iface.context(), remote, local) {
                tracing::debug!(%dst, port, %err, "connect rejected by the stack");
                ports.free(local_port);
                let _ = reply.send(Err(StackError::ConnectFailed));
                return;
            }
            let handle = sockets.add(socket);
            let id = *next_id;
            *next_id += 1;
            let (outbound, outbound_rx) = mpsc::channel(SESSION_QUEUE_LEN);
            let (inbound_tx, inbound) = mpsc::channel(SESSION_QUEUE_LEN);
            let (control, control_rx) = mpsc::unbounded_channel();
            let session = Session {
                id,
                local_port,
                outbound,
                inbound,
                control,
            };
            entries.insert(
                id,
                Entry::Outbound(Box::new(Outbound {
                    handle,
                    local_port,
                    connecting: Some((reply, session)),
                    connecting_since: std::time::Instant::now(),
                    established: false,
                    outbound_rx,
                    inbound_tx: Some(inbound_tx),
                    control_rx,
                    pending_out: VecDeque::new(),
                    pending_in: VecDeque::new(),
                })),
            );
        }
        Command::Listen { port, reply } => {
            if port == 0 || !ports.used.insert(port) {
                let _ = reply.send(Err(StackError::PortUnavailable));
                return;
            }
            let mut socket = new_tcp_socket();
            if let Err(err) = socket.listen(IpListenEndpoint { addr: None, port }) {
                ports.free(port);
                tracing::debug!(port, %err, "the stack rejected the listen request");
                let _ = reply.send(Err(StackError::PortUnavailable));
                return;
            }
            let handle = sockets.add(socket);
            let (inbound, inbound_rx) = mpsc::channel(SESSION_QUEUE_LEN);
            let id = *next_id;
            *next_id += 1;
            entries.insert(id, Entry::Listener { handle, port, inbound });
            let _ = reply.send(Ok(inbound_rx));
        }
    }
}

/// Per-entry pump result: keep the entry or tear it down.
enum Pump {
    Keep,
    Remove,
}

/// Advances every tracked socket: accepts listeners, drives sessions.
fn pump_entries(
    sockets: &mut SocketSet,
    entries: &mut HashMap<u64, Entry>,
    ports: &mut Ports,
    live: &AtomicUsize,
    scratch: &mut [u8],
) {
    let ids: Vec<u64> = entries.keys().copied().collect();
    for id in ids {
        let Some(entry) = entries.get_mut(&id) else {
            continue;
        };
        if let Entry::Listener { handle, port, inbound } = entry {
            let established =
                sockets.get_mut::<tcp::Socket>(*handle).state() == tcp::State::Established;
            if established {
                // Copy the fields out: the borrow of `entries` must end
                // before the accept mutates the map.
                let accepted = Accepted {
                    id,
                    handle: *handle,
                    port: *port,
                    inbound: inbound.clone(),
                };
                accept_inbound(sockets, entries, ports, live, accepted);
            }
            continue;
        }
        let Entry::Outbound(outbound) = entry else {
            continue;
        };
        let outcome = pump_outbound(outbound, sockets, scratch, live);
        if matches!(outcome, Pump::Remove) {
            let (established, local_port, handle) =
                (outbound.established, outbound.local_port, outbound.handle);
            if established {
                live.fetch_sub(1, Ordering::Relaxed);
            }
            ports.free(local_port);
            sockets.remove(handle);
            entries.remove(&id);
        }
    }
}

/// The listener entry fields of an accepted connection.
struct Accepted {
    id: u64,
    handle: SocketHandle,
    port: u16,
    inbound: mpsc::Sender<Session>,
}

/// Converts an accepted listener socket into a session and swaps in a fresh
/// listening socket for the same port.
fn accept_inbound(
    sockets: &mut SocketSet,
    entries: &mut HashMap<u64, Entry>,
    ports: &mut Ports,
    live: &AtomicUsize,
    accepted: Accepted,
) {
    let Accepted {
        id,
        handle,
        port,
        inbound,
    } = accepted;
    let (outbound, outbound_rx) = mpsc::channel(SESSION_QUEUE_LEN);
    let (inbound_tx, session_inbound) = mpsc::channel(SESSION_QUEUE_LEN);
    let (control, control_rx) = mpsc::unbounded_channel();
    let session = Session {
        id,
        local_port: port,
        outbound,
        inbound: session_inbound,
        control,
    };

    // Hand the session to the application; if nobody is waiting, the
    // closed channels make the next pump tear the socket down.
    if inbound.try_send(session).is_err() {
        ports.free(port);
        sockets.remove(handle);
        entries.remove(&id);
        return;
    }

    // A fresh listener for the next connection on the same port. The
    // accepted socket keeps its handle: anything it already buffered is
    // still delivered through the session.
    let mut fresh = new_tcp_socket();
    if fresh
        .listen(IpListenEndpoint { addr: None, port })
        .is_ok()
    {
        let fresh_handle = sockets.add(fresh);
        if let Some(Entry::Listener { handle, .. }) = entries.get_mut(&id) {
            *handle = fresh_handle;
        }
    } else {
        tracing::warn!(port, "cannot re-arm the tunnel-side listener");
    }

    live.fetch_add(1, Ordering::Relaxed);
    if let Some(entry) = entries.get_mut(&id) {
        *entry = Entry::Outbound(Box::new(Outbound {
            handle,
            local_port: port,
            connecting: None,
            connecting_since: std::time::Instant::now(),
            established: true,
            outbound_rx,
            inbound_tx: Some(inbound_tx),
            control_rx,
            pending_out: VecDeque::new(),
            pending_in: VecDeque::new(),
        }));
    }
}

/// Drives one outbound/inbound session socket. Returns [`Pump::Remove`] to
/// tear the entry down.
fn pump_outbound(
    outbound: &mut Outbound,
    sockets: &mut SocketSet,
    scratch: &mut [u8],
    live: &AtomicUsize,
) -> Pump {
    // Handshake completion and failures.
    if let Some((reply, session)) = outbound.connecting.take() {
        let state = sockets.get_mut::<tcp::Socket>(outbound.handle).state();
        match state {
            tcp::State::Established => {
                outbound.established = true;
                // Counted before the reply: the application may check
                // `live_sessions()` the moment connect() returns.
                live.fetch_add(1, Ordering::Relaxed);
                let _ = reply.send(Ok(session));
            }
            // The remote refused, reset or became unreachable.
            tcp::State::Closed | tcp::State::TimeWait => {
                let _ = reply.send(Err(StackError::ConnectFailed));
                return Pump::Remove;
            }
            _ => {
                // Silent SYN retries: fail after the deadline.
                if std::time::Instant::now().duration_since(outbound.connecting_since) > CONNECT_TIMEOUT {
                    let _ = reply.send(Err(StackError::ConnectFailed));
                    return Pump::Remove;
                }
                outbound.connecting = Some((reply, session));
            }
        }
    }

    let socket = sockets.get_mut::<tcp::Socket>(outbound.handle);

    // Control: the application finished writing (half-close or drop).
    while let Ok(Control::HalfClose) = outbound.control_rx.try_recv() {
        if socket.is_open() {
            socket.close();
        }
    }

    // Application → remote.
    loop {
        match outbound.outbound_rx.try_recv() {
            Ok(chunk) => outbound.pending_out.push_back(chunk),
            Err(mpsc::error::TryRecvError::Empty) => break,
            Err(mpsc::error::TryRecvError::Disconnected) => {
                // The application dropped the session: deliver a FIN.
                if socket.is_open() {
                    socket.close();
                }
                break;
            }
        }
    }
    while socket.can_send() {
        let Some(chunk) = outbound.pending_out.pop_front() else {
            break;
        };
        let written = socket.send_slice(&chunk).unwrap_or(0);
        if written < chunk.len() {
            // The socket buffer filled up mid-chunk; the rest goes back.
            outbound.pending_out.push_front(chunk[written..].to_vec());
            break;
        }
    }

    // Remote → application. Not draining the socket keeps its receive
    // window small, which throttles the remote when the application is slow.
    let inbound_tx = outbound.inbound_tx.take();
    if let Some(inbound_tx) = &inbound_tx {
        loop {
            let mut chunk = outbound.pending_in.pop_front();
            if chunk.is_none() {
                if !socket.can_recv() {
                    break;
                }
                let received = socket.recv_slice(scratch).unwrap_or(0);
                if received == 0 {
                    break;
                }
                chunk = Some(scratch[..received].to_vec());
            }
            let chunk = chunk.expect("just built");
            match inbound_tx.try_send(chunk) {
                Ok(()) => {}
                Err(mpsc::error::TrySendError::Full(chunk)) => {
                    outbound.pending_in.push_front(chunk);
                    break;
                }
                Err(mpsc::error::TrySendError::Closed(_)) => {
                    // The application dropped the session: close the socket.
                    if socket.is_open() {
                        socket.close();
                    }
                    break;
                }
            }
        }
    }
    // The remote finished (its FIN was received and everything buffered was
    // delivered): tell the application and finish our side.
    let remote_finished = matches!(
        socket.state(),
        tcp::State::CloseWait | tcp::State::TimeWait | tcp::State::LastAck | tcp::State::Closing
    ) && !socket.can_recv()
        && outbound.pending_in.is_empty();
    if remote_finished && inbound_tx.is_some() {
        // Dropping the sender ends the application's `recv()` with `None`.
        if socket.is_open() {
            socket.close();
        }
    } else {
        outbound.inbound_tx = inbound_tx;
    }

    // Teardown: the TCP connection reached its end (TIME_WAIT runs for a
    // bounded 10 s in smoltcp, then the socket reaches `Closed`).
    if socket.state() == tcp::State::Closed {
        Pump::Remove
    } else {
        Pump::Keep
    }
}

/// Aborts every socket (a new VIP invalidates all sessions).
fn abort_all(
    sockets: &mut SocketSet,
    entries: &mut HashMap<u64, Entry>,
    ports: &mut Ports,
    live: &AtomicUsize,
) {
    let ids: Vec<u64> = entries.keys().copied().collect();
    for id in ids {
        let Some(entry) = entries.remove(&id) else {
            continue;
        };
        match entry {
            Entry::Outbound(outbound) => {
                if outbound.established {
                    live.fetch_sub(1, Ordering::Relaxed);
                }
                sockets.get_mut::<tcp::Socket>(outbound.handle).abort();
                sockets.remove(outbound.handle);
                ports.free(outbound.local_port);
            }
            Entry::Listener { handle, port, .. } => {
                sockets.get_mut::<tcp::Socket>(handle).abort();
                sockets.remove(handle);
                ports.free(port);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ephemeral_ports_are_unique_until_exhausted() {
        let mut ports = Ports::new();
        let first = ports.alloc().expect("first port");
        assert_eq!(first, EPHEMERAL_FIRST);
        let mut seen = HashSet::new();
        seen.insert(first);
        for _ in 1..EPHEMERAL_COUNT {
            let port = ports.alloc().expect("every port once before exhaustion");
            assert!(seen.insert(port), "port {port} was handed out twice");
        }
        assert_eq!(ports.alloc(), None, "the range is exhausted");
        // Freed ports become available again.
        ports.free(EPHEMERAL_FIRST);
        assert_eq!(ports.alloc(), Some(EPHEMERAL_FIRST));
    }

    #[test]
    fn ephemeral_ports_wrap_around_the_range() {
        let mut ports = Ports {
            next: u16::MAX,
            used: HashSet::new(),
        };
        assert_eq!(ports.alloc(), Some(u16::MAX));
        assert_eq!(ports.alloc(), Some(EPHEMERAL_FIRST), "wraps to the range start");
    }
}
