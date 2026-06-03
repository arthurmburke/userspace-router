//! Stateful TCP connection tracking — the firewall layer that complements
//! [`crate::router::nat`]'s address translation.
//!
//! Implements the full TCP state machine from **RFC 9293 §3.3.2** (the
//! eleven-state FSM that supersedes RFC 793). We model both endpoints of each
//! TCP flow because the router is a passive observer: every packet we see is
//! sent by one peer and received by the other, and each side has its own state
//! per the spec. Egress packets advance the internal peer via the *send*
//! transitions and the external peer via the *receive* transitions; ingress
//! packets do the opposite.
//!
//! # Why per-peer states?
//!
//! TCP's state diagram in RFC 9293 §3.3.2 is per-endpoint, not per-flow. A
//! "flow" is the pairing of two endpoint state machines, and many transitions
//! only make sense relative to one side: `CLOSE-WAIT → LAST-ACK` is something
//! the FIN-receiver does when its application closes, not something the
//! FIN-sender does. A coarse one-state-per-flow model drops the asymmetry and
//! ends up either over- or under-permissive at teardown. Tracking both sides
//! independently is cheap (two `TcpState` byte enums per flow) and matches the
//! spec verbatim.
//!
//! # Why this isn't part of NAT
//!
//! The existing [`Nat`](crate::router::nat::Nat) is endpoint-independent
//! (full-cone): a given internal `(ip, port)` always maps to the same external
//! port regardless of peer, so the binding alone tells us how to *rewrite* a
//! return packet but not whether to *accept* it. Two different peers can be
//! talking to the same internal endpoint via the same external port; without
//! per-flow state the router would happily forward unsolicited probes.
//!
//! Conntrack adds the 5-tuple state needed for "this packet belongs to a flow
//! we opened" checks, while NAT keeps doing the address arithmetic.

use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::sync::Arc;

use crate::core::spinlock::SpinLock;
use crate::net::tcp::flag;
use crate::router::neighbor::Tick;

/// 5-tuple keying a TCP flow. "Internal" / "external" names the side of the
/// NAT — `int_*` is the LAN host, `ext_*` is the public peer — independent of
/// which direction a given packet is travelling.
///
/// Protocol is implicit (TCP) since only TCP flows live here.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
struct FlowKey {
    int_ip: Ipv4Addr,
    int_port: u16,
    ext_ip: Ipv4Addr,
    ext_port: u16,
}

/// The eleven TCP connection states from **RFC 9293 §3.3.2**. We model both
/// endpoints' states independently — see the module docs for the rationale.
///
/// `Listen` exists for completeness; today the router only tracks
/// egress-initiated flows, so we never legitimately enter it from `Closed`
/// via a received SYN to a tracked endpoint. We model the transitions anyway
/// so `transition_on_recv` can be reused if passive opens are added later.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum TcpState {
    Closed,
    Listen,
    SynSent,
    SynReceived,
    Established,
    FinWait1,
    FinWait2,
    CloseWait,
    Closing,
    LastAck,
    TimeWait,
}

impl TcpState {
    /// Idle timeout, in milliseconds, before [`ConnTrack::sweep`] evicts a
    /// flow sitting in this state. Numbers track Linux netfilter's defaults
    /// (`net.netfilter.nf_conntrack_tcp_timeout_*`), which themselves follow
    /// RFC 9293's recommendations:
    ///
    /// - `Established` is long (24 h) because real flows are refreshed on
    ///   every packet; we never sit here idle for that long in practice.
    /// - `TimeWait` is 2*MSL (120 s, the conventional MSL of 60 s).
    /// - SYN-side states use 60 s — enough for OS retransmits, short enough
    ///   that half-open scans don't pin memory.
    /// - `Closed` is short (10 s) so reaped flows aren't immediately recreated
    ///   by a stray retransmit; the entry sticks just long enough to absorb
    ///   final TCP noise.
    pub const fn idle_timeout_ms(self) -> u64 {
        use TcpState::*;
        match self {
            Closed => 10_000,
            Listen => 60_000,
            SynSent | SynReceived => 60_000,
            Established => 24 * 60 * 60_000,
            FinWait1 | FinWait2 => 60_000,
            CloseWait => 60_000,
            Closing => 60_000,
            LastAck => 30_000,
            TimeWait => 120_000,
        }
    }
}

/// Per-flow state: both peers' RFC 9293 states plus a `last_seen` for aging.
#[derive(Clone, Copy)]
struct Conn {
    /// State of the LAN-side endpoint.
    internal: TcpState,
    /// State of the WAN-side endpoint.
    external: TcpState,
    last_seen: Tick,
}

impl Conn {
    /// A flow is fully closed once both endpoints reach `Closed`. We reap
    /// these immediately rather than waiting for the idle sweep, since
    /// post-close packets are either retransmits we shouldn't forward or new
    /// connection attempts that need to start from scratch.
    fn fully_closed(&self) -> bool {
        self.internal == TcpState::Closed && self.external == TcpState::Closed
    }

    /// The active timeout for this flow is the *longer* of either peer's
    /// per-state timeout. We keep the flow alive as long as the most-patient
    /// endpoint expects it to be — otherwise normal half-closed traffic
    /// (one side in `FinWait2`, the other in `CloseWait`) would get evicted
    /// before the closing app drains its buffer.
    fn idle_timeout_ms(&self) -> u64 {
        self.internal
            .idle_timeout_ms()
            .max(self.external.idle_timeout_ms())
    }
}

/// Advance the state of the peer that *sent* a packet with these flags, per
/// the RFC 9293 FSM. Many state transitions in the diagram are driven by the
/// application (open, close, abort) rather than by the wire, so for those we
/// return the unchanged state — the only way they can happen is when the
/// *receiver* on the other side observes them as receive events.
pub fn transition_on_send(state: TcpState, flags: u8) -> TcpState {
    use TcpState::*;
    let syn = flags & flag::SYN != 0;
    let ack = flags & flag::ACK != 0;
    let fin = flags & flag::FIN != 0;
    let rst = flags & flag::RST != 0;

    // RST is unambiguous: sender forcibly closes.
    if rst {
        return Closed;
    }

    match state {
        // Active open: app called `connect()`, stack sends SYN.
        Closed if syn && !ack => SynSent,
        // Passive open responding to a SYN we received: send SYN+ACK.
        Listen if syn && ack => SynReceived,
        // Retransmits of SYN+ACK while waiting for the final ACK — no change.
        SynReceived if syn && ack => SynReceived,
        // App close while connection is established: send FIN.
        Established if fin => FinWait1,
        // App close after peer's FIN already arrived: send our FIN.
        CloseWait if fin => LastAck,
        // Everything else is either an ACK or data that doesn't advance the
        // sender's state — receive transitions handle those on the peer side.
        _ => state,
    }
}

/// Advance the state of the peer that *received* a packet with these flags,
/// per the RFC 9293 FSM. This is the half of the diagram that gets driven
/// directly by the wire — most "interesting" transitions live here.
pub fn transition_on_recv(state: TcpState, flags: u8) -> TcpState {
    use TcpState::*;
    let syn = flags & flag::SYN != 0;
    let ack = flags & flag::ACK != 0;
    let fin = flags & flag::FIN != 0;
    let rst = flags & flag::RST != 0;

    // RST received: tear the receiver's state down.
    if rst {
        return Closed;
    }

    match state {
        // Stack receives a SYN to a port the app is listening on. We never
        // legitimately reach this branch in the egress-only model, but it
        // matches the spec.
        Closed if syn && !ack => SynReceived,
        Listen if syn && !ack => SynReceived,

        // Three-way handshake, the common case: our SYN got SYN+ACK back.
        SynSent if syn && ack => Established,
        // Simultaneous open: both peers sent SYN before seeing the other's.
        SynSent if syn => SynReceived,
        // Responder receives the final ACK of the handshake. Per RFC 9293
        // §3.10.7.4, any valid ACK in SYN-RECEIVED moves to ESTABLISHED —
        // including a SYN+ACK in the simultaneous-open case, where the
        // peer's SYN+ACK carries an acknowledgement of our SYN. We exclude
        // a co-set FIN so a half-open FIN doesn't shortcut into ESTABLISHED.
        SynReceived if ack && !fin => Established,

        // Peer initiates close while we're connected.
        Established if fin => CloseWait,

        // We sent FIN (we're in FIN-WAIT-1) and the peer responds:
        // - their FIN+ACK closes our side simultaneously → TIME-WAIT.
        // - their FIN alone (we haven't been ACK'd yet) → CLOSING.
        // - their ACK to our FIN with no FIN of their own → FIN-WAIT-2.
        FinWait1 if fin && ack => TimeWait,
        FinWait1 if fin => Closing,
        FinWait1 if ack => FinWait2,

        // We were waiting for the peer's FIN; it arrived → enter TIME-WAIT.
        FinWait2 if fin => TimeWait,

        // We're CLOSING (both sent FINs nearly simultaneously); peer's ACK
        // for ours arrives → TIME-WAIT.
        Closing if ack => TimeWait,

        // We're LAST-ACK (sent the second FIN); peer's ACK closes us fully.
        LastAck if ack => Closed,

        // CLOSE-WAIT and TIME-WAIT don't advance on incoming packets — they
        // wait for an app-close and a 2*MSL timeout respectively.
        _ => state,
    }
}

pub struct ConnTrack {
    flows: HashMap<FlowKey, Conn>,
}

impl ConnTrack {
    pub fn new() -> Self {
        Self {
            flows: HashMap::new(),
        }
    }

    pub fn len(&self) -> usize {
        self.flows.len()
    }

    pub fn is_empty(&self) -> bool {
        self.flows.is_empty()
    }

    /// Observe an outbound (LAN → WAN) TCP packet. The internal endpoint is
    /// the *sender*, the external endpoint is the *receiver*; update both
    /// per the RFC 9293 FSM. Returns the post-update `(internal, external)`
    /// states for inspection (and tests).
    ///
    /// Creates a flow on first sight: a bare outbound SYN will start from
    /// `(Closed, Closed)` and end up at `(SynSent, SynReceived)`, which is
    /// where the receiver of an unsolicited SYN sits per RFC 9293's
    /// "SEND/CLOSED → SYN-SENT" plus the receive transition into
    /// `SYN-RECEIVED`.
    pub fn observe_egress(
        &mut self,
        int_ip: Ipv4Addr,
        int_port: u16,
        ext_ip: Ipv4Addr,
        ext_port: u16,
        flags: u8,
        now: Tick,
    ) -> (TcpState, TcpState) {
        let key = FlowKey {
            int_ip,
            int_port,
            ext_ip,
            ext_port,
        };
        let conn = self.flows.entry(key).or_insert(Conn {
            internal: TcpState::Closed,
            external: TcpState::Closed,
            last_seen: now,
        });

        conn.internal = transition_on_send(conn.internal, flags);
        conn.external = transition_on_recv(conn.external, flags);
        conn.last_seen = now;

        let states = (conn.internal, conn.external);
        if conn.fully_closed() {
            self.flows.remove(&key);
        }
        states
    }

    /// Check an inbound (WAN → LAN) TCP packet against the table.
    ///
    /// Returns `true` and updates flow state when:
    /// - the 5-tuple matches an existing flow, **and**
    /// - that flow isn't already fully closed.
    ///
    /// Returns `false` (drop the packet) when:
    /// - no flow matches (unsolicited inbound — scan, stray packet, replay), or
    /// - the flow exists but both endpoints are already `Closed` (post-RST or
    ///   after a full teardown that hasn't yet been swept).
    ///
    /// On a `true` return the external endpoint is the *sender* and the
    /// internal endpoint is the *receiver*; both transition per RFC 9293.
    pub fn check_ingress(
        &mut self,
        int_ip: Ipv4Addr,
        int_port: u16,
        ext_ip: Ipv4Addr,
        ext_port: u16,
        flags: u8,
        now: Tick,
    ) -> bool {
        let key = FlowKey {
            int_ip,
            int_port,
            ext_ip,
            ext_port,
        };
        let Some(conn) = self.flows.get_mut(&key) else {
            return false;
        };
        if conn.fully_closed() {
            // Stale flow entry; the next sweep will collect it.
            return false;
        }

        conn.external = transition_on_send(conn.external, flags);
        conn.internal = transition_on_recv(conn.internal, flags);
        conn.last_seen = now;

        let now_fully_closed = conn.fully_closed();
        if now_fully_closed {
            self.flows.remove(&key);
        }
        true
    }

    /// Drop flows whose `last_seen` is older than their per-state timeout.
    /// Call periodically (e.g. from the sweeper lcore alongside neighbor
    /// sweeps).
    pub fn sweep(&mut self, now: Tick) {
        self.flows
            .retain(|_, c| now.elapsed_since(c.last_seen) < c.idle_timeout_ms());
    }

    /// Look up the (internal, external) RFC 9293 states for a flow without
    /// mutating it. Returns `None` when no flow matches. Useful for tests,
    /// observability dashboards, and assertions in the data plane.
    pub fn states(
        &self,
        int_ip: Ipv4Addr,
        int_port: u16,
        ext_ip: Ipv4Addr,
        ext_port: u16,
    ) -> Option<(TcpState, TcpState)> {
        let key = FlowKey {
            int_ip,
            int_port,
            ext_ip,
            ext_port,
        };
        self.flows.get(&key).map(|c| (c.internal, c.external))
    }

    /// Display the status of the conntrack table for debugging and observability. Shows each flow's 5-tuple and
    /// both endpoints' states. Flows that are fully closed are included here until the next sweep.
    pub fn status(&self, f: &mut impl std::fmt::Write) -> std::fmt::Result {
        writeln!(f, "ConnTrack:")?;
        for (key, conn) in &self.flows {
            writeln!(
                f,
                "  {}:{} ↔ {}:{} → ({:?}, {:?}) @ {} ms",
                key.int_ip, key.int_port, key.ext_ip, key.ext_port, conn.internal, conn.external, conn.last_seen.0
            )?;
        }
        Ok(())
    }
}

impl Default for ConnTrack {
    fn default() -> Self {
        Self::new()
    }
}

/// Cloneable handle to a [`ConnTrack`] shared across workers. Every operation
/// briefly takes the spinlock — the work is a single hash lookup + state
/// update, so contention stays low even at line rate.
#[derive(Clone)]
pub struct SharedConnTrack {
    inner: Arc<SpinLock<ConnTrack>>,
}

impl SharedConnTrack {
    pub fn new() -> Self {
        Self {
            inner: Arc::new(SpinLock::new(ConnTrack::new())),
        }
    }

    pub fn len(&self) -> usize {
        self.inner.with(|c| c.len())
    }

    pub fn is_empty(&self) -> bool {
        self.inner.with(|c| c.is_empty())
    }

    pub fn observe_egress(
        &self,
        int_ip: Ipv4Addr,
        int_port: u16,
        ext_ip: Ipv4Addr,
        ext_port: u16,
        flags: u8,
        now: Tick,
    ) -> (TcpState, TcpState) {
        self.inner
            .with(|c| c.observe_egress(int_ip, int_port, ext_ip, ext_port, flags, now))
    }

    pub fn check_ingress(
        &self,
        int_ip: Ipv4Addr,
        int_port: u16,
        ext_ip: Ipv4Addr,
        ext_port: u16,
        flags: u8,
        now: Tick,
    ) -> bool {
        self.inner
            .with(|c| c.check_ingress(int_ip, int_port, ext_ip, ext_port, flags, now))
    }

    pub fn sweep(&self, now: Tick) {
        self.inner.with(|c| c.sweep(now));
    }

    pub fn states(
        &self,
        int_ip: Ipv4Addr,
        int_port: u16,
        ext_ip: Ipv4Addr,
        ext_port: u16,
    ) -> Option<(TcpState, TcpState)> {
        self.inner
            .with(|c| c.states(int_ip, int_port, ext_ip, ext_port))
    }

    pub fn status(&self, f: &mut impl std::fmt::Write) -> std::fmt::Result {
        self.inner.with(|c| c.status(f))
    }
}

impl Default for SharedConnTrack {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const INT_IP: Ipv4Addr = Ipv4Addr::new(192, 168, 1, 50);
    const EXT_IP: Ipv4Addr = Ipv4Addr::new(203, 0, 113, 10);
    const INT_PORT: u16 = 49_152;
    const EXT_PORT: u16 = 443;

    /// Helpers to read flow state out of conntrack for assertions.
    fn states(c: &ConnTrack) -> Option<(TcpState, TcpState)> {
        c.states(INT_IP, INT_PORT, EXT_IP, EXT_PORT)
    }
    fn out(c: &mut ConnTrack, flags: u8, t_ms: u64) -> (TcpState, TcpState) {
        c.observe_egress(INT_IP, INT_PORT, EXT_IP, EXT_PORT, flags, Tick::ms(t_ms))
    }
    fn into_(c: &mut ConnTrack, flags: u8, t_ms: u64) -> bool {
        c.check_ingress(INT_IP, INT_PORT, EXT_IP, EXT_PORT, flags, Tick::ms(t_ms))
    }

    // ---------- RFC 9293 transition coverage ----------

    #[test]
    fn three_way_handshake_walks_both_endpoints_to_established() {
        let mut c = ConnTrack::new();

        // (CLOSED, CLOSED) --SYN--> (SYN-SENT, SYN-RECEIVED)
        assert_eq!(
            out(&mut c, flag::SYN, 0),
            (TcpState::SynSent, TcpState::SynReceived)
        );

        // (SYN-SENT, SYN-RECEIVED) <--SYN+ACK-- (ESTABLISHED, SYN-RECEIVED)
        // External sends SYN+ACK; it stays SYN-RECEIVED (resend semantics).
        assert!(into_(&mut c, flag::SYN | flag::ACK, 1));
        assert_eq!(
            states(&c).unwrap(),
            (TcpState::Established, TcpState::SynReceived)
        );

        // (ESTABLISHED, SYN-RECEIVED) --ACK--> (ESTABLISHED, ESTABLISHED)
        out(&mut c, flag::ACK, 2);
        assert_eq!(
            states(&c).unwrap(),
            (TcpState::Established, TcpState::Established)
        );
    }

    #[test]
    fn simultaneous_open_walks_to_established() {
        // Both sides send SYN before seeing the other's.
        let mut c = ConnTrack::new();
        out(&mut c, flag::SYN, 0);
        // External (somehow) sends bare SYN — we move internal to SYN-RECEIVED.
        assert!(into_(&mut c, flag::SYN, 1));
        assert_eq!(
            states(&c).unwrap(),
            (TcpState::SynReceived, TcpState::SynReceived)
        );
        // Now the SYN+ACK each side sends drives both to ESTABLISHED.
        out(&mut c, flag::SYN | flag::ACK, 2);
        assert!(into_(&mut c, flag::SYN | flag::ACK, 3));
        assert_eq!(
            states(&c).unwrap(),
            (TcpState::Established, TcpState::Established)
        );
    }

    #[test]
    fn normal_active_close_runs_through_fin_wait_states() {
        let mut c = ConnTrack::new();
        // Bring the flow to ESTABLISHED.
        out(&mut c, flag::SYN, 0);
        into_(&mut c, flag::SYN | flag::ACK, 1);
        out(&mut c, flag::ACK, 2);

        // Internal sends FIN → internal moves to FIN-WAIT-1, external to CLOSE-WAIT.
        out(&mut c, flag::FIN | flag::ACK, 3);
        assert_eq!(
            states(&c).unwrap(),
            (TcpState::FinWait1, TcpState::CloseWait)
        );

        // External ACKs our FIN → internal moves to FIN-WAIT-2.
        into_(&mut c, flag::ACK, 4);
        assert_eq!(
            states(&c).unwrap(),
            (TcpState::FinWait2, TcpState::CloseWait)
        );

        // External (its app called close) sends its FIN. The send-side
        // transition CLOSE-WAIT + FIN → LAST-ACK happens for external; the
        // recv-side FIN-WAIT-2 + FIN → TIME-WAIT happens for internal.
        into_(&mut c, flag::FIN | flag::ACK, 5);
        assert_eq!(
            states(&c).unwrap(),
            (TcpState::TimeWait, TcpState::LastAck)
        );

        // Internal ACKs that FIN → external transitions LAST-ACK + ACK →
        // CLOSED via its recv-side rule; internal stays in TIME-WAIT waiting
        // out 2*MSL. The flow lives until TIME-WAIT ages out (internal Closed
        // && external Closed is false because internal is still TIME-WAIT).
        out(&mut c, flag::ACK, 6);
        assert_eq!(
            states(&c).unwrap(),
            (TcpState::TimeWait, TcpState::Closed)
        );
    }

    #[test]
    fn crossed_fins_with_ack_collapse_to_time_wait() {
        // The common "close-close" pattern where B's FIN+ACK arrives at A
        // before B has seen A's FIN. The +ACK piggybacks the acknowledgement
        // of A's FIN, so A transitions FIN-WAIT-1 → TIME-WAIT directly per
        // RFC 9293 §3.10.7.4 (the FIN+ACK closes both half-connections at
        // once). The bare-FIN case that exercises CLOSING is covered by the
        // separate `simultaneous_close_via_bare_fin_routes_through_closing`
        // test below.
        let mut c = ConnTrack::new();
        out(&mut c, flag::SYN, 0);
        into_(&mut c, flag::SYN | flag::ACK, 1);
        out(&mut c, flag::ACK, 2);

        out(&mut c, flag::FIN | flag::ACK, 3);
        into_(&mut c, flag::FIN | flag::ACK, 4);

        assert_eq!(
            states(&c).unwrap(),
            (TcpState::TimeWait, TcpState::LastAck)
        );
    }

    #[test]
    fn simultaneous_close_via_bare_fin_routes_through_closing() {
        // True simultaneous close per RFC 9293: A sends FIN, then receives B's
        // FIN *without an ACK* for A's FIN (because B's FIN was generated
        // before B saw A's). A's FIN-WAIT-1 + recv FIN → CLOSING (we need the
        // peer's ACK before we can move on).
        let mut c = ConnTrack::new();
        out(&mut c, flag::SYN, 0);
        into_(&mut c, flag::SYN | flag::ACK, 1);
        out(&mut c, flag::ACK, 2);

        // A sends FIN.
        out(&mut c, flag::FIN | flag::ACK, 3);
        assert_eq!(
            states(&c).unwrap(),
            (TcpState::FinWait1, TcpState::CloseWait)
        );

        // B's bare FIN crosses in — no ACK of A's FIN.
        into_(&mut c, flag::FIN, 4);
        assert_eq!(
            states(&c).unwrap(),
            (TcpState::Closing, TcpState::LastAck)
        );

        // B's eventual ACK closes A out into TIME-WAIT.
        into_(&mut c, flag::ACK, 5);
        assert_eq!(
            states(&c).unwrap(),
            (TcpState::TimeWait, TcpState::LastAck)
        );
    }

    #[test]
    fn rst_immediately_closes_both_sides() {
        let mut c = ConnTrack::new();
        out(&mut c, flag::SYN, 0);
        into_(&mut c, flag::SYN | flag::ACK, 1);
        out(&mut c, flag::ACK, 2);

        // External RSTs the flow.
        let admitted = into_(&mut c, flag::RST, 3);
        assert!(admitted, "RST should be delivered to the internal host");
        // Both states should be Closed → flow is reaped.
        assert!(states(&c).is_none(), "fully-closed flow should be removed");
    }

    // ---------- Firewall admission policy ----------

    #[test]
    fn unsolicited_ingress_is_dropped() {
        let mut c = ConnTrack::new();
        assert!(!into_(&mut c, flag::SYN | flag::ACK, 0));
        assert!(!into_(&mut c, flag::ACK, 0));
        assert!(!into_(&mut c, flag::SYN, 0));
        assert_eq!(c.len(), 0, "rejected ingress shouldn't create flows");
    }

    #[test]
    fn wrong_peer_attack_is_dropped() {
        let mut c = ConnTrack::new();
        out(&mut c, flag::SYN, 0);
        // A stranger hitting the same internal endpoint at the same port:
        let stranger = Ipv4Addr::new(198, 51, 100, 99);
        let ok = c.check_ingress(
            INT_IP,
            INT_PORT,
            stranger,
            EXT_PORT,
            flag::SYN | flag::ACK,
            Tick::ms(1),
        );
        assert!(!ok);
    }

    // ---------- Per-state timeouts ----------

    #[test]
    fn idle_syn_sent_is_swept_after_60s() {
        let mut c = ConnTrack::new();
        out(&mut c, flag::SYN, 0);
        // 1 ms before SYN-SENT timeout: alive.
        c.sweep(Tick::ms(TcpState::SynSent.idle_timeout_ms() - 1));
        assert_eq!(c.len(), 1);
        // At/past the timeout: gone. Note that the *flow*'s timeout uses the
        // max of both sides, and external is SYN-RECEIVED which has the same
        // 60 s timeout — so the flow ages out at exactly that mark.
        c.sweep(Tick::ms(TcpState::SynSent.idle_timeout_ms()));
        assert_eq!(c.len(), 0);
    }

    #[test]
    fn time_wait_uses_2_msl_timeout() {
        let mut c = ConnTrack::new();
        // Drive into TIME-WAIT via the active-close path.
        out(&mut c, flag::SYN, 0);
        into_(&mut c, flag::SYN | flag::ACK, 1);
        out(&mut c, flag::ACK, 2);
        out(&mut c, flag::FIN | flag::ACK, 3);
        into_(&mut c, flag::ACK, 4);
        into_(&mut c, flag::FIN | flag::ACK, 5);
        let (i, _) = states(&c).unwrap();
        assert_eq!(i, TcpState::TimeWait);

        // Refresh `last_seen` to 5 ms (the last update).
        // Inside the TIME-WAIT timeout: still alive.
        c.sweep(Tick::ms(5 + TcpState::TimeWait.idle_timeout_ms() - 1));
        assert_eq!(c.len(), 1);
        // Past the TIME-WAIT timeout: gone.
        c.sweep(Tick::ms(5 + TcpState::TimeWait.idle_timeout_ms()));
        assert_eq!(c.len(), 0);
    }

    #[test]
    fn established_uses_a_long_timeout_so_idle_keepalives_survive() {
        let mut c = ConnTrack::new();
        out(&mut c, flag::SYN, 0);
        into_(&mut c, flag::SYN | flag::ACK, 1);
        out(&mut c, flag::ACK, 2);
        // Hours later, nothing has been flowing — flow should still be alive.
        c.sweep(Tick::ms(6 * 60 * 60_000)); // 6 hours
        assert_eq!(c.len(), 1);
    }

    // ---------- Smoke test for SharedConnTrack ----------

    #[test]
    fn shared_handle_mirrors_inner_state() {
        let s = SharedConnTrack::new();
        let (i, e) = s.observe_egress(INT_IP, INT_PORT, EXT_IP, EXT_PORT, flag::SYN, Tick::ms(0));
        assert_eq!((i, e), (TcpState::SynSent, TcpState::SynReceived));
        assert_eq!(
            s.states(INT_IP, INT_PORT, EXT_IP, EXT_PORT),
            Some((TcpState::SynSent, TcpState::SynReceived))
        );
        assert!(s.check_ingress(INT_IP, INT_PORT, EXT_IP, EXT_PORT, flag::SYN | flag::ACK, Tick::ms(1)));
        assert_eq!(
            s.states(INT_IP, INT_PORT, EXT_IP, EXT_PORT),
            Some((TcpState::Established, TcpState::SynReceived))
        );
    }

    // ---------- Spot-check the transition tables themselves ----------

    #[test]
    fn send_transitions_match_rfc_9293() {
        use TcpState::*;
        assert_eq!(transition_on_send(Closed, flag::SYN), SynSent);
        assert_eq!(transition_on_send(Listen, flag::SYN | flag::ACK), SynReceived);
        assert_eq!(transition_on_send(Established, flag::FIN | flag::ACK), FinWait1);
        assert_eq!(transition_on_send(CloseWait, flag::FIN | flag::ACK), LastAck);
        assert_eq!(transition_on_send(Established, flag::RST), Closed);
        // Stable states for non-driving flags:
        assert_eq!(transition_on_send(Established, flag::ACK), Established);
        assert_eq!(transition_on_send(FinWait2, flag::ACK), FinWait2);
    }

    #[test]
    fn recv_transitions_match_rfc_9293() {
        use TcpState::*;
        assert_eq!(transition_on_recv(SynSent, flag::SYN | flag::ACK), Established);
        assert_eq!(transition_on_recv(SynSent, flag::SYN), SynReceived);
        assert_eq!(transition_on_recv(SynReceived, flag::ACK), Established);
        assert_eq!(transition_on_recv(Established, flag::FIN | flag::ACK), CloseWait);
        assert_eq!(transition_on_recv(FinWait1, flag::FIN | flag::ACK), TimeWait);
        assert_eq!(transition_on_recv(FinWait1, flag::ACK), FinWait2);
        assert_eq!(transition_on_recv(FinWait1, flag::FIN), Closing);
        assert_eq!(transition_on_recv(FinWait2, flag::FIN | flag::ACK), TimeWait);
        assert_eq!(transition_on_recv(Closing, flag::ACK), TimeWait);
        assert_eq!(transition_on_recv(LastAck, flag::ACK), Closed);
        assert_eq!(transition_on_recv(Established, flag::RST), Closed);
    }
}
