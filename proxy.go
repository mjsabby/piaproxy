// proxy.go: back-compat wrapper that combines a Tunnel + a
// SocksListener. New code should use Tunnel and SocksListener directly
// — those types own their own lifecycles and can be attached/detached
// independently. This Proxy type exists to keep the piaproxyd CLI and
// other pre-split consumers working without changes.
//
// Public surface kept stable:
//
//	NewProxy(cfg, pia) *Proxy
//	p.Bind = ...           (conn.Bind override; wired to internal Tunnel)
//	p.Username = ...       (wired to internal SocksListener)
//	p.Password = ...
//	p.DNSResolverIP = ...
//	p.Run(ctx)             (blocks; runs tunnel + listener; reconnect on
//	                        tunnel bring-up failure, listener is bound
//	                        for the entire Run lifetime).
//	p.Snapshot() Status    (merged tunnel + listener JSON, schema unchanged)
//	p.Netstack() *Net
//	p.Cfg() CityConfig
//
// Internally, Proxy holds a *Tunnel and a *SocksListener; the wrapper
// connects them so that the SocksListener is started as soon as Run is
// invoked and stopped when Run returns. The pre-split behavior of "the
// SOCKS5 listener doesn't bind until the tunnel is up" is reproduced
// here by waiting for the tunnel to first transition out of StateIdle.
package piaproxy

import (
	"context"
	"net"
	"sync"
	"time"

	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/tun/netstack"
)

// State is the high-level connection state of a Tunnel (and, by
// extension, a Proxy).
type State string

const (
	StateIdle       State = "idle"
	StateConnecting State = "connecting"
	StateUp         State = "up"
	StateDegraded   State = "degraded"
	StateError      State = "error"
)

// CityConfig is the static input for one Proxy / Tunnel.
type CityConfig struct {
	City   string // display name (e.g. "Seattle")
	Region string // PIA region ID (e.g. "us_seattle")
	Listen string // SOCKS5 listen address (e.g. "127.0.0.1:1081")

	// PreferredServer, if non-empty CN, makes runOnce try this exact
	// server first via NewSessionWithServer. On addKey failure (server
	// gone, network error, etc.) we fall back to the normal random pick
	// from region.WireGuardServers. This is how the Android wrapper
	// keeps "the same server across cellular flaps" without paying the
	// cost of a new auth round-trip.
	PreferredServer ServerEndpoint
}

// Proxy bundles a Tunnel and a SocksListener with the original
// "single-call lifecycle" API the piaproxyd CLI uses. For new code,
// prefer constructing Tunnel and SocksListener directly so you can
// attach/detach the listener independently.
type Proxy struct {
	cfg CityConfig
	pia *PIAClient

	// Bind is the wireguard-go conn.Bind used for outer UDP packets.
	// Forwarded to the internal Tunnel at Run() time.
	Bind conn.Bind

	// DNSResolverIP, Username, Password are forwarded to the internal
	// SocksListener at Run() time. See SocksOpts.
	DNSResolverIP net.IP
	Username      string
	Password      string

	mu       sync.RWMutex
	tunnel   *Tunnel
	listener *SocksListener
}

// NewProxy creates an idle proxy. Call Run to start it.
func NewProxy(cfg CityConfig, pia *PIAClient) *Proxy {
	return &Proxy{cfg: cfg, pia: pia}
}

// Cfg returns the static configuration.
func (p *Proxy) Cfg() CityConfig { return p.cfg }

// Netstack returns the gVisor netstack adapter currently powering the
// outbound side of this proxy's tunnel, or nil if the tunnel isn't
// currently up. Equivalent to Tunnel.Netstack on the internal tunnel;
// see that method's caveats about caching the returned pointer.
func (p *Proxy) Netstack() *netstack.Net {
	p.mu.RLock()
	t := p.tunnel
	p.mu.RUnlock()
	if t == nil {
		return nil
	}
	return t.Netstack()
}

// Run blocks until ctx is canceled. Starts the tunnel and (once the
// tunnel transitions out of Idle) starts the SOCKS5 listener. On
// ctx cancel both are torn down.
//
// Behavior matches the pre-split Proxy:
//   - Tunnel bring-up failures restart with backoff inside the Tunnel.
//   - The SOCKS5 listener is bound for the lifetime of Run; if the
//     tunnel cycles, the listener keeps accepting and dials go through
//     the new netstack on the next reconnect. Mid-cycle dials return
//     ErrTunnelDown which the SOCKS5 server reports as
//     "host unreachable".
func (p *Proxy) Run(ctx context.Context) {
	t := NewTunnel(p.cfg, p.pia)
	t.Bind = p.Bind
	l := NewSocksListener(t, p.cfg.Listen, SocksOpts{
		Username:      p.Username,
		Password:      p.Password,
		DNSResolverIP: p.DNSResolverIP,
	})

	p.mu.Lock()
	p.tunnel = t
	p.listener = l
	p.mu.Unlock()

	tunnelDone := make(chan struct{})
	go func() {
		defer close(tunnelDone)
		t.Run(ctx)
	}()

	// Wait for the tunnel to transition out of Idle before binding the
	// listener. This mirrors the pre-split behavior where the SOCKS5
	// listen() was deferred until the tunnel had at least started its
	// bring-up sequence. We don't wait for StateUp — that would
	// permanently delay binding if PIA is unreachable — just for any
	// state change at all.
	if !p.waitForTunnelStart(ctx, t) {
		<-tunnelDone
		return
	}

	if err := l.Start(ctx); err != nil {
		t.logger.Printf("SOCKS5 listener start failed: %v", err)
	}

	<-ctx.Done()
	_ = l.Stop()
	<-tunnelDone

	p.mu.Lock()
	p.tunnel = nil
	p.listener = nil
	p.mu.Unlock()
}

// waitForTunnelStart polls the tunnel's state until it leaves Idle,
// or ctx is canceled. Returns true if the tunnel started (and Run
// should proceed to bind the listener), false if ctx was canceled
// first.
func (p *Proxy) waitForTunnelStart(ctx context.Context, t *Tunnel) bool {
	ticker := time.NewTicker(50 * time.Millisecond)
	defer ticker.Stop()
	for {
		t.mu.RLock()
		s := t.state
		t.mu.RUnlock()
		if s != StateIdle {
			return true
		}
		select {
		case <-ctx.Done():
			return false
		case <-ticker.C:
		}
	}
}

// Status is the merged Tunnel + Listener snapshot. The JSON schema is
// stable across the pre-split Proxy and the post-split Proxy wrapper.
// New code that doesn't need back-compat should use Tunnel.Snapshot()
// and SocksListener.Snapshot() directly.
type Status struct {
	City                  string     `json:"city"`
	Region                string     `json:"region"`
	Listen                string     `json:"listen"`
	State                 State      `json:"state"`
	LastError             string     `json:"last_error,omitempty"`
	ServerCN              string     `json:"server_cn,omitempty"`
	ServerIP              string     `json:"server_ip,omitempty"`
	ServerPort            int        `json:"server_port,omitempty"`
	PeerIP                string     `json:"peer_ip,omitempty"`
	ConnectedAtMS         int64      `json:"connected_at_ms,omitempty"`
	AddKeyAtMS            int64      `json:"addkey_at_ms,omitempty"`
	UptimeSec             int64      `json:"uptime_sec"`
	HandshakeAgoS         int64      `json:"handshake_ago_s"`
	RxBytes               uint64     `json:"rx_bytes"`
	TxBytes               uint64     `json:"tx_bytes"`
	RxRate                float64    `json:"rx_rate_bps"`
	TxRate                float64    `json:"tx_rate_bps"`
	ProbeAtMS             int64      `json:"probe_at_ms"`
	ProbeOK               bool       `json:"probe_ok"`
	ProbeStatus           string     `json:"probe_status"`
	ProbeLatencyMs        int64      `json:"probe_latency_ms"`
	PingLatencyMs         int64      `json:"ping_latency_ms"`
	ProbeCount            uint64     `json:"probe_count"`
	ProbeFails            uint64     `json:"probe_fails"`
	ConnectTries          uint64     `json:"connect_tries"`
	ConnectFails          uint64     `json:"connect_fails"`
	AuthToken             string     `json:"auth_token,omitempty"`
	AuthTokenAcquiredAtMS int64      `json:"auth_token_acquired_at_ms,omitempty"`
	Conns                 []ConnInfo `json:"conns"`
}

// Snapshot returns a copy of the current state, merging the
// tunnel-side fields and the listener-side fields into the legacy
// Status struct shape.
func (p *Proxy) Snapshot() Status {
	p.mu.RLock()
	t := p.tunnel
	l := p.listener
	p.mu.RUnlock()

	s := Status{
		City:          p.cfg.City,
		Region:        p.cfg.Region,
		Listen:        p.cfg.Listen,
		State:         StateIdle,
		HandshakeAgoS: -1,
	}
	if t != nil {
		ts := t.Snapshot()
		s.State = ts.State
		s.LastError = ts.LastError
		s.ServerCN = ts.ServerCN
		s.ServerIP = ts.ServerIP
		s.ServerPort = ts.ServerPort
		s.PeerIP = ts.PeerIP
		s.ConnectedAtMS = ts.ConnectedAtMS
		s.AddKeyAtMS = ts.AddKeyAtMS
		s.UptimeSec = ts.UptimeSec
		s.HandshakeAgoS = ts.HandshakeAgoS
		s.RxBytes = ts.RxBytes
		s.TxBytes = ts.TxBytes
		s.RxRate = ts.RxRate
		s.TxRate = ts.TxRate
		s.ProbeAtMS = ts.ProbeAtMS
		s.ProbeOK = ts.ProbeOK
		s.ProbeStatus = ts.ProbeStatus
		s.ProbeLatencyMs = ts.ProbeLatencyMs
		s.PingLatencyMs = ts.PingLatencyMs
		s.ProbeCount = ts.ProbeCount
		s.ProbeFails = ts.ProbeFails
		s.ConnectTries = ts.ConnectTries
		s.ConnectFails = ts.ConnectFails
		s.AuthToken = ts.AuthToken
		s.AuthTokenAcquiredAtMS = ts.AuthTokenAcquiredAtMS
	}
	if l != nil {
		ls := l.Snapshot()
		s.Conns = ls.Conns
		if ls.Bound && ls.Addr != "" {
			s.Listen = ls.Addr
		}
	}
	if s.Conns == nil {
		s.Conns = []ConnInfo{}
	}
	return s
}
