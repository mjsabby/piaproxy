// tunnel.go: PIA WireGuard tunnel lifecycle, decoupled from any
// downstream listener.
//
// A Tunnel owns the WG userspace device, the gVisor netstack, and the
// per-session status/health/stats loops. It exposes Netstack() and
// Dial(...) so independent listeners (SOCKS5, inbound WG receiver, …)
// can dial out through the tunnel without holding stale references
// across reconnects.
//
// Lifecycle:
//
//	t := NewTunnel(cfg, pia)
//	go t.Run(ctx)
//	// any time after Run starts, callers can Dial via t.Dial.
//	// returns ErrTunnelDown until the tunnel reaches StateUp.
//	cancel()                // shuts everything down
package piaproxy

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun/netstack"
)

// ErrTunnelDown is returned by Tunnel.Dial when the tunnel is not
// currently up (no netstack, e.g. the very first bring-up hasn't
// completed yet or we're between reconnect attempts).
var ErrTunnelDown = errors.New("piaproxy: tunnel is down")

// Tunnel is one PIA WireGuard session. It is independent of any
// downstream listener: it can be up and idle, with listeners attaching
// and detaching freely.
//
// Public fields (Bind) must be set before calling Run.
type Tunnel struct {
	cfg CityConfig
	pia *PIAClient

	// Bind is the wireguard-go conn.Bind used for outer UDP packets.
	// If nil, Run installs conn.NewDefaultBind() (standard dual-stack
	// StdNetBind). The Android variant injects a custom Bind that pins
	// each outer UDP socket to the cellular Network so the carrier
	// sees those packets as phone-originated rather than tethered.
	Bind conn.Bind

	logger *log.Logger

	// guarded by mu
	mu             sync.RWMutex
	state          State
	lastError      string
	session        *WGSession
	connectedAt    time.Time
	addKeyAt       time.Time
	lastHandshake  time.Time
	rxTotal        uint64
	txTotal        uint64
	rxRate         float64 // bytes/sec, EMA-smoothed
	txRate         float64
	prevRx         uint64
	prevTx         uint64
	prevStatsAt    time.Time
	probeAt        time.Time
	probeOK        bool
	probeStatus    string
	probeLatencyMs int64
	pingLatencyMs  int64
	probeCount     uint64
	probeFailCount uint64
	connectAttempt uint64
	connectFails   uint64

	// active resources, only valid while StateUp/StateDegraded
	device *device.Device
	netNet *netstack.Net
}

// NewTunnel constructs an idle Tunnel. Call Run to start it.
//
// The Listen field on cfg is ignored — Tunnel owns no listener. Pass
// the listener address to a SocksListener (or equivalent) instead.
func NewTunnel(cfg CityConfig, pia *PIAClient) *Tunnel {
	prefix := fmt.Sprintf("[%s] ", cfg.City)
	return &Tunnel{
		cfg:    cfg,
		pia:    pia,
		logger: log.New(log.Writer(), prefix, log.LstdFlags),
		state:  StateIdle,
	}
}

// Cfg returns the static configuration this tunnel was created with.
func (t *Tunnel) Cfg() CityConfig { return t.cfg }

// Netstack returns the gVisor netstack adapter currently powering the
// outbound side of this tunnel, or nil if the tunnel isn't currently
// up. Callers MUST call Netstack() afresh for each new flow they want
// to dial out; don't cache the pointer across flows. Prefer Dial(...)
// which handles the lifecycle and returns ErrTunnelDown cleanly.
func (t *Tunnel) Netstack() *netstack.Net {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return t.netNet
}

// Dial opens a new connection through the tunnel. Returns ErrTunnelDown
// if the tunnel is not currently up. network/addr semantics are the
// same as net.Dial; addr must be an IP:port (DNS resolution is the
// caller's responsibility, since the SOCKS5/wgserver layers each have
// their own DNS-override policies).
func (t *Tunnel) Dial(ctx context.Context, network, addr string) (net.Conn, error) {
	t.mu.RLock()
	n := t.netNet
	t.mu.RUnlock()
	if n == nil {
		return nil, ErrTunnelDown
	}
	return n.DialContext(ctx, network, addr)
}

// Run blocks until ctx is canceled, repeatedly bringing up the tunnel
// after bring-up failures with backoff.
//
// Backoff is exponential (2s → 60s) for normal failures, but a much
// longer fixed cooldown is used when PIA returns HTTP 429: continuing
// to retry every 60s extends their lockout window indefinitely. The
// cooldown honors the server's Retry-After header when present, with
// a 5-minute floor.
//
// Once the tunnel reaches StateUp, runOnce blocks until ctx is
// canceled — runtime handshake failures demote to StateDegraded but
// do not, by themselves, trigger a tunnel rebuild (matching the
// pre-split Proxy behavior). Cellular flap, region change, etc. are
// handled by the embedder canceling ctx and starting a fresh Tunnel.
func (t *Tunnel) Run(ctx context.Context) {
	backoff := 2 * time.Second
	const maxBackoff = 60 * time.Second
	const rateLimitFloor = 5 * time.Minute

	for {
		if ctx.Err() != nil {
			return
		}
		err := t.runOnce(ctx)
		if ctx.Err() != nil {
			return
		}
		atomic.AddUint64(&t.connectFails, 1)
		t.setError(err)

		var delay time.Duration
		var rl *RateLimitError
		if errors.As(err, &rl) {
			delay = rl.RetryAfter
			if delay < rateLimitFloor {
				delay = rateLimitFloor
			}
			backoff = 2 * time.Second // reset normal exponential
			t.logger.Printf("session ended (rate-limited by PIA): %v; cooling down for %s", err, delay)
		} else {
			delay = backoff
			t.logger.Printf("session ended: %v; reconnecting in %s", err, backoff)
			backoff *= 2
			if backoff > maxBackoff {
				backoff = maxBackoff
			}
		}

		select {
		case <-ctx.Done():
			return
		case <-time.After(delay):
		}
	}
}

// runOnce establishes one WireGuard session, runs until ctx is
// canceled or bring-up fails, then tears it down.
func (t *Tunnel) runOnce(ctx context.Context) error {
	atomic.AddUint64(&t.connectAttempt, 1)
	t.setState(StateConnecting, "")

	// 1. Find region.
	region, err := t.pia.FindRegion(ctx, t.cfg.Region)
	if err != nil {
		return fmt.Errorf("region lookup: %w", err)
	}

	// 2. Register a fresh peer with PIA.
	//
	// Strategy:
	//   a) if CityConfig.PreferredServer is set AND that CN/IP is still
	//      in the region's WG list, addKey to it directly. This keeps
	//      the same server across reconnects, which lets our cached
	//      auth token short-circuit /token entirely AND gives the user
	//      a stable exit IP.
	//   b) on auth failure to the preferred server, fall back to a
	//      random pick (the auth failure invalidated our token, so the
	//      random pick will refresh it).
	//   c) on any other failure, log and try a random pick once before
	//      giving up.
	var session *WGSession
	regCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	if pref := t.preferredServerInRegion(region); pref != nil {
		t.logger.Printf("trying preferred server %s (%s)", pref.CN, pref.IP)
		session, err = t.pia.NewSessionWithServer(regCtx, region, *pref)
		if err != nil {
			t.logger.Printf("preferred server %s failed: %v; falling back to random", pref.CN, err)
			session = nil
		}
	}
	if session == nil {
		session, err = t.pia.NewSession(regCtx, region)
	}
	cancel()
	if err != nil {
		return fmt.Errorf("addKey: %w", err)
	}
	t.logger.Printf("registered: server=%s (%s) peer=%s", session.Server.CN, session.Server.IP, session.PeerIP)
	t.mu.Lock()
	t.addKeyAt = time.Now()
	t.mu.Unlock()

	// 3. Build netstack TUN.
	peerAddr, ok := netip.AddrFromSlice(session.PeerIP.To4())
	if !ok || !peerAddr.IsValid() {
		return fmt.Errorf("invalid peer IP %v", session.PeerIP)
	}
	dnsAddrs := make([]netip.Addr, 0, len(session.DNSServers))
	for _, ip := range session.DNSServers {
		v4 := ip.To4()
		if v4 == nil {
			continue
		}
		a, ok := netip.AddrFromSlice(v4)
		if ok {
			dnsAddrs = append(dnsAddrs, a)
		}
	}
	if len(dnsAddrs) == 0 {
		// PIA tunnel DNS as fallback.
		dnsAddrs = append(dnsAddrs, netip.MustParseAddr("10.0.0.243"))
	}

	tunDev, netNet, err := netstack.CreateNetTUN([]netip.Addr{peerAddr}, dnsAddrs, 1420)
	if err != nil {
		return fmt.Errorf("create netstack tun: %w", err)
	}

	// 4. WireGuard userspace device. The Bind defaults to the standard
	// dual-stack listener; the Android variant injects a Bind that pins
	// each outer UDP socket to the cellular Network.
	wgLogger := device.NewLogger(device.LogLevelError, fmt.Sprintf("[%s/wg] ", t.cfg.City))
	bind := t.Bind
	if bind == nil {
		bind = conn.NewDefaultBind()
	}
	dev := device.NewDevice(tunDev, bind, wgLogger)

	ipc, err := session.IPCConfig()
	if err != nil {
		dev.Close()
		return fmt.Errorf("build ipc config: %w", err)
	}
	if err := dev.IpcSet(ipc); err != nil {
		dev.Close()
		return fmt.Errorf("ipc set: %w", err)
	}
	if err := dev.Up(); err != nil {
		dev.Close()
		return fmt.Errorf("wg up: %w", err)
	}

	// 5. Publish state and start background loops.
	t.mu.Lock()
	t.state = StateUp
	t.lastError = ""
	t.session = session
	t.connectedAt = time.Now()
	t.device = dev
	t.netNet = netNet
	t.prevRx, t.prevTx = 0, 0
	t.rxTotal, t.txTotal = 0, 0
	t.rxRate, t.txRate = 0, 0
	t.prevStatsAt = time.Now()
	t.lastHandshake = time.Time{}
	t.probeOK = false
	t.probeStatus = ""
	t.mu.Unlock()
	t.logger.Printf("tunnel up: server=%s peer=%s", session.Server.CN, session.PeerIP)

	// Cleanup on exit. Clear netstack first so concurrent Dial callers
	// see ErrTunnelDown rather than a closed-device panic, then close
	// the device.
	defer func() {
		t.mu.Lock()
		wasUp := t.state == StateUp || t.state == StateDegraded
		t.netNet = nil
		t.device = nil
		t.session = nil
		// Only mark Error if we weren't asked to shut down cleanly;
		// the outer Run() loop will overwrite anyway, but a clean
		// ctx cancel shouldn't look like a failure mid-snapshot.
		if ctx.Err() == nil {
			t.state = StateError
		} else if wasUp {
			t.state = StateIdle
		}
		t.mu.Unlock()
		dev.Close()
	}()

	loopCtx, loopCancel := context.WithCancel(ctx)
	defer loopCancel()

	var wg sync.WaitGroup
	wg.Add(2)
	go func() { defer wg.Done(); t.statsLoop(loopCtx, dev) }()
	go func() { defer wg.Done(); t.healthLoop(loopCtx, netNet) }()

	<-loopCtx.Done()
	wg.Wait()
	return ctx.Err()
}

// preferredServerInRegion returns a pointer to the matching entry in
// region.WireGuardServers if CityConfig.PreferredServer is set and that
// CN (or IP if CN is empty) is in the region's current server list.
// Returns nil if no preference is set or the preferred server is no
// longer offered by the region.
func (t *Tunnel) preferredServerInRegion(region *Region) *ServerEndpoint {
	pref := t.cfg.PreferredServer
	if pref.CN == "" && pref.IP == "" {
		return nil
	}
	for i := range region.WireGuardServers {
		s := &region.WireGuardServers[i]
		if pref.CN != "" && strings.EqualFold(s.CN, pref.CN) {
			return s
		}
		if pref.CN == "" && s.IP == pref.IP {
			return s
		}
	}
	return nil
}

// statsLoop polls the wg device for byte counters and last handshake.
func (t *Tunnel) statsLoop(ctx context.Context, dev *device.Device) {
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
		raw, err := dev.IpcGet()
		if err != nil {
			continue
		}
		var rx, tx uint64
		var hsSec int64
		for _, line := range strings.Split(raw, "\n") {
			line = strings.TrimSpace(line)
			k, v, ok := strings.Cut(line, "=")
			if !ok {
				continue
			}
			switch k {
			case "rx_bytes":
				rx, _ = strconv.ParseUint(v, 10, 64)
			case "tx_bytes":
				tx, _ = strconv.ParseUint(v, 10, 64)
			case "last_handshake_time_sec":
				hsSec, _ = strconv.ParseInt(v, 10, 64)
			}
		}
		now := time.Now()
		t.mu.Lock()
		dt := now.Sub(t.prevStatsAt).Seconds()
		if dt > 0 && (t.prevRx != 0 || t.prevTx != 0) {
			// Smooth with EMA so the bar doesn't jitter wildly.
			rxInst := float64(rx-t.prevRx) / dt
			txInst := float64(tx-t.prevTx) / dt
			alpha := 0.4
			t.rxRate = alpha*rxInst + (1-alpha)*t.rxRate
			t.txRate = alpha*txInst + (1-alpha)*t.txRate
		}
		t.prevRx, t.prevTx = rx, tx
		t.prevStatsAt = now
		t.rxTotal, t.txTotal = rx, tx
		if hsSec > 0 {
			t.lastHandshake = time.Unix(hsSec, 0)
		}
		// Demote to Degraded if handshake is older than 3 minutes.
		if t.state == StateUp && hsSec > 0 && time.Since(t.lastHandshake) > 3*time.Minute {
			t.state = StateDegraded
			t.lastError = "stale handshake"
		} else if t.state == StateDegraded && hsSec > 0 && time.Since(t.lastHandshake) <= 3*time.Minute {
			t.state = StateUp
			t.lastError = ""
		}
		t.mu.Unlock()
	}
}

// healthLoop runs HTTP probes and TCP-ping latency through the tunnel.
func (t *Tunnel) healthLoop(ctx context.Context, n *netstack.Net) {
	httpClient := &http.Client{
		Timeout: 8 * time.Second,
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
				return n.DialContext(ctx, network, address)
			},
			DisableKeepAlives:     true,
			ResponseHeaderTimeout: 6 * time.Second,
		},
	}

	// First probe runs after a small delay so the handshake can complete.
	timer := time.NewTimer(5 * time.Second)
	defer timer.Stop()

	probeURLs := []string{
		"http://www.gstatic.com/generate_204",
		"http://www.msftconnecttest.com/connecttest.txt",
	}
	idx := 0

	for {
		select {
		case <-ctx.Done():
			return
		case <-timer.C:
		}

		// HTTP probe.
		probeURL := probeURLs[idx%len(probeURLs)]
		idx++
		atomic.AddUint64(&t.probeCount, 1)
		start := time.Now()
		ok, status := doProbe(ctx, httpClient, probeURL)
		probeLatency := time.Since(start).Milliseconds()
		if !ok {
			atomic.AddUint64(&t.probeFailCount, 1)
		}

		// TCP "ping" to a stable IP+port to measure tunnel latency
		// independent of DNS / TLS.
		pingLatency := tcpPing(ctx, n, "1.1.1.1:443", 4*time.Second)

		t.mu.Lock()
		t.probeAt = time.Now()
		t.probeOK = ok
		t.probeStatus = status
		t.probeLatencyMs = probeLatency
		t.pingLatencyMs = pingLatency
		// If probes are consistently failing, mark degraded.
		if t.state == StateUp && !ok {
			t.state = StateDegraded
			if t.lastError == "" {
				t.lastError = "health probe failed: " + status
			}
		} else if t.state == StateDegraded && ok && time.Since(t.lastHandshake) <= 3*time.Minute {
			t.state = StateUp
			t.lastError = ""
		}
		t.mu.Unlock()

		timer.Reset(30 * time.Second)
	}
}

func doProbe(ctx context.Context, c *http.Client, url string) (bool, string) {
	ctx, cancel := context.WithTimeout(ctx, 8*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return false, err.Error()
	}
	req.Header.Set("User-Agent", "piaproxy/health")
	resp, err := c.Do(req)
	if err != nil {
		return false, err.Error()
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 2048))
	if resp.StatusCode >= 200 && resp.StatusCode < 400 {
		return true, resp.Status
	}
	return false, resp.Status
}

func tcpPing(ctx context.Context, n *netstack.Net, hostport string, timeout time.Duration) int64 {
	dialCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	start := time.Now()
	c, err := n.DialContext(dialCtx, "tcp", hostport)
	if err != nil {
		return -1
	}
	_ = c.Close()
	return time.Since(start).Milliseconds()
}

func (t *Tunnel) setState(s State, msg string) {
	t.mu.Lock()
	t.state = s
	t.lastError = msg
	t.mu.Unlock()
}

func (t *Tunnel) setError(err error) {
	if err == nil {
		return
	}
	t.mu.Lock()
	t.state = StateError
	t.lastError = err.Error()
	t.mu.Unlock()
}

// TunnelStatus is the tunnel-only snapshot. It's a strict subset of
// the legacy Status struct (which is the merged Tunnel + Listener
// shape kept for back-compat with the piaproxyd CLI and the Android
// Java parser). Fields named here match Status verbatim so a TunnelStatus
// can be embedded into Status with no field-name remapping.
type TunnelStatus struct {
	City                  string  `json:"city"`
	Region                string  `json:"region"`
	State                 State   `json:"state"`
	LastError             string  `json:"last_error,omitempty"`
	ServerCN              string  `json:"server_cn,omitempty"`
	ServerIP              string  `json:"server_ip,omitempty"`
	ServerPort            int     `json:"server_port,omitempty"`
	PeerIP                string  `json:"peer_ip,omitempty"`
	ConnectedAtMS         int64   `json:"connected_at_ms,omitempty"`
	AddKeyAtMS            int64   `json:"addkey_at_ms,omitempty"`
	UptimeSec             int64   `json:"uptime_sec"`
	HandshakeAgoS         int64   `json:"handshake_ago_s"`
	RxBytes               uint64  `json:"rx_bytes"`
	TxBytes               uint64  `json:"tx_bytes"`
	RxRate                float64 `json:"rx_rate_bps"`
	TxRate                float64 `json:"tx_rate_bps"`
	ProbeAtMS             int64   `json:"probe_at_ms"`
	ProbeOK               bool    `json:"probe_ok"`
	ProbeStatus           string  `json:"probe_status"`
	ProbeLatencyMs        int64   `json:"probe_latency_ms"`
	PingLatencyMs         int64   `json:"ping_latency_ms"`
	ProbeCount            uint64  `json:"probe_count"`
	ProbeFails            uint64  `json:"probe_fails"`
	ConnectTries          uint64  `json:"connect_tries"`
	ConnectFails          uint64  `json:"connect_fails"`
	AuthToken             string  `json:"auth_token,omitempty"`
	AuthTokenAcquiredAtMS int64   `json:"auth_token_acquired_at_ms,omitempty"`
}

// Snapshot returns a copy of the current tunnel state.
func (t *Tunnel) Snapshot() TunnelStatus {
	t.mu.RLock()
	defer t.mu.RUnlock()
	s := TunnelStatus{
		City:           t.cfg.City,
		Region:         t.cfg.Region,
		State:          t.state,
		LastError:      t.lastError,
		RxBytes:        t.rxTotal,
		TxBytes:        t.txTotal,
		RxRate:         t.rxRate,
		TxRate:         t.txRate,
		ProbeOK:        t.probeOK,
		ProbeStatus:    t.probeStatus,
		ProbeLatencyMs: t.probeLatencyMs,
		PingLatencyMs:  t.pingLatencyMs,
		ProbeCount:     atomic.LoadUint64(&t.probeCount),
		ProbeFails:     atomic.LoadUint64(&t.probeFailCount),
		ConnectTries:   atomic.LoadUint64(&t.connectAttempt),
		ConnectFails:   atomic.LoadUint64(&t.connectFails),
	}
	if !t.connectedAt.IsZero() && (t.state == StateUp || t.state == StateDegraded) {
		s.ConnectedAtMS = t.connectedAt.UnixMilli()
		s.UptimeSec = int64(time.Since(t.connectedAt).Seconds())
	}
	if !t.lastHandshake.IsZero() {
		s.HandshakeAgoS = int64(time.Since(t.lastHandshake).Seconds())
	} else {
		s.HandshakeAgoS = -1
	}
	if !t.probeAt.IsZero() {
		s.ProbeAtMS = t.probeAt.UnixMilli()
	}
	if t.session != nil {
		s.ServerCN = t.session.Server.CN
		s.ServerIP = t.session.Server.IP
		s.ServerPort = t.session.Server.Port
		if t.session.PeerIP != nil {
			s.PeerIP = t.session.PeerIP.String()
		}
	}
	if !t.addKeyAt.IsZero() {
		s.AddKeyAtMS = t.addKeyAt.UnixMilli()
	}
	if t.pia != nil {
		token, acquiredAt := t.pia.GetToken()
		s.AuthToken = token
		if !acquiredAt.IsZero() {
			s.AuthTokenAcquiredAtMS = acquiredAt.UnixMilli()
		}
	}
	return s
}
