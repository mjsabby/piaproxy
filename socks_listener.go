// socks_listener.go: SOCKS5 listener that consumes a Tunnel.
//
// SocksListener is the "Wi-Fi side" of the split architecture: it
// owns a TCP listener bound to some local address (typically the
// phone's Wi-Fi v4 on Android, or 127.0.0.1 on the CLI) and forwards
// every accepted client connection through the supplied Tunnel.
//
// Lifecycle is independent of the tunnel:
//
//	t := NewTunnel(cfg, pia); go t.Run(ctx)
//	l := NewSocksListener(t, "192.168.1.50:1080", SocksOpts{})
//	if err := l.Start(ctx); err != nil { ... }
//	... later ...
//	_ = l.Stop()                       // detach, e.g. on Wi-Fi loss
//	... later ...
//	_ = l.Start(ctx)                   // re-attach when Wi-Fi returns
//
// A listener can be Start/Stop-ed many times. Each Start opens a
// fresh net.Listener; each Stop closes it and drains active client
// connections. The listener never holds a netstack pointer of its
// own — every accepted connection calls Tunnel.Dial, which returns
// ErrTunnelDown if the tunnel happens to be cycling at that moment;
// the SOCKS5 reply for that is a "host unreachable" code so clients
// see a normal failure rather than a hang.
package piaproxy

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net"
	"sync"
)

// SocksOpts is the set of optional configuration for a SocksListener.
// All fields are optional and default to zero values.
type SocksOpts struct {
	// Username and Password, if both non-empty, enable RFC1929
	// username/password authentication. Leave empty for an
	// unauthenticated listener (fine on a private LAN).
	Username string
	Password string

	// DNSResolverIP, if non-zero, overrides hostname resolution for
	// SOCKS5 requests: hostnames are resolved against this IP (over
	// the tunnel) instead of the OS resolver / PIA's pushed DNS.
	// Equivalent to the DNS_IP env var on the CLI. Used for forcing
	// a specific resolver visible to dnsleaktest-style sites.
	DNSResolverIP net.IP

	// Logf optionally specifies the logger to use. If nil, the
	// tunnel's logger prefix is used.
	Logf Logf
}

// SocksListener is a Wi-Fi-side SOCKS5 listener that forwards every
// accepted connection through the bound Tunnel.
type SocksListener struct {
	tunnel *Tunnel
	addr   string
	opts   SocksOpts

	mu       sync.Mutex
	listener net.Listener
	server   *Server
	cancel   context.CancelFunc
	done     chan struct{}
	started  bool
	startErr error
}

// NewSocksListener constructs a stopped SocksListener bound to addr
// (host:port). Call Start to bind the socket and begin serving.
func NewSocksListener(t *Tunnel, addr string, opts SocksOpts) *SocksListener {
	return &SocksListener{tunnel: t, addr: addr, opts: opts}
}

// Addr returns the listener address the SocksListener was constructed
// with. After Start succeeds this is the actual bound address (may
// differ in port if the port was 0). Empty if never started.
func (l *SocksListener) Addr() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.listener != nil {
		return l.listener.Addr().String()
	}
	return l.addr
}

// Start binds the listener and begins serving. Returns an error if
// the bind fails (e.g. address in use, unbindable IP). Idempotent:
// calling Start on an already-running listener returns nil. Calling
// Start after Stop opens a fresh listener.
//
// ctx controls only the listener's lifetime; the tunnel's lifetime
// is independent.
func (l *SocksListener) Start(ctx context.Context) error {
	l.mu.Lock()
	if l.started {
		l.mu.Unlock()
		return nil
	}

	ln, err := net.Listen("tcp", l.addr)
	if err != nil {
		l.startErr = err
		l.mu.Unlock()
		return fmt.Errorf("listen on %s: %w", l.addr, err)
	}

	dnsOverride := l.buildDNSOverride()
	srv := &Server{
		Logf:     l.logf,
		Username: l.opts.Username,
		Password: l.opts.Password,
		Dialer: func(dialCtx context.Context, network, address string) (net.Conn, error) {
			if dnsOverride != nil {
				host, port, splitErr := net.SplitHostPort(address)
				if splitErr == nil && net.ParseIP(host) == nil {
					// Tunnel is IPv4-only (CreateNetTUN was given an
					// IPv4 peer address), so AAAA answers are
					// unroutable. Force A-record lookups.
					ips, err := dnsOverride.LookupIP(dialCtx, "ip4", host)
					if err != nil {
						return nil, fmt.Errorf("dns lookup %s via override: %w", host, err)
					}
					if len(ips) == 0 {
						return nil, fmt.Errorf("dns lookup %s via override: no A records", host)
					}
					address = net.JoinHostPort(ips[0].String(), port)
				}
			}
			return l.tunnel.Dial(dialCtx, network, address)
		},
	}

	listenerCtx, cancel := context.WithCancel(ctx)
	done := make(chan struct{})

	l.listener = ln
	l.server = srv
	l.cancel = cancel
	l.done = done
	l.started = true
	l.startErr = nil
	addr := ln.Addr().String()
	l.mu.Unlock()

	// Close the listener if the listener ctx is canceled.
	go func() {
		<-listenerCtx.Done()
		_ = ln.Close()
	}()

	// Run Accept loop.
	go func() {
		defer close(done)
		err := srv.Serve(ln)
		if err != nil && !errors.Is(err, net.ErrClosed) {
			l.logf("SOCKS5 serve %s: %v", addr, err)
		}
	}()

	l.logf("SOCKS5 listening on %s", addr)
	return nil
}

// Stop closes the listener and waits for active accept loops to
// drain. Idempotent: calling Stop on a non-running listener returns
// nil. Active client connections receive an immediate close of the
// accept side but are not themselves forcibly aborted — they finish
// their current request and then close on the next read.
func (l *SocksListener) Stop() error {
	l.mu.Lock()
	if !l.started {
		l.mu.Unlock()
		return nil
	}
	cancel := l.cancel
	done := l.done
	addr := ""
	if l.listener != nil {
		addr = l.listener.Addr().String()
	}
	l.started = false
	l.listener = nil
	l.server = nil
	l.cancel = nil
	l.done = nil
	l.mu.Unlock()

	if cancel != nil {
		cancel()
	}
	if done != nil {
		<-done
	}
	if addr != "" {
		l.logf("SOCKS5 stopped on %s", addr)
	}
	return nil
}

// ListenerStatus is the SOCKS5-listener snapshot for inclusion in
// status JSON.
type ListenerStatus struct {
	// Bound is true while Start has succeeded and Stop hasn't been
	// called.
	Bound bool `json:"bound"`
	// Addr is the bound listen address (host:port), or the
	// requested address if Bound is false.
	Addr string `json:"addr,omitempty"`
	// LastError is the most recent Start failure (if any).
	LastError string `json:"last_error,omitempty"`
	// Conns is the list of currently active client connections.
	Conns []ConnInfo `json:"conns"`
}

// Snapshot returns the current listener state.
func (l *SocksListener) Snapshot() ListenerStatus {
	l.mu.Lock()
	defer l.mu.Unlock()
	s := ListenerStatus{
		Bound: l.started,
		Addr:  l.addr,
	}
	if l.listener != nil {
		s.Addr = l.listener.Addr().String()
	}
	if l.startErr != nil {
		s.LastError = l.startErr.Error()
	}
	if l.server != nil {
		s.Conns = l.server.Snapshot()
	}
	return s
}

// ActiveConnCount returns the current number of in-flight SOCKS5
// client connections. Cheap; safe to poll on health checks.
func (l *SocksListener) ActiveConnCount() int {
	l.mu.Lock()
	srv := l.server
	l.mu.Unlock()
	if srv == nil {
		return 0
	}
	srv.connsMu.Lock()
	defer srv.connsMu.Unlock()
	return len(srv.activeConns)
}

func (l *SocksListener) buildDNSOverride() *net.Resolver {
	dnsIP := l.opts.DNSResolverIP
	if dnsIP == nil {
		return nil
	}
	target := net.JoinHostPort(dnsIP.String(), "53")
	l.logf("DNS override: forcing SOCKS5 hostname resolution to %s", target)
	return &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
			return l.tunnel.Dial(ctx, network, target)
		},
	}
}

func (l *SocksListener) logf(format string, args ...any) {
	if l.opts.Logf != nil {
		l.opts.Logf(format, args...)
		return
	}
	if l.tunnel != nil && l.tunnel.logger != nil {
		l.tunnel.logger.Printf(format, args...)
		return
	}
	log.Printf(format, args...)
}
