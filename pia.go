// PIA (Private Internet Access) client.
//
// It performs token auth, fetches the WireGuard server list, and
// registers a freshly-generated public key with a chosen server to
// obtain a usable WireGuard session.
package piaproxy

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/curve25519"
)

// RateLimitError indicates the PIA API returned HTTP 429 Too Many
// Requests. Callers (notably the reconnect loop in proxy.go) should
// treat this specially and back off for at least a few minutes; the
// usual exponential reconnect schedule keeps hammering the auth
// endpoint and only extends the lockout window.
type RateLimitError struct {
	Endpoint   string        // e.g. "token" or "addKey"
	Status     string        // HTTP status line ("429 Too Many Requests")
	Body       string        // response body (truncated)
	RetryAfter time.Duration // parsed from Retry-After header, 0 if absent
}

func (e *RateLimitError) Error() string {
	if e.RetryAfter > 0 {
		return fmt.Sprintf("rate-limited by PIA %s endpoint: %s (retry-after %s): %s",
			e.Endpoint, e.Status, e.RetryAfter, e.Body)
	}
	return fmt.Sprintf("rate-limited by PIA %s endpoint: %s: %s",
		e.Endpoint, e.Status, e.Body)
}

// AuthError indicates the PIA API returned HTTP 401 / 403, meaning the
// supplied credentials or bearer token were rejected. This is the only
// reason we should ever invalidate a cached auth token: a network
// timeout, a 5xx, or a 429 must NOT trigger re-auth (it'd just hammer
// the heavily-rate-limited /token endpoint with the same bad creds).
type AuthError struct {
	Endpoint string // "token" or "addKey"
	Status   string
	Body     string
}

func (e *AuthError) Error() string {
	return fmt.Sprintf("auth rejected by PIA %s endpoint: %s: %s",
		e.Endpoint, e.Status, e.Body)
}

// IsAuthError is a convenience for the common errors.As check.
func IsAuthError(err error) bool {
	var ae *AuthError
	return errors.As(err, &ae)
}

// IsRateLimitError is a convenience for the common errors.As check.
func IsRateLimitError(err error) bool {
	var rl *RateLimitError
	return errors.As(err, &rl)
}

// parseRetryAfter parses an RFC 7231 Retry-After header value (either
// delta-seconds or HTTP-date). Returns 0 if absent or unparseable.
func parseRetryAfter(h string) time.Duration {
	h = strings.TrimSpace(h)
	if h == "" {
		return 0
	}
	if secs, err := strconv.Atoi(h); err == nil && secs > 0 {
		return time.Duration(secs) * time.Second
	}
	if t, err := http.ParseTime(h); err == nil {
		if d := time.Until(t); d > 0 {
			return d
		}
	}
	return 0
}

// ServerEndpoint identifies a single WireGuard server in a region.
type ServerEndpoint struct {
	IP   string
	CN   string
	Port int
}

// Region represents one PIA region.
type Region struct {
	ID               string
	Name             string
	Country          string
	DNS              string
	PortForward      bool
	Geo              bool
	Offline          bool
	WireGuardServers []ServerEndpoint
}

// WGSession is everything we need to bring up a WireGuard tunnel.
type WGSession struct {
	Region          *Region
	Server          ServerEndpoint
	PeerIP          net.IP
	ServerPublicKey string // base64
	ServerPort      int
	DNSServers      []net.IP
	PrivateKey      string // base64
	PublicKey       string // base64
}

// PIAClient is a small stateful helper for talking to the PIA API.
// Token and Regions are cached after first use.
//
// PIA bearer tokens are valid for a long time (weeks) — they should be
// reused across reconnects, region changes, and even process restarts.
// Callers persisting state across processes should use SetToken /
// GetToken to seed the cache from disk so we don't re-hit the heavily
// rate-limited /token endpoint on every cold start.
//
// HTTPDial, when non-nil, is used as the DialContext for every HTTP
// client this PIAClient creates internally (currently /token and
// /addKey, plus addKey's TLS-on-top dial). This is how the Android
// wrapper pins those plaintext-Internet calls to the cellular network:
// without it, the OS would route the request over the default network
// (Wi-Fi when both are up), which is exactly what we don't want — that
// path looks like tethering to the carrier and partly defeats the
// purpose of the app. Non-Android callers can leave it nil.
type PIAClient struct {
	Cert     *x509.Certificate
	Username string
	Password string

	// HTTPDial is consulted by the internal http.Transports for /token
	// and /addKey. Setting it AFTER NewPIAClient is fine; each request
	// reads the field afresh.
	HTTPDial func(ctx context.Context, network, addr string) (net.Conn, error)

	mu              sync.Mutex
	token           string
	tokenAcquiredAt time.Time
	regions         []Region
}

// NewPIAClient constructs a client. cert must be the PIA root CA used to
// validate WireGuard server certificates during the addKey call.
func NewPIAClient(cert *x509.Certificate, username, password string) *PIAClient {
	return &PIAClient{Cert: cert, Username: username, Password: password}
}

// Regions returns the cached region list, fetching it once if needed.
func (c *PIAClient) Regions(ctx context.Context) ([]Region, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.regions != nil {
		return c.regions, nil
	}
	regions, err := fetchServerList(ctx)
	if err != nil {
		return nil, err
	}
	c.regions = regions
	return regions, nil
}

// FindRegion returns the region with the given (case-insensitive) ID.
func (c *PIAClient) FindRegion(ctx context.Context, id string) (*Region, error) {
	regions, err := c.Regions(ctx)
	if err != nil {
		return nil, err
	}
	for i := range regions {
		if strings.EqualFold(regions[i].ID, id) {
			return &regions[i], nil
		}
	}
	return nil, fmt.Errorf("region %q not found", id)
}

// Token returns the cached auth token, fetching one if needed.
func (c *PIAClient) Token(ctx context.Context) (string, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.token != "" {
		return c.token, nil
	}
	t, err := c.fetchAuthToken(ctx, c.Username, c.Password)
	if err != nil {
		return "", err
	}
	c.token = t
	c.tokenAcquiredAt = time.Now()
	return t, nil
}

// SetToken seeds the cached token from an external store (e.g. a Java
// SharedPreferences blob persisted by the Android wrapper). Pass the
// zero time for acquiredAt if unknown — callers should treat the
// timestamp as advisory only.
func (c *PIAClient) SetToken(token string, acquiredAt time.Time) {
	c.mu.Lock()
	c.token = token
	c.tokenAcquiredAt = acquiredAt
	c.mu.Unlock()
}

// GetToken returns the cached token and the timestamp at which it was
// acquired (or seeded via SetToken). Both zero if no token is cached.
func (c *PIAClient) GetToken() (string, time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.token, c.tokenAcquiredAt
}

// InvalidateToken drops the cached token so the next call re-auths.
// Reserve this for genuine auth failures (HTTP 401/403) — calling it on
// network errors or 429 will cause us to re-hit /token on the next try
// and extend any rate-limit window.
func (c *PIAClient) InvalidateToken() {
	c.mu.Lock()
	c.token = ""
	c.tokenAcquiredAt = time.Time{}
	c.mu.Unlock()
}

// dialFunc returns the DialContext to use for HTTP requests issued from
// this client. If the caller has injected an HTTPDial (e.g. one that
// pins to a specific Android Network), we use it; otherwise we fall
// back to a vanilla net.Dialer.
func (c *PIAClient) dialFunc() func(ctx context.Context, network, addr string) (net.Conn, error) {
	if c.HTTPDial != nil {
		return c.HTTPDial
	}
	d := &net.Dialer{Timeout: 15 * time.Second}
	return d.DialContext
}

// httpTransport returns an *http.Transport that uses dialFunc(). Each
// caller gets a fresh transport so connections aren't pooled across
// network handles (e.g. if the cellular network changes underneath).
func (c *PIAClient) httpTransport() *http.Transport {
	dial := c.dialFunc()
	return &http.Transport{
		DialContext: dial,
	}
}

// NewSession picks a random server in the given region and registers a
// fresh keypair with PIA, returning a usable session.
func (c *PIAClient) NewSession(ctx context.Context, region *Region) (*WGSession, error) {
	if len(region.WireGuardServers) == 0 {
		return nil, fmt.Errorf("region %s has no WireGuard servers", region.ID)
	}
	r, err := rand.Int(rand.Reader, big.NewInt(int64(len(region.WireGuardServers))))
	if err != nil {
		return nil, err
	}
	return c.NewSessionWithServer(ctx, region, region.WireGuardServers[int(r.Int64())])
}

// NewSessionWithServer registers a fresh keypair with the specified
// server in the given region. The server should typically come from
// region.WireGuardServers — passing an arbitrary endpoint is allowed
// (e.g. resuming with a previously-known server that has since dropped
// off the list) but the Region pointer is still required because PIA's
// post-handshake DNS comes from the region record.
//
// Token invalidation: the cached token is only dropped on AuthError
// (HTTP 401/403). Network errors, timeouts, and RateLimit errors leave
// the cached token intact, because re-fetching would just extend any
// rate-limit window without solving anything. Callers who hit AuthError
// will see the next call re-auth via /token transparently.
func (c *PIAClient) NewSessionWithServer(ctx context.Context, region *Region, server ServerEndpoint) (*WGSession, error) {
	pub, priv, err := generateWireGuardKeyPair()
	if err != nil {
		return nil, err
	}

	token, err := c.Token(ctx)
	if err != nil {
		return nil, err
	}

	wg, err := c.registerWireGuardKey(ctx, c.Cert, server.IP, server.CN, server.Port, token, pub)
	if err != nil {
		if IsAuthError(err) {
			c.InvalidateToken()
		}
		return nil, err
	}

	return &WGSession{
		Region:          region,
		Server:          server,
		PeerIP:          wg.PeerIPv4,
		ServerPublicKey: wg.ServerPublicKey,
		ServerPort:      wg.ServerPort,
		DNSServers:      wg.DNSIPv4Servers,
		PrivateKey:      priv,
		PublicKey:       pub,
	}, nil
}

// IPCConfig builds the userspace WireGuard IPC string for this session,
// suitable for passing to (*device.Device).IpcSet.
func (s *WGSession) IPCConfig() (string, error) {
	pkBytes, err := base64.StdEncoding.DecodeString(s.PrivateKey)
	if err != nil {
		return "", fmt.Errorf("invalid private key: %w", err)
	}
	peerBytes, err := base64.StdEncoding.DecodeString(s.ServerPublicKey)
	if err != nil {
		return "", fmt.Errorf("invalid server public key: %w", err)
	}

	var b strings.Builder
	b.WriteString("private_key=")
	b.WriteString(hex.EncodeToString(pkBytes))
	b.WriteByte('\n')
	b.WriteString("replace_peers=true\n")
	b.WriteString("public_key=")
	b.WriteString(hex.EncodeToString(peerBytes))
	b.WriteByte('\n')
	fmt.Fprintf(&b, "endpoint=%s:%d\n", s.Server.IP, s.ServerPort)
	b.WriteString("persistent_keepalive_interval=25\n")
	b.WriteString("replace_allowed_ips=true\n")
	b.WriteString("allowed_ip=0.0.0.0/0\n")
	b.WriteString("allowed_ip=::/0\n")
	return b.String(), nil
}

// --- internal helpers --------------------------------------------------

// LoadCertFromFile parses a certificate from a PEM or DER file.
func LoadCertFromFile(path string) (*x509.Certificate, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return ParseCertificate(data)
}

// ParseCertificate parses a single X.509 certificate from PEM or DER bytes.
// Convenient for callers (e.g. the Android variant) that ship the PIA root
// CA as an embedded asset rather than a file on disk.
func ParseCertificate(data []byte) (*x509.Certificate, error) {
	if strings.Contains(string(data), "-----BEGIN") {
		for {
			block, rest := pem.Decode(data)
			if block == nil {
				return nil, errors.New("no PEM certificate found")
			}
			if block.Type == "CERTIFICATE" {
				return x509.ParseCertificate(block.Bytes)
			}
			data = rest
		}
	}
	return x509.ParseCertificate(data)
}

func (c *PIAClient) fetchAuthToken(ctx context.Context, username, password string) (string, error) {
	form := url.Values{}
	form.Set("username", username)
	form.Set("password", password)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		"https://www.privateinternetaccess.com/api/client/v2/token",
		strings.NewReader(form.Encode()))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	client := &http.Client{Timeout: 30 * time.Second, Transport: c.httpTransport()}
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusTooManyRequests {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return "", &RateLimitError{
			Endpoint:   "token",
			Status:     resp.Status,
			Body:       string(body),
			RetryAfter: parseRetryAfter(resp.Header.Get("Retry-After")),
		}
	}
	if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return "", &AuthError{Endpoint: "token", Status: resp.Status, Body: string(body)}
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return "", fmt.Errorf("token request failed: %s: %s", resp.Status, string(body))
	}

	var payload struct {
		Token string `json:"token"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		return "", fmt.Errorf("invalid token response: %w", err)
	}
	if payload.Token == "" {
		return "", errors.New("received empty token")
	}
	return payload.Token, nil
}

// FetchRegions hits PIA's public server-list endpoint and returns the
// parsed list. No credentials or root CA are required; this is the same
// API the official client uses for its server picker.
//
// Use this from clients that need the region catalog *before* a
// PIAClient is fully configured (e.g. the Android UI populating its
// region spinner).
func FetchRegions(ctx context.Context) ([]Region, error) {
	return fetchServerList(ctx)
}

func fetchServerList(ctx context.Context) ([]Region, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet,
		"https://serverlist.piaservers.net/vpninfo/servers/v6", nil)
	if err != nil {
		return nil, err
	}
	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("server list request failed: %s", resp.Status)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	// Format is: <json>\n<signature>\n. Take the first line only.
	newline := -1
	for i, b := range body {
		if b == '\n' {
			newline = i
			break
		}
	}
	if newline == -1 {
		return nil, errors.New("invalid server list format")
	}
	jsonBytes := body[:newline]

	var root struct {
		Groups struct {
			WG []struct {
				Name  string `json:"name"`
				Ports []int  `json:"ports"`
			} `json:"wg"`
		} `json:"groups"`
		Regions []struct {
			ID          string `json:"id"`
			Name        string `json:"name"`
			Country     string `json:"country"`
			DNS         string `json:"dns"`
			PortForward bool   `json:"port_forward"`
			Geo         bool   `json:"geo"`
			Offline     bool   `json:"offline"`
			Servers     struct {
				WG []struct {
					IP string `json:"ip"`
					CN string `json:"cn"`
				} `json:"wg"`
			} `json:"servers"`
		} `json:"regions"`
	}
	if err := json.Unmarshal(jsonBytes, &root); err != nil {
		return nil, err
	}

	port := -1
	for _, g := range root.Groups.WG {
		if strings.EqualFold(g.Name, "WireGuard") && len(g.Ports) > 0 {
			port = g.Ports[0]
			break
		}
	}
	if port == -1 {
		return nil, errors.New("WireGuard port not found in server list")
	}

	regions := make([]Region, 0, len(root.Regions))
	for _, r := range root.Regions {
		servers := make([]ServerEndpoint, 0, len(r.Servers.WG))
		for _, s := range r.Servers.WG {
			servers = append(servers, ServerEndpoint{IP: s.IP, CN: s.CN, Port: port})
		}
		regions = append(regions, Region{
			ID:               r.ID,
			Name:             r.Name,
			Country:          r.Country,
			DNS:              r.DNS,
			PortForward:      r.PortForward,
			Geo:              r.Geo,
			Offline:          r.Offline,
			WireGuardServers: servers,
		})
	}
	return regions, nil
}

type wireGuardConfig struct {
	PeerIPv4        net.IP
	ServerPublicKey string
	ServerPort      int
	DNSIPv4Servers  []net.IP
}

func (c *PIAClient) registerWireGuardKey(ctx context.Context, piaCert *x509.Certificate, serverIP, serverHostname string, port int, token, publicKey string) (*wireGuardConfig, error) {
	roots := x509.NewCertPool()
	roots.AddCert(piaCert)

	tlsConfig := &tls.Config{
		ServerName:         serverHostname,
		InsecureSkipVerify: true, // we do our own verification below
		VerifyConnection: func(cs tls.ConnectionState) error {
			if len(cs.PeerCertificates) == 0 {
				return errors.New("no peer certificates")
			}
			leaf := cs.PeerCertificates[0]
			if !strings.EqualFold(leaf.Subject.CommonName, serverHostname) {
				return fmt.Errorf("certificate CN mismatch: got %q, want %q", leaf.Subject.CommonName, serverHostname)
			}
			intermediates := x509.NewCertPool()
			for _, c := range cs.PeerCertificates[1:] {
				intermediates.AddCert(c)
			}
			_, err := leaf.Verify(x509.VerifyOptions{
				Roots:         roots,
				Intermediates: intermediates,
				CurrentTime:   time.Now(),
				KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
			})
			return err
		},
	}

	dial := c.dialFunc()
	transport := &http.Transport{
		DialTLSContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			conn, err := dial(ctx, "tcp", fmt.Sprintf("%s:%d", serverIP, port))
			if err != nil {
				return nil, err
			}
			tlsConn := tls.Client(conn, tlsConfig)
			if err := tlsConn.HandshakeContext(ctx); err != nil {
				conn.Close()
				return nil, err
			}
			return tlsConn, nil
		},
	}

	endpoint := fmt.Sprintf("https://%s:%d/addKey?pt=%s&pubkey=%s",
		serverIP, port, url.QueryEscape(token), url.QueryEscape(publicKey))

	client := &http.Client{Transport: transport, Timeout: 30 * time.Second}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusTooManyRequests {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return nil, &RateLimitError{
			Endpoint:   "addKey",
			Status:     resp.Status,
			Body:       string(body),
			RetryAfter: parseRetryAfter(resp.Header.Get("Retry-After")),
		}
	}
	if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return nil, &AuthError{Endpoint: "addKey", Status: resp.Status, Body: string(body)}
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return nil, fmt.Errorf("addKey failed: %s: %s", resp.Status, string(body))
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	var payload struct {
		Status     string   `json:"status"`
		ServerIP   string   `json:"server_ip"`
		PeerIP     string   `json:"peer_ip"`
		ServerKey  string   `json:"server_key"`
		ServerPort int      `json:"server_port"`
		DNSServers []string `json:"dns_servers"`
	}
	if err := json.Unmarshal(body, &payload); err != nil {
		return nil, fmt.Errorf("invalid addKey response: %w (body=%s)", err, string(body))
	}
	if !strings.EqualFold(payload.Status, "OK") {
		return nil, fmt.Errorf("addKey returned status %q", payload.Status)
	}
	if !strings.EqualFold(payload.ServerIP, serverIP) {
		return nil, errors.New("server IP in response does not match")
	}

	peerIP := net.ParseIP(payload.PeerIP)
	if peerIP == nil {
		return nil, fmt.Errorf("invalid peer IP: %s", payload.PeerIP)
	}
	dns := make([]net.IP, 0, len(payload.DNSServers))
	for _, s := range payload.DNSServers {
		ip := net.ParseIP(s)
		if ip == nil {
			return nil, fmt.Errorf("invalid DNS server IP: %s", s)
		}
		dns = append(dns, ip)
	}
	return &wireGuardConfig{
		PeerIPv4:        peerIP,
		ServerPublicKey: payload.ServerKey,
		ServerPort:      payload.ServerPort,
		DNSIPv4Servers:  dns,
	}, nil
}

func generateWireGuardKeyPair() (string, string, error) {
	var priv [32]byte
	if _, err := io.ReadFull(rand.Reader, priv[:]); err != nil {
		return "", "", fmt.Errorf("generating private key: %w", err)
	}
	priv[0] &= 248
	priv[31] &= 127
	priv[31] |= 64
	pub, err := curve25519.X25519(priv[:], curve25519.Basepoint)
	if err != nil {
		return "", "", fmt.Errorf("deriving public key: %w", err)
	}
	return base64.StdEncoding.EncodeToString(pub),
		base64.StdEncoding.EncodeToString(priv[:]),
		nil
}
