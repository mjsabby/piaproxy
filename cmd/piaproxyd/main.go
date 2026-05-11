// piaproxy: spins up one userspace WireGuard + SOCKS5 listener per city
// against Private Internet Access, and exposes a status dashboard.
//
// Configuration is via environment variables:
//
//	PIA_USER       (required) PIA username (p########)
//	PIA_PWD        (required) PIA password
//	PIA_CERT_FILE  PIA root CA used to verify WireGuard server TLS.
//	               Default: ./ca.rsa.4096.crt
//	CONTROL_ADDR   address for the status HTTP server.
//	               Default: 127.0.0.1:9090
//	BIND_ADDR      base interface for the SOCKS5 listeners.
//	               Default: 127.0.0.1
//	BASE_PORT      first SOCKS5 port; cities use BASE_PORT+i.
//	               Default: 9091
//	PIA_REGIONS    optional override, comma-separated entries of
//	               City=region_id[:port]. Example:
//	               Seattle=us_seattle:1081,Chicago=us_chicago:1085
//	DNS_IP         optional. If set, hostnames received over SOCKS5 are
//	               resolved against this DNS server (over the tunnel)
//	               instead of PIA's pushed resolvers. Useful for forcing
//	               a specific resolver visible to dnsleaktest-style sites.
package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"piaproxy"
)

// Default city -> PIA region mapping. PIA does not have a unique region
// for every city; nearby regions are used (e.g. Portland uses
// us_oregon-pf, Dallas uses us_south_west which is named "US Texas",
// LA uses us_california, Paris uses the country-level "france" region,
// Mumbai uses the country-level "in" region).
var defaultCities = []piaproxy.CityConfig{
	{City: "Vancouver", Region: "ca_vancouver"},
	{City: "Seattle", Region: "us_seattle"},
	{City: "Portland", Region: "us_oregon-pf"},
	{City: "San Francisco", Region: "us_silicon_valley"},
	{City: "Los Angeles", Region: "us_california"},
	{City: "Denver", Region: "us_denver"},
	{City: "Dallas", Region: "us_south_west"},
	{City: "Houston", Region: "us_houston"},
	{City: "Chicago", Region: "us_chicago"},
	{City: "Atlanta", Region: "us_atlanta"},
	{City: "NYC", Region: "us_new_york_city"},
	{City: "Miami", Region: "us_florida"},
	{City: "London", Region: "uk"},
	{City: "Paris", Region: "france"},
	{City: "Mumbai", Region: "in"},
	{City: "Seoul", Region: "kr_south_korea-pf"},
	{City: "Tokyo", Region: "japan"},
	{City: "Beijing", Region: "china"},
	{City: "Singapore", Region: "sg"},
	{City: "Sydney", Region: "aus"},
	{City: "Melbourne", Region: "aus_melbourne"},
}

func main() {
	log.SetFlags(log.LstdFlags | log.Lmicroseconds)

	user := os.Getenv("PIA_USER")
	pass := os.Getenv("PIA_PWD")
	if user == "" || pass == "" {
		log.Fatal("PIA_USER and PIA_PWD must be set")
	}

	certPath := envOr("PIA_CERT_FILE", "ca.rsa.4096.crt")
	cert, err := piaproxy.LoadCertFromFile(certPath)
	if err != nil {
		log.Fatalf("read PIA cert (%s): %v\n"+
			"Download it from https://www.privateinternetaccess.com/openvpn/openvpn.zip "+
			"or the pia-foss/desktop repo (rsa_4096.crt).", certPath, err)
	}

	controlAddr := envOr("CONTROL_ADDR", "127.0.0.1:9090")
	bindAddr := envOr("BIND_ADDR", "127.0.0.1")
	basePort := envOrInt("BASE_PORT", 9091)

	cities := buildCityList(bindAddr, basePort)
	if len(cities) == 0 {
		log.Fatal("no cities configured")
	}

	pia := piaproxy.NewPIAClient(cert, user, pass)

	// Warm up auth + region list before spinning up any tunnel, so we get
	// fast feedback if credentials are wrong.
	warmCtx, warmCancel := context.WithTimeout(context.Background(), 45*time.Second)
	if _, err := pia.Token(warmCtx); err != nil {
		warmCancel()
		log.Fatalf("PIA auth failed: %v", err)
	}
	regions, err := pia.Regions(warmCtx)
	warmCancel()
	if err != nil {
		log.Fatalf("PIA server list: %v", err)
	}
	log.Printf("PIA: %d regions known, control panel on http://%s", len(regions), controlAddr)

	// Filter out cities whose region isn't in the server list.
	cities = filterUnknownRegions(cities, regions)
	if len(cities) == 0 {
		log.Fatal("no configured cities matched a known PIA region")
	}

	// SOCKS5 listeners are unauthenticated; bind them to localhost (the
	// default) unless you really know what you're doing with BIND_ADDR.
	proxies := make([]*piaproxy.Proxy, 0, len(cities))
	for _, c := range cities {
		proxies = append(proxies, piaproxy.NewProxy(c, pia))
	}

	rootCtx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	var wg sync.WaitGroup
	for _, p := range proxies {
		p := p
		wg.Add(1)
		go func() {
			defer wg.Done()
			p.Run(rootCtx)
		}()
	}

	// Status HTTP server.
	mux := http.NewServeMux()
	NewStatusServer(proxies).Routes(mux)
	httpSrv := &http.Server{
		Addr:              controlAddr,
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
	}
	go func() {
		if err := httpSrv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Fatalf("control server: %v", err)
		}
	}()

	<-rootCtx.Done()
	log.Printf("shutdown signal received, stopping…")

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = httpSrv.Shutdown(shutdownCtx)

	wg.Wait()
	log.Printf("bye")
}

func envOr(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

func envOrInt(k string, def int) int {
	if v := os.Getenv(k); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			return n
		}
	}
	return def
}

// buildCityList honors PIA_REGIONS if set, otherwise uses the defaults
// at sequential ports starting from basePort.
func buildCityList(bindAddr string, basePort int) []piaproxy.CityConfig {
	if raw := os.Getenv("PIA_REGIONS"); raw != "" {
		out := make([]piaproxy.CityConfig, 0)
		for _, entry := range strings.Split(raw, ",") {
			entry = strings.TrimSpace(entry)
			if entry == "" {
				continue
			}
			name, rest, ok := strings.Cut(entry, "=")
			if !ok {
				log.Printf("PIA_REGIONS entry %q ignored (expected City=region[:port])", entry)
				continue
			}
			region := rest
			port := basePort + len(out)
			if r, p, hasPort := strings.Cut(rest, ":"); hasPort {
				region = r
				if pn, err := strconv.Atoi(p); err == nil {
					port = pn
				}
			}
			out = append(out, piaproxy.CityConfig{
				City:   strings.TrimSpace(name),
				Region: strings.TrimSpace(region),
				Listen: net.JoinHostPort(bindAddr, strconv.Itoa(port)),
			})
		}
		return out
	}

	out := make([]piaproxy.CityConfig, 0, len(defaultCities))
	for i, c := range defaultCities {
		c.Listen = net.JoinHostPort(bindAddr, strconv.Itoa(basePort+i))
		out = append(out, c)
	}
	return out
}

func filterUnknownRegions(cities []piaproxy.CityConfig, regions []piaproxy.Region) []piaproxy.CityConfig {
	known := make(map[string]bool, len(regions))
	for _, r := range regions {
		known[strings.ToLower(r.ID)] = true
	}
	out := make([]piaproxy.CityConfig, 0, len(cities))
	for _, c := range cities {
		if !known[strings.ToLower(c.Region)] {
			fmt.Fprintf(os.Stderr, "warning: dropping %s: region %q not in PIA server list\n",
				c.City, c.Region)
			continue
		}
		out = append(out, c)
	}
	return out
}
