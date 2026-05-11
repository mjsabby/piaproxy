// status.go: HTTP control server that exposes a status dashboard.
//
// Routes:
//
//	GET /            -> dashboard HTML (embedded from dashboard.html)
//	GET /api/status  -> JSON snapshot of all proxies
package main

import (
	_ "embed"
	"encoding/json"
	"net/http"
	"sort"
	"time"

	"piaproxy"
)

//go:embed dashboard.html
var dashboardHTML []byte

// StatusServer serves the dashboard.
type StatusServer struct {
	proxies []*piaproxy.Proxy
	started time.Time
}

// NewStatusServer captures the proxies for snapshotting.
func NewStatusServer(proxies []*piaproxy.Proxy) *StatusServer {
	return &StatusServer{proxies: proxies, started: time.Now()}
}

// Routes wires the handlers onto a mux.
func (s *StatusServer) Routes(mux *http.ServeMux) {
	mux.HandleFunc("/", s.handleIndex)
	mux.HandleFunc("/api/status", s.handleAPI)
}

func (s *StatusServer) handleIndex(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	_, _ = w.Write(dashboardHTML)
}

type apiPayload struct {
	NowMS      int64             `json:"now_ms"`
	UptimeSec  int64             `json:"uptime_sec"`
	ProxyCount int               `json:"proxy_count"`
	UpCount    int               `json:"up_count"`
	Proxies    []piaproxy.Status `json:"proxies"`
}

func (s *StatusServer) handleAPI(w http.ResponseWriter, r *http.Request) {
	snaps := make([]piaproxy.Status, 0, len(s.proxies))
	up := 0
	for _, p := range s.proxies {
		snap := p.Snapshot()
		if snap.State == piaproxy.StateUp {
			up++
		}
		snaps = append(snaps, snap)
	}
	// Stable order by city for the UI.
	sort.Slice(snaps, func(i, j int) bool { return snaps[i].City < snaps[j].City })

	payload := apiPayload{
		NowMS:      time.Now().UnixMilli(),
		UptimeSec:  int64(time.Since(s.started).Seconds()),
		ProxyCount: len(snaps),
		UpCount:    up,
		Proxies:    snaps,
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	_ = enc.Encode(payload)
}
