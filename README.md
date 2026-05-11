# piaproxy

A small Go program that brings up one userspace WireGuard tunnel **per city**
against [Private Internet Access](https://www.privateinternetaccess.com/), each
fronted by its own local **SOCKS5** listener. A status dashboard shows the live
state of every tunnel.

It runs entirely in userspace (no `TUN`/`tap` device, no root): WireGuard speaks
to a [gVisor netstack](https://pkg.go.dev/golang.zx2c4.com/wireguard/tun/netstack),
and SOCKS5 dials out through that netstack. Each city is independent, so one
flaky region doesn't take down the others.

```
client app ──SOCKS5──▶  127.0.0.1:1081 (Vancouver)  ──┐
client app ──SOCKS5──▶  127.0.0.1:1082 (Seattle)    ──┤   piaproxy
client app ──SOCKS5──▶  127.0.0.1:1083 (Portland)   ──┤   (one wg+netstack
                              …                        │    per city)
                                                        ▼
                                              PIA WireGuard servers
```

---

## Requirements

- Go ≥ 1.26 (see [go.mod](go.mod) for the exact toolchain).
- A working PIA subscription. You'll need:
  - your PIA username (the `p########` form, **not** the email),
  - your PIA password,
  - the PIA root CA, `ca.rsa.4096.crt` (see [Getting the PIA root CA](#getting-the-pia-root-ca)).
- Outbound UDP to PIA WireGuard servers (default port `1337`). The control
  channel and server-list lookup go over HTTPS.

No root/admin is required. No kernel modules. Works on Windows, Linux, and
macOS (Apple Silicon and x64).

---

## Quick start

```sh
# Put the PIA root CA next to the binary (or set PIA_CERT_FILE).
curl -sSL -o ca.rsa.4096.crt https://raw.githubusercontent.com/pia-foss/desktop/master/daemon/res/ca/rsa_4096.crt

export PIA_USER='p1234567'
export PIA_PWD='your-password'

go run ./cmd/piaproxyd
# or: go build -o piaproxy ./cmd/piaproxyd && ./piaproxy
```

Then in another shell:

```sh
# Test a specific city tunnel.
curl --socks5-hostname 127.0.0.1:9091 https://ifconfig.me
# Open the dashboard.
xdg-open http://127.0.0.1:9090   # macOS: open ...   Windows: start ...
```

The first SOCKS5 port is `BASE_PORT` (default `9091`); each subsequent city
gets `BASE_PORT+1`, `BASE_PORT+2`, … in the order listed in
[cmd/piaproxyd/main.go](cmd/piaproxyd/main.go) (`defaultCities`).

---

## Environment variables

All configuration is via env vars. Empty/unset means "use default".

| Variable        | Required | Default            | Description |
| --------------- | :------: | ------------------ | ----------- |
| `PIA_USER`      | yes      | —                  | PIA username (e.g. `p1234567`). |
| `PIA_PWD`       | yes      | —                  | PIA password. |
| `PIA_CERT_FILE` | no       | `./ca.rsa.4096.crt`| Path to the PIA root CA used to verify the WireGuard registration server's TLS cert (the cert is pinned to the server's CN, signed by this CA). |
| `CONTROL_ADDR`  | no       | `127.0.0.1:9090`   | Bind address for the status dashboard / JSON API. |
| `BIND_ADDR`     | no       | `127.0.0.1`        | Interface IP that all SOCKS5 listeners bind to. |
| `BASE_PORT`     | no       | `9091`             | First SOCKS5 port; cities use `BASE_PORT+i` (only when `PIA_REGIONS` is unset, or for entries in `PIA_REGIONS` that don't specify a port). |
| `PIA_REGIONS`   | no       | (built-in list)    | Override the city list. Comma-separated entries `City=region_id[:port]`. See below. |
| `DNS_IP`        | no       | (PIA-pushed)       | If set to an IP, hostnames received over SOCKS5 are resolved against `DNS_IP:53` (over the tunnel) instead of PIA's pushed resolvers. See [Forcing a specific DNS resolver](#forcing-a-specific-dns-resolver). |

### `PIA_REGIONS` examples

```sh
# Just two cities, custom ports:
export PIA_REGIONS='Seattle=us_seattle:1081,Chicago=us_chicago:1085'

# Auto-assigned sequential ports starting at BASE_PORT:
export PIA_REGIONS='Seattle=us_seattle,Chicago=us_chicago,Tokyo=japan'
```

`region_id` must match an ID returned by PIA's server list. To enumerate them:

```sh
curl -s https://serverlist.piaservers.net/vpninfo/servers/v6 \
  | head -c -100 | jq -r '.regions[] | .id + "\t" + .name'
```

Cities whose region is not in the live PIA server list are dropped at startup
with a warning.

### Default city → region map

| City         | PIA region        |
| ------------ | ----------------- |
| Vancouver    | `ca_vancouver`    |
| Seattle      | `us_seattle`      |
| Portland     | `us_oregon-pf`    |
| San Francisco| `us_silicon_valley`|
| Los Angeles  | `us_california`   |
| Denver       | `us_denver`       |
| Dallas       | `us_south_west`   |
| Houston      | `us_houston`      |
| Chicago      | `us_chicago`      |
| Atlanta      | `us_atlanta`      |
| NYC          | `us_new_york_city`|
| Miami        | `us_florida`      |
| London       | `uk`              |
| Paris        | `france`          |
| Mumbai       | `in`              |
| Seoul        | `kr_south_korea-pf`|
| Tokyo        | `japan`           |
| Beijing      | `china`           |
| Singapore    | `sg`              |
| Sydney       | `aus`             |
| Melbourne    | `aus_melbourne`   |

PIA does not have a unique region for every city in this list; nearby or
country-level regions are used (e.g. Paris → `france`, Mumbai → `in`).

### Forcing a specific DNS resolver

By default, hostnames received over SOCKS5 are resolved using the DNS servers
PIA pushed for the current tunnel (typically PIA's own resolvers, falling back
to `10.0.0.243`). If you want to force every lookup at a specific public
resolver — e.g. to verify on
[dnsleaktest.com](https://www.dnsleaktest.com/) or
[1.1.1.1/help](https://1.1.1.1/help) which resolver is actually answering —
set `DNS_IP`:

```sh
export DNS_IP=1.1.1.1     # or 8.8.8.8, 9.9.9.9, etc.
go run .
```

Lookups still travel through the WireGuard tunnel, so the resolver sees the
PIA exit IP, not your real one.

To make Firefox actually send hostnames over SOCKS5 (rather than resolving
them locally first), set in `about:config`:

| Pref                            | Value           |
| ------------------------------- | --------------- |
| `network.proxy.type`            | `1`             |
| `network.proxy.socks`           | `127.0.0.1`     |
| `network.proxy.socks_port`      | `9091` (or your `BASE_PORT`) |
| `network.proxy.socks_version`   | `5`             |
| `network.proxy.socks_remote_dns`| `true`          |
| `network.trr.mode`              | `5` (disable DoH so it doesn't bypass SOCKS) |

`DNS_IP` only affects hostname-form SOCKS5 destinations; IP-literal
destinations are dialed unchanged.

---

## Status dashboard & API

The control HTTP server serves:

- `GET /` — embedded HTML dashboard (see [dashboard.html](dashboard.html)).
- `GET /api/status` — JSON snapshot of every proxy.

Sample `/api/status` payload:

```json
{
  "now_ms": 1714780000000,
  "uptime_sec": 312,
  "proxy_count": 21,
  "up_count": 21,
  "proxies": [
    {
      "city": "Seattle",
      "region": "us_seattle",
      "listen": "127.0.0.1:9092",
      "state": "up",
      "...": "..."
    }
  ]
}
```

`state` is one of `idle`, `connecting`, `up`, `degraded`, `error`. A proxy
is "degraded" when WireGuard handshakes have stopped or the periodic HTTP
probe (against `gstatic.com/generate_204` / `msftconnecttest.com`) is failing
through the tunnel.

---

## Security notes — read this before changing `BIND_ADDR` or `CONTROL_ADDR`

- The **SOCKS5 listeners are unauthenticated**. They accept any connection and
  forward it through the PIA tunnel. Defaults bind to `127.0.0.1`, which is
  safe. Setting `BIND_ADDR=0.0.0.0` (all IPv4) or `::` (all IPv6/dual-stack)
  exposes an **open proxy** to anyone who can reach the host on
  `BASE_PORT..BASE_PORT+N`. Use a firewall and/or a specific interface IP if
  you need LAN access.
- The **control server is also unauthenticated** and discloses live proxy
  state (regions, server CNs/IPs, byte counters, etc.). Same advice for
  `CONTROL_ADDR`.
- `PIA_USER`/`PIA_PWD` are read from the environment. Avoid putting them on
  the command line. Prefer a `.env` file with restrictive permissions, a
  systemd unit's `EnvironmentFile=`, or a secrets manager.
- The WireGuard server's TLS certificate is verified against the PIA root CA
  in `PIA_CERT_FILE`, with the cert's CN pinned to the chosen server. Do not
  swap in an arbitrary CA bundle; use the PIA-published CA.

---

## How it works (brief)

1. Auth with `https://www.privateinternetaccess.com/api/client/v2/token` using
   `PIA_USER`/`PIA_PWD`.
2. Fetch the WireGuard server list from
   `https://serverlist.piaservers.net/vpninfo/servers/v6`.
3. For each configured city: pick a server in that region, generate a fresh
   Curve25519 keypair, and call the server's `/addKey` endpoint over TLS
   (verified against the PIA CA, hostname pinned to the server's CN).
4. Bring up a userspace WireGuard device backed by a gVisor netstack TUN.
5. Open a SOCKS5 listener on `BIND_ADDR:port` whose `Dialer` dials through the
   netstack — every connection from a SOCKS5 client exits via the tunnel.
6. Background loops poll WireGuard counters every 2 s and HTTP-probe every
   ~30 s. On failure, the tunnel is torn down and reconnected with
   exponential backoff (2 s → 60 s).

Source layout:

- [cmd/piaproxyd/main.go](cmd/piaproxyd/main.go) — entry point, env parsing, default cities.
- [pia.go](pia.go) — PIA auth, server list, key registration.
- [proxy.go](proxy.go) — per-city WireGuard + SOCKS5 lifecycle, health probes.
- [socks5.go](socks5.go) — SOCKS5 server (vendored from Tailscale, BSD-3).
- [status.go](status.go) — control HTTP server.
- [dashboard.html](dashboard.html) — embedded dashboard UI.

---

## Getting the PIA root CA

PIA publishes the CA in their open-source desktop client and OpenVPN bundle:

- `https://raw.githubusercontent.com/pia-foss/desktop/master/daemon/res/ca/rsa_4096.crt`
- bundled in `https://www.privateinternetaccess.com/openvpn/openvpn.zip`
  (extract `ca.rsa.4096.crt`).

Save it as `ca.rsa.4096.crt` next to the binary, or point `PIA_CERT_FILE`
at it.

---

## Building

```sh
go build -trimpath -o piaproxy ./cmd/piaproxyd
```

Cross-compile for any of the supported targets:

```sh
GOOS=linux   GOARCH=amd64 CGO_ENABLED=0 go build -trimpath -o piaproxy-linux-amd64 ./cmd/piaproxyd
GOOS=linux   GOARCH=arm64 CGO_ENABLED=0 go build -trimpath -o piaproxy-linux-arm64 ./cmd/piaproxyd
GOOS=windows GOARCH=amd64 CGO_ENABLED=0 go build -trimpath -o piaproxy-windows-amd64.exe ./cmd/piaproxyd
GOOS=windows GOARCH=arm64 CGO_ENABLED=0 go build -trimpath -o piaproxy-windows-arm64.exe ./cmd/piaproxyd
GOOS=darwin  GOARCH=arm64 CGO_ENABLED=0 go build -trimpath -o piaproxy-darwin-arm64 ./cmd/piaproxyd
```

CI (GitHub Actions) builds all five targets natively on the matching runner
and ships each binary alongside a debug-info sidecar (`*.debug` for
ELF/PE with `.gnu_debuglink`, `*.dwarf` unstripped copy for Mach-O). See
[.github/workflows/build.yml](.github/workflows/build.yml).

---

## Troubleshooting

- **`PIA auth failed`** — check `PIA_USER` (must be `p########`, not your
  email) and `PIA_PWD`.
- **`read PIA cert (...): no such file`** — download `ca.rsa.4096.crt` (see
  above) or point `PIA_CERT_FILE` at it.
- **`region "..." not in PIA server list`** — region IDs change occasionally;
  re-check against `https://serverlist.piaservers.net/vpninfo/servers/v6`.
- **`listen on 127.0.0.1:NNNN: bind: address already in use`** — another
  process owns the port; change `BASE_PORT` or use `PIA_REGIONS` with
  explicit ports.
- **State stuck in `degraded`** — handshake or HTTP probe failing through the
  tunnel. The dashboard shows `last_handshake` and probe status; the proxy
  will reconnect automatically on a hard failure.
- **`CONTROL_ADDR: bind: permission denied`** — likely trying to bind to a
  privileged port (<1024) without privileges; pick a higher port.

---

## License

See [LICENSE](LICENSE). [socks5.go](socks5.go) is vendored from Tailscale and
is BSD-3-Clause.
