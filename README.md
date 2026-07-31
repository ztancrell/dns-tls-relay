# DNS-over-TLS-Relay

A fork of [DOWRIGHTTV's DNS-TLS Relay](https://github.com/DOWRIGHTTV/dns-tls-relay) with enhanced features: color output, debug logging, multi-provider resolvers, privacy hardening, self-tuning top domains heuristic, and more.

Privacy proxy converting DNS:UDP to TLS with local record caching, DNSSEC support, rate limiting, Prometheus metrics, and YAML configuration.

**Must be run as root** (use `--force` for testing).

```
usage: run_relay.py [-h] [--version] [-l listen_ip [listen_ip...]]
                    [-r resolver_ip resolver_ip] [-k {4,6,8}] [-c] [-v] [-d]
                    [-m] [--force] [--config PATH] [--workers N]
                    [--keepalive-domain DOMAIN] [--daemonize] [--syslog]
                    [--dnssec | --no-dnssec] [--rate-limit QPS] [--rate-burst N]
                    [--metrics-port PORT]
```

### Arguments

| Argument | Description |
|----------|-------------|
| `-h`, `--help` | Show help message and exit |
| `--version` | Show version and exit |
| `-l ip_addr [ip_addr...]` | List of IP addresses to listen for requests on |
| `-r ip_addr ip_addr` | List of (2) IP addresses of desired public DoT resolvers |
| `-k {4,6,8}` | Enables TLS connection keepalives (seconds interval) |
| `-c` | Print general messages to screen |
| `-v` | Print informational messages to screen |
| `-d`, `--debug` | Print debug-level messages (blue). Independent of `-v`; use both for full output. |
| `-m` | Paranoid/memory-only mode. Disables all disk persistence of the top domains cache |
| `--force` | Allow running without root (for testing) |
| `--config PATH` | Path to YAML configuration file |
| `--workers N` | Max thread pool workers (default: 32) |
| `--keepalive-domain DOMAIN` | Domain used for TLS keepalive queries (default: dnxfirewall.com) |
| `--daemonize` | Daemonize the process (fork to background) |
| `--syslog` | Log to syslog instead of stderr |
| `--dnssec` / `--no-dnssec` | Enforce DNSSEC at the upstream resolver (on by default): sets the EDNS DO bit and forces CD=0 so the upstream resolver checks signatures and returns SERVFAIL on bogus data. The relay relies on the upstream for validation; it does not verify RRSIG chains in-process. |
| `--rate-limit QPS` | Max queries per second per client IP (default: 50) |
| `--rate-burst N` | Max burst size per client IP (default: 100) |
| `--metrics-port PORT` | Prometheus metrics HTTP port (default: 9190) |

### Features

- **Multi-provider resolvers** — defaults to two different providers (Cloudflare + Quad9) rather than two IPs of the same provider
- **Color output** — magenta/blue/green/yellow/red terminal output for different log levels
- **Debug logging** (`-d`) — blue debug messages independent of verbose mode
- **Paranoid mode** (`-m`) — memory-only operation; no top-domains cache touches disk
- **Multi-timeframe top domains** — dual counters: fast-decay burst counter catches traffic spikes, slow-decay stability counter recognizes long-term patterns; combined scoring promotes domains that are either recently popular or consistently used
- **Rank-weighted churn adaptation** — burst decay rate is self-tuned using a weighted churn metric (70% top-5 changes, 30% full-set) so noise in the long tail doesn't over-sensitize the system
- **Negative caching** — NXDOMAIN/SERVFAIL responses are cached for 30s so repeat lookups for nonexistent domains never hit the upstream resolver
- **Connection pool** — one persistent TLS socket per provider stays open simultaneously; queries fan out to all active providers on cache misses, taking the first response
- **Latency-aware provider routing** — per-provider exponential moving average of response time; the best-performing provider is preferred for internal top-domain refresh and keepalive traffic
- **Privacy hardening** — EDNS0 Client Subnet stripping (RFC 7871), EDNS0 padding (RFC 8467, 128-byte block), domain noise filtering
- **Top domains persistence** — JSON-based across restarts (disabled in paranoid mode)
- **AAAA record caching** — AAAA records are now cached alongside A records to reduce WAN chatter for both address families
- **DNSSEC enforcement** (on by default; `--no-dnssec` to disable) — sets the EDNS DNSSEC OK (DO) bit and forces CD=0 on upstream queries so the validating resolver (e.g. Cloudflare/Quad9 over authenticated TLS) always checks signatures and returns SERVFAIL for bogus data. The relay relies on the upstream resolver for validation; it does not verify RRSIG chains in-process.
- **Rate limiting** (`--rate-limit`, `--rate-burst`) — token bucket per client IP to protect against DoS / accidental flooding
- **YAML configuration** (`--config PATH`) — load all settings from a config file instead of CLI flags
- **Prometheus metrics** (`--metrics-port PORT`) — HTTP endpoint exposing query counts, cache hit ratio, error count, and uptime
- **Hot-reload** — send `SIGHUP` to reload YAML config and update log levels without restarting
- **Systemd integration** — `dns-tls-relay.service` file included; supports `--daemonize` and `--syslog`
- **DNS ID randomization** — random IDs from 70–32000 per query
- **Orphaned ID cleanup** — stale DNS ID entries are automatically purged after 30 seconds
- **Configurable thread pool** — adjust worker count with `--workers` to match your hardware

### Details

If a listener IP address is not specified, the relay falls back to the loopback interface [127.0.0.1].

DNS-over-TLS resolution time is slower than standard UDP **_if a connection to the remote resolver has not already been established_**. DNS queries tend to group up as a side effect of system and relay record caching, making timeouts more likely even if the average QPS is within the timeout threshold. The `-k` keepalive option sends periodic queries to reset the resolver's timeout interval.

By default, the public resolvers are set to **Cloudflare (1.1.1.1)** and **Quad9 (9.9.9.9)** — two different providers so no single company has visibility into 100% of this relay's query history. The relay randomizes which provider is preferred on each new connection. Override with `-r`.

### Configuration File

All CLI flags can be specified in a YAML config file and loaded with `--config`:

```yaml
relay:
  listen:
    - 127.0.0.1
    - 192.168.1.1
  resolvers:
    - 1.1.1.1
    - 9.9.9.9
  keepalive: 6
  keepalive_domain: "dnxfirewall.com"
  workers: 32
  console: true
  verbose: false
  debug: false
  memory_only: false

dnssec: true
rate_limit: 50
rate_burst: 100
metrics_port: 9190
```

### Local Caching

All records are cached for a minimum of 5 minutes to improve LAN efficiency and reduce WAN chatter. The most-requested domains on your network are permanently cached (updated every 3 minutes) to guarantee a cached response for these domains.

> **Note:** The minimum TTL can cause issues with CDNs in rare cases where IPs rotate in shorter intervals. Adjust the constants in `dns_tls_constants.py` or use `-m` to avoid disk-based persistence.

### Prometheus Metrics

When the relay is running, metrics are available at `http://127.0.0.1:9190/metrics` (or the port specified with `--metrics-port`):

```
# HELP dns_relay_queries_total Total DNS queries received
# TYPE dns_relay_queries_total counter
dns_relay_queries_total 1234
# HELP dns_relay_cached_responses Total cached responses served
# TYPE dns_relay_cached_responses counter
dns_relay_cached_responses 567
```

### Systemd Installation

```bash
sudo cp dns-tls-relay.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable dns-tls-relay
sudo systemctl start dns-tls-relay
```

### Build System

```bash
pip install -r requirements.txt
pip install .  # optional: install as a system package
```
