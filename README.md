# DNS-over-TLS-Relay

A fork of [DOWRIGHTTV's DNS-TLS Relay](https://github.com/DOWRIGHTTV/dns-tls-relay) with enhanced features: color output, debug logging, multi-provider resolvers, privacy hardening, self-tuning top domains heuristic, and more.

Reviewed and optimized with [OpenCode AI](https://opencode.ai).

Privacy proxy converting DNS:UDP to TLS.

**Must be run as root.**

```
usage: run_relay.py [-h] [--version] [-l listen_ip [listen_ip...]]
                    [-r resolver_ip resolver_ip] [-k {4,6,8}] [-c] [-v] [-d] [-m]
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
| `-m` | Paranoid/memory-only mode. Disables all disk persistence of the top domains cache. |

### Details

If a listener IP address is not specified, the relay falls back to the loopback interface [127.0.0.1].

DNS-over-TLS resolution time is slower than standard UDP **_if a connection to the remote resolver has not already been established_**. DNS queries tend to group up as a side effect of system and relay record caching, making timeouts more likely even if the average QPS is within the timeout threshold. The `-k` keepalive option sends periodic queries to reset the resolver's timeout interval.

By default, the public resolvers are set to **Cloudflare (1.1.1.1)** and **Quad9 (9.9.9.9)** — two different providers so no single company has visibility into 100% of this relay's query history. The relay randomizes which provider is preferred on each new connection. Override with `-r`.

### Fork Features

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
- **DNS ID randomization** — random IDs from 70–32000 per query
- **No CDN issues** — minimum TTL (5 min) and configurable constants in `dns_tls_constants.py`

### Local Caching

All records are cached for a minimum of 5 minutes to improve LAN efficiency and reduce WAN chatter. The most-requested domains on your network are permanently cached (updated every 3 minutes) to guarantee a cached response for these domains.

> **Note:** The minimum TTL can cause issues with CDNs in rare cases where IPs rotate in shorter intervals. Adjust the constants in `dns_tls_constants.py` or use `-m` to avoid disk-based persistence.
