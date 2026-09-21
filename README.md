# Sudoku Brutal Helper

A Linux/systemd Rust daemon that discovers Sudoku client IPs without relying on Sudoku log messages. It reads the server `local_port` from `/etc/sudoku/config.json`, monitors established TCP sockets through Linux `sock_diag`, applies TCP Brutal rules, and destroys existing connections so reconnects use Brutal.

The design is based on [sing-box-brutal-guard](https://github.com/love4taylor/sing-box-brutal-guard). This project manages rules only; it does not install the TCP Brutal kernel module or modify the Sudoku configuration.

Connection discovery, connection destruction, Brutal rule writes, and Brutal route installation use Linux proc/netlink interfaces directly. The daemon does not depend on external `ss`, `ip`, or `brutalctl` executables.

## Workflow

1. Read the server `local_port` from the Sudoku configuration. The helper's `listen_port` setting can override it.
2. Enumerate `ESTABLISHED` TCP sockets through `sock_diag`.
3. For each new client, write a rule to `/proc/net/tcp_brutal/rules` and install a `congctl lock brutal` route through `rtnetlink`.
4. Destroy matching Sudoku TCP sockets through `SOCK_DESTROY`.
5. Persist recent clients in an atomic state file and evict the oldest rule after `max_ips` is reached.

IPv4 clients use `/32` prefixes and IPv6 clients use `/128` prefixes. IPv4-mapped IPv6 addresses are normalized to IPv4. On restart, saved rules are restored and existing connections found during the first scan are destroyed once.

## Connection Matching

Connection destruction matches the client's peer IP and the local Sudoku listening port. These are separate socket fields, not a combined endpoint: a connection such as `local:50514 <-> 114.229.216.238:42228` is matched as `peer_ip=114.229.216.238` and `local_port=50514`. The client's ephemeral port is discovered from `sock_diag` for each exact socket and does not need to be configured.

## Requirements

| Component | Requirement |
|---|---|
| System | Linux + systemd |
| Sudoku | Server configuration at `/etc/sudoku/config.json`, using TCP transport |
| TCP Brutal | tcp-brutal 2.x kernel module loaded |
| Permissions | root or equivalent `CAP_NET_ADMIN` capability |
| Build | Rust 1.85+ |

Verify the kernel interfaces are available:

```bash
test -e /proc/net/tcp_brutal/rules
test -e /proc/net/tcp
```

## Build and Test

```bash
cargo test
cargo build --release
```

The binary is written to `target/release/sudoku-brutal-helper`.

## Installation

```bash
sudo install -m 0755 target/release/sudoku-brutal-helper \
  /usr/local/bin/sudoku-brutal-helper
sudo install -m 0644 config.example.json \
  /etc/sudoku-brutal-helper.json
sudo install -m 0644 sudoku-brutal-helper.service \
  /etc/systemd/system/sudoku-brutal-helper.service

sudo systemctl daemon-reload
sudo systemctl enable --now sudoku-brutal-helper.service
```

Check the service:

```bash
systemctl status sudoku-brutal-helper.service
journalctl -u sudoku-brutal-helper.service -f -o cat
```

## Configuration

The default helper configuration is `/etc/sudoku-brutal-helper.json`. If it does not exist, built-in defaults are used.

| Field | Default | Description |
|---|---:|---|
| `sudoku_config` | `/etc/sudoku/config.json` | Sudoku server configuration path |
| `listen_port` | unset | Override Sudoku's `local_port`, useful behind a front proxy |
| `rate_mbps` | `1000` | Rate written to the Brutal kernel rule, in Mbps |
| `max_ips` | `20` | Maximum number of recent client rules |
| `poll_interval_ms` | `200` | Scan interval, from `20` to `60000` milliseconds |
| `state_file` | `/var/lib/sudoku-brutal-helper/state.json` | Persistent rule state |
| `operation_timeout_seconds` | `15` | Netlink operation timeout |

Restart after changing the configuration:

```bash
sudo systemctl restart sudoku-brutal-helper.service
```

## Manual Verification

Run one scan and print the native rule and connection-destruction actions without changing the system:

```bash
sudo ./target/debug/sudoku-brutal-helper \
  --config ./config.example.json \
  --dry-run \
  --once
```

## Notes

- Brutal rules normally take effect when a TCP connection is created, so destroying the first existing connection is intentional.
- Polling can miss connections shorter than the scan interval. Sudoku's long-lived and multiplexed connections are normally captured reliably; lower `poll_interval_ms` if needed.
- If a front proxy terminates client TCP, the helper sees the source IP presented by that proxy. Set `listen_port` to the front proxy's public listener when appropriate.
- `SOCK_DESTROY` filters by both peer IP and the Sudoku local port, so it does not destroy that IP's connections to unrelated local services. IPv4 and IPv6 socket families are scanned, including IPv4-mapped IPv6 sockets.
- This daemon handles TCP only. Sudoku UDP-over-TCP traffic is covered by its outer TCP connection.

## License

This project is licensed under the [MIT License](LICENSE).
