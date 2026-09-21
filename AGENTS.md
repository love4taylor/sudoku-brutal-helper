# AGENTS.md

## Project Overview

`sudoku-brutal-helper` is a Linux/systemd Rust daemon that applies TCP Brutal rules to clients connected to a Sudoku server.

The daemon:

1. Reads `local_port` from `/etc/sudoku/config.json` unless `listen_port` overrides it.
2. Enumerates established TCP sockets with Linux `sock_diag` netlink.
3. Writes rules directly to `/proc/net/tcp_brutal/rules`.
4. Reads the existing route and gateway from `/proc/net/route` or `/proc/net/ipv6_route`.
5. Installs and removes Brutal routes with native `rtnetlink` messages.
6. Destroys matching connections with `SOCK_DESTROY`.
7. Persists an LRU client list in an atomic JSON state file.

The implementation intentionally does not invoke external `ss`, `ip`, or `brutalctl` executables. Runtime operation requires Linux, tcp-brutal 2.x, and `CAP_NET_ADMIN` (the systemd unit runs as root with that capability).

## Repository Layout

| Path | Purpose |
|---|---|
| `src/main.rs` | CLI parsing, daemon loop, signal handling, logging |
| `src/config.rs` | Helper and Sudoku configuration loading and validation |
| `src/command.rs` | Native proc/netlink implementation for socket and Brutal operations |
| `src/guard.rs` | LRU state management, rule reconciliation, and connection activation |
| `config.example.json` | Example production configuration |
| `sudoku-brutal-helper.service` | Hardened systemd service unit |
| `README.md` | User-facing documentation |

## Setup and Dependencies

- Install Rust 1.85 or newer.
- Use the stable Rust toolchain with edition 2024 support.
- Runtime hosts must have tcp-brutal 2.x loaded and expose `/proc/net/tcp_brutal/rules`.
- Runtime operations require root or equivalent `CAP_NET_ADMIN` privileges.
- No external `ss`, `ip`, or `brutalctl` binary is required.

Fetch and lock dependencies with:

```bash
cargo check
```

Do not add generated `target/` artifacts to the repository.

## Development Workflow

Run the daemon in the foreground with a local configuration:

```bash
cargo run -- --config ./config.example.json --dry-run
```

Useful development modes:

```bash
# Scan once and exit without mutating kernel state.
cargo run -- --config ./config.example.json --dry-run --once

# Enable verbose logging through env_logger.
RUST_LOG=debug cargo run -- --config ./config.example.json --dry-run
```

The configuration must either set `listen_port` or point `sudoku_config` to a valid Sudoku server configuration containing a TCP `local_port`.

## Testing Instructions

Run the complete unit-test suite before submitting changes:

```bash
cargo test
```

Build the optimized binary:

```bash
cargo build --release
```

The current tests cover configuration parsing, IPv4/IPv6 prefix formatting, proc-route IPv4 byte-order decoding, route attribute encoding, and LRU behavior. Changes to netlink message layouts or proc-file commands should add focused tests before broader refactoring.

For a runtime smoke test that does not modify kernel state, use `--dry-run --once` against a temporary `listen_port`. A real integration test of `SOCK_DESTROY`, Brutal rule writes, or route installation must run as root on a host with tcp-brutal 2.x loaded and should never target production client traffic.

If installed, also run:

```bash
cargo fmt --check
cargo clippy --all-targets --all-features -- -D warnings
```

## Code Style

- Keep all source code, comments, CLI help, logs, and error messages in English.
- Follow standard Rust formatting and idiomatic ownership/error propagation.
- Use descriptive names; avoid one-letter variables except for conventional low-level indices.
- Prefer `anyhow::Context` at system-call, file, and configuration boundaries.
- Keep unsafe code isolated to the small libc/netlink boundary in `src/command.rs`.
- Preserve native operation: do not reintroduce shell commands or subprocess wrappers for socket, route, or Brutal operations.
- Keep public configuration fields documented in both `config.example.json` and `README.md`.
- Use atomic state-file replacement and restrictive `0600` permissions for persisted state.

## Native Linux Interfaces

When changing `src/command.rs`, preserve these compatibility requirements:

- `sock_diag` requests use `SOCK_DIAG_BY_FAMILY`, TCP protocol, and `TCP_ESTABLISHED` state filtering.
- Connection destruction uses the exact socket identity returned by netlink and `SOCK_DESTROY`.
- Brutal rules use `/proc/net/tcp_brutal/rules` command strings compatible with tcp-brutal 2.x.
- Brutal routes use protocol `233`, `congctl lock brutal`, and the route's existing gateway/output interface.
- Route discovery reads `/proc/net/route` and `/proc/net/ipv6_route`; preserve their native byte order when decoding gateways, masks, and prefixes.
- IPv4 uses `/32`; IPv6 uses `/128`; IPv4-mapped IPv6 addresses must normalize consistently for rule and destroy matching.
- Netlink failures must include an actionable error and must not silently fall back to an external command.

## Build and Deployment

Install the release binary, configuration, and service unit with:

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

After service changes, inspect the unit and logs:

```bash
systemctl status sudoku-brutal-helper.service
journalctl -u sudoku-brutal-helper.service -f -o cat
```

The service uses `ProtectSystem=strict`, `PrivateTmp=true`, and a dedicated writable `StateDirectory`. Changes that write outside `/var/lib/sudoku-brutal-helper` require an explicit review of the systemd sandbox.

## Security Considerations

- Treat all client IPs and configuration paths as untrusted input; pass values through typed netlink/proc interfaces rather than a shell.
- Do not log secrets from Sudoku configuration files.
- Do not broaden `SOCK_DESTROY` matching beyond the configured local port and the target peer IP.
- Keep `CAP_NET_ADMIN` as the only ambient capability unless a concrete kernel requirement is documented.
- State files contain client IP addresses and must remain mode `0600`.
- Test destructive connection behavior only on isolated development hosts.

## Pull Requests and Commits

- Keep changes focused on the requested behavior.
- Update `README.md`, `config.example.json`, and this file when configuration or operational behavior changes.
- Before a pull request, run `cargo test`, `cargo build --release`, and available formatting/lint checks.
- Do not commit `target/`, temporary state files, local service overrides, or host-specific configuration.
- Do not commit secrets, private keys, or production Sudoku configurations.

## Troubleshooting

| Symptom | Checks |
|---|---|
| `tcp_brutal` rules file is missing | Confirm the tcp-brutal 2.x kernel module is loaded and `/proc/net/tcp_brutal/rules` exists |
| Netlink permission errors | Run under root or grant the service `CAP_NET_ADMIN` |
| No clients are detected | Verify the Sudoku `local_port`, TCP transport, and `ESTABLISHED` socket state |
| Rules exist but traffic is not Brutal | Inspect the installed route and confirm the destination route uses `congctl lock brutal` |
| Existing clients stay connected | Check `SOCK_DESTROY` permissions and retry behavior in the service logs |
