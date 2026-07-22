# Hyrule Network Proxy Agent Guide

## Purpose

This repository builds **two separate binaries** that share the Go skeleton
(config loader, bearer-auth middleware, slog rules, Prometheus registry, CI) but
run as **distinct processes with distinct users, tokens, and charters**. They are
co-located on the `netproxy` VM but are otherwise independent.

- **`cmd/hyrule-network-proxy`** — the internal egress sidecar. Hyrule Cloud calls
  it for paid x402 network *requests* (fetch-a-URL over direct/tor/i2p/yggdrasil).
  Internal-only; never faces the Internet.
- **`cmd/hyrule-tunnel-proxy`** — the public reverse-SSH tunnel daemon
  (`internal/tunnel/*`). Hosts behind NAT dial in with `ssh -R`; visitors reach a
  public data port. This is the **sanctioned public-facing** service. Hyrule Cloud
  still owns x402 verification/settlement and mints leases via the daemon's
  internal, bearer-authed control API.

## Security Rules — egress sidecar (`hyrule-network-proxy`)

- Never expose the authenticated `/v1/*` API publicly.
- The sidecar must listen only on internal/loopback addresses in production.
- Require `Authorization: Bearer <token>` for all `/v1/*` routes.
- Never log request bodies, response bodies, payment headers, authorization headers, or cookies.
- **Do not add CONNECT tunneling or arbitrary TCP proxying to this binary** — that
  capability lives, deliberately isolated, in `hyrule-tunnel-proxy`.
- Do not add residential proxy support.
- Keep routing modes explicit: `direct`, `tor`, `i2p`, `yggdrasil`.

## Security Rules — tunnel daemon (`hyrule-tunnel-proxy`)

- The SSH username IS the x402 lease token; there is no password or public-key auth.
- Accept **only** remote (`-R`) port forwarding. Reject `direct-tcpip`
  (`ssh -L`/`-D`/SOCKS), `exec`, `shell`, and subsystems — this is the egress-abuse
  guard and the reason it is a separate binary. This rejection is covered by a Go
  test (`internal/tunnel/sshd/server_test.go`); do not weaken it.
- The control API (`internal/tunnel/control`) is the money path: bearer-authed,
  never a wildcard bind, internal-only.
- Never log lease tokens, the control bearer token, or forwarded payload bytes.
- Only the SSH intake (`:2222`), data-port range, and STUN (`:3478`) face the
  Internet; the control and metrics listeners stay internal.

## Domain Policy

- `hyrule.host` is customer-facing Hyrule Cloud identity.
- `servify.network` is infrastructure identity for internal hosts such as `netproxy.servify.network`.
- `as215932.net` is AS215932 overlay/routing identity only.
