# Hyrule Network Proxy

This repository builds **two binaries** that share a Go skeleton but run as
separate processes with separate users, tokens, and charters (see `AGENTS.md`):

- **`hyrule-network-proxy`** — the internal egress sidecar documented below.
- **`hyrule-tunnel-proxy`** — the public reverse-SSH tunnel daemon
  (`internal/tunnel/*`, `cmd/hyrule-tunnel-proxy`). See
  [Reverse-SSH tunnel daemon](#reverse-ssh-tunnel-daemon).

## Hyrule Network Proxy (egress sidecar)

Internal Go sidecar for Hyrule Cloud's x402-gated `POST /v1/network/request` endpoint.

Hyrule Cloud verifies and settles x402 payments. This service accepts only authenticated internal requests from Hyrule Cloud, applies egress policy, and dispatches requests over one of four explicit modes:

- `direct`
- `tor`
- `i2p`
- `yggdrasil`

It is not a public proxy and must not be exposed to the Internet.

## Internal API

All `/v1/*` endpoints require:

```http
Authorization: Bearer <HNP_AUTH_TOKEN>
```

### `GET /v1/health`

```json
{"status":"ok","service":"hyrule-network-proxy","version":"dev"}
```

### `GET /v1/modes`

Reports whether each mode appears usable.

### `POST /v1/request`

Request:

```json
{
  "request_id": "optional-id",
  "url": "https://example.com",
  "method": "GET",
  "headers": {"accept": "text/html"},
  "body": null,
  "proxy_mode": "direct",
  "timeout_seconds": 15
}
```

Response:

```json
{
  "status_code": 200,
  "headers": {"content-type": "text/html"},
  "body": "...",
  "elapsed_seconds": 0.12,
  "proxy_mode": "direct",
  "error": null
}
```

Handled upstream and policy failures return HTTP 200 with a `NetworkResponse` body containing `status_code` and `error`. Authentication/server failures use normal HTTP error statuses.

## Runtime Config

See `packaging/env.example`.

## Development

```bash
go test ./...
go vet ./...
go build ./cmd/hyrule-network-proxy
```

Run locally:

```bash
HNP_AUTH_TOKEN=dev-secret \
HNP_API_LISTEN_ADDR=127.0.0.1:8450 \
HNP_METRICS_LISTEN_ADDR=127.0.0.1:8451 \
go run ./cmd/hyrule-network-proxy
```

## Production Topology

```text
Hyrule Cloud API
  -> http://[netproxy]:8450/v1/request
     Authorization: Bearer <vault token>

Prometheus
  -> http://[netproxy]:8451/metrics
```

The sidecar should run on `netproxy.servify.network`, with firewall rules allowing:

- `8450/tcp` only from the `api` VM;
- `8451/tcp` only from the `mon` VM.

## Reverse-SSH tunnel daemon

`hyrule-tunnel-proxy` makes a host behind NAT publicly reachable over a raw TCP
port, priced per hour in USDC via x402. It is the productized version of the
"rescue-mode server made reachable with pinggy" workflow.

### Client usage (zero install — works from stock rescue images)

```sh
# <lease-token> is the SSH username; it comes from the x402 create response.
ssh -N -R 0:localhost:22 <lease-token>@tun.hyrule.host -p 2222
# ssh prints: "Allocated port 10234 for remote forward to localhost:22"
# The host is now reachable at tun.hyrule.host:10234
```

Use `-R 0:` (dynamic) so the client learns the server-assigned port. Raw `ssh`
does **not** auto-reconnect — wrap it in `autossh` or a `while true` loop so a
daemon restart or network blip re-establishes the tunnel.

Only remote (`-R`) forwarding is accepted. `ssh -L` / `-D` / SOCKS
(`direct-tcpip`), shells, and exec are refused — this daemon is not an egress
proxy.

### Control API (internal, Hyrule Cloud only, `Authorization: Bearer <HTP_AUTH_TOKEN>`)

- `POST /v1/leases` — create; body `{lease_id, duration_seconds, allowlist_cidrs?}`;
  returns `{lease_id, token, port, endpoint_host, ssh_port, expires_at, status}`.
  Idempotent on `lease_id`.
- `POST /v1/leases/{id}/extend` — `{duration_seconds}`.
- `DELETE /v1/leases/{id}` — revoke.
- `GET /v1/leases/{id}` / `GET /v1/leases` — status / reconcile.
- `GET /v1/health` — `{status, active_leases, free_ports}`.

### Free STUN responder

The daemon answers STUN binding requests on UDP `3478` (RFC 5389), returning the
caller's observed public IP:port. Unauthenticated and unbilled; probed by Hyrule
Cloud's `/v1/voip/check` STUN arm and the foundation for NAT-type classification.

See `packaging/env.tunnel.example` for configuration.
