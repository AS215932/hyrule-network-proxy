# Hyrule Network Proxy

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
