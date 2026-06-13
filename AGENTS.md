# Hyrule Network Proxy Agent Guide

## Purpose

`hyrule-network-proxy` is the internal Go sidecar used by Hyrule Cloud for paid x402 network requests. Hyrule Cloud owns the public API and x402 payment verification; this service only executes already-authorized internal requests.

## Security Rules

- Never expose the authenticated `/v1/*` API publicly.
- The sidecar must listen only on internal/loopback addresses in production.
- Require `Authorization: Bearer <token>` for all `/v1/*` routes.
- Never log request bodies, response bodies, payment headers, authorization headers, or cookies.
- Do not add CONNECT tunneling or arbitrary TCP proxying without a new design review.
- Do not add residential proxy support.
- Keep routing modes explicit: `direct`, `tor`, `i2p`, `yggdrasil`.

## Domain Policy

- `hyrule.host` is customer-facing Hyrule Cloud identity.
- `servify.network` is infrastructure identity for internal hosts such as `netproxy.servify.network`.
- `as215932.net` is AS215932 overlay/routing identity only.
