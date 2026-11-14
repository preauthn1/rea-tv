# REA TV backend adapter

This directory contains the first concrete adapter between the Flutter TV client and the upstream REA CLI.

## Run

From this directory, with the upstream REA checkout available:

```bash
REA_ROOT=/absolute/path/to/rea node backend/rea-backend.mjs
```

The adapter exposes:

- `GET /api/capabilities`
- `POST /api/analyses`
- `GET /api/analyses/:id`
- `GET /api/mihomo/status`
- `GET /api/mihomo/proxies`
- `PUT /api/mihomo/proxies/:group` with `{ "name": "node" }`
- `GET /api/mihomo/connections`
- `DELETE /api/mihomo/connections`
- `GET /api/mihomo/rules`
- `PATCH /api/mihomo/configs`

These routes require the same backend Bearer token. The mihomo Controller itself is configured separately through `MIHOMO_CONTROLLER_URL` and `MIHOMO_SECRET`; it is never exposed by the Flutter client.

This is a development adapter, not a public deployment boundary. It binds to loopback by default. Set `REA_BACKEND_TOKEN` to require `Authorization: Bearer <token>` on every endpoint. `REA_BACKEND_HOST` must be changed deliberately if a reverse proxy or another host needs to reach it. Before production use, add persistent evidence storage, cancellation, target-root admission, rate limits, and a complete parameter-to-CLI mapping.