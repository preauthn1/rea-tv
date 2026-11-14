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
- `GET /api/evidence?limit=50`

The adapter invokes REA's existing CLI dispatcher with `--json`, records the returned result as Evidence, and keeps a bounded in-memory evidence list.

This is a development adapter, not a public deployment boundary. It binds to loopback by default. Set `REA_BACKEND_TOKEN` to require `Authorization: Bearer <token>` on every endpoint. `REA_BACKEND_HOST` must be changed deliberately if a reverse proxy or another host needs to reach it. Before production use, add persistent evidence storage, cancellation, target-root admission, rate limits, and a complete parameter-to-CLI mapping.