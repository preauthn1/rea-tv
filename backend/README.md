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

This is a development adapter, not a production deployment boundary. It needs authentication, target admission, persistent evidence storage, cancellation, and a more complete parameter-to-CLI mapping before exposure outside a controlled network.
