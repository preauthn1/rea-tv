# REA TV backend contract v0

The Android TV client is deliberately a client, not an execution engine. The controlled backend adapts REA CLI/MCP operations to these HTTP endpoints.

## GET /api/capabilities

```json
{
  "families": [
    {"id": "android-apk", "name": "Android APK", "operations": ["inspect_android_package", "search_android_classes", "inspect_android_class"]},
    {"id": "flutter", "name": "Flutter AOT", "operations": ["identify_flutter_build", "inspect_dart_aot"]},
    {"id": "native", "name": "Native binary", "operations": ["inspect_binary_layout", "inspect_native_exports"]},
    {"id": "evidence", "name": "Evidence", "operations": ["inspect_evidence_bundle", "inspect_analysis_view"]}
  ]
}
```

## POST /api/analyses

Request:

```json
{
  "operation": "inspect_android_package",
  "target": "/targets/sample.apk",
  "parameters": {}
}
```

Response may be `202 Accepted` with an operation ID:

```json
{"analysis_id":"an-...","status":"queued"}
```

The backend should execute the bounded REA operation, preserve the exact target digest, and record Evidence.

## GET /api/analyses/:id

The TV client polls this endpoint every two seconds while a submitted operation is `queued` or `running`:

```json
{
  "analysis_id": "an-...",
  "operation": "inspect_android_package",
  "target": "/targets/sample.apk",
  "status": "running",
  "message": "JADX is indexing classes"
}
```

Terminal states are `completed` and `failed`. Once `completed`, the client refreshes `/api/evidence`.

## GET /api/evidence?limit=50

Response is a JSON array of REA Evidence records. The client consumes:

- `evidence_id`
- `operation`
- `subject.name`
- `normalized_result`
- `confidence`
- `authority`
- `limitations[]`
- `locations[]`

Tokens are stored in the platform secure storage on the client, not ordinary preferences. The backend must not expose credentials or arbitrary process output in this first client slice.

## Backend implementation mapping

A runnable development adapter is included at [`backend/rea-backend.mjs`](backend/rea-backend.mjs). It invokes the upstream REA CLI dispatcher with `--json`, maintains bounded in-memory jobs/evidence, and serves the contract endpoints. It is intentionally not an internet-facing deployment: operator authentication, target admission, persistent storage, cancellation, and complete parameter translation remain required before production use.

The existing REA source already has canonical tool contracts and registrations. Flutter-facing adapters should call the same service boundary rather than duplicate decompilers:

- `registerAndroidTools.ts`
- `registerFlutterTools.ts`
- `registerApktoolTools.ts`
- `registerNativeTools.ts`
- `registerAnalysisViewTool.ts`
- `src/domain/evidence.ts`

The backend should return the full operation list for each family. The TV client uses that list when present and falls back to a bundled catalog when discovery is unavailable. The backend should use the existing evidence schema and return `normalized_result`, not an LLM-generated summary without source evidence.
