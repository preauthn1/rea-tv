# REA TV

REA TV is an Android TV client for a controlled REA backend. It presents REA's evidence-first investigation workflow on a D-Pad-friendly large-screen interface.

## Scope

This repository is the Flutter client. It does **not** execute JADX, Ghidra, APKs, native binaries, arbitrary shell commands, or MCP providers on the TV. Those remain backend responsibilities.

Current client slice:

- Android TV landscape and Leanback launcher metadata
- D-Pad/Select shortcut path and visible focusable navigation
- Backend URL persistence
- Capability-family discovery
- Bounded analysis submission
- Backend capability-family discovery with concrete REA operation mapping
- JSON parameter editor with operation-specific templates and help text
- Evidence detail dialog with target, operation, confidence, authority, limitations, location and normalized result
- Explicit empty, loading and error states

Backend contract: [`BACKEND_CONTRACT.md`](BACKEND_CONTRACT.md)

Product constraints: [`PRODUCT.md`](PRODUCT.md)

## Development

Requires Flutter stable and Android SDK:

```bash
flutter pub get
flutter analyze
```

The project is designed for GitHub Actions Android builds. Do not treat a source-level analyze result as proof of device acceptance.

## REA source mapping

The client maps to the upstream REA contracts and services rather than copying analysis engines:

- Android tools: `src/server/registerAndroidTools.ts`
- Flutter tools: `src/server/registerFlutterTools.ts`
- Evidence schema: `src/domain/evidence.ts`
- MCP server composition: `src/server/createServer.ts`

Upstream project: https://github.com/morluto/rea
