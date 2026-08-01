# Sentinel-X Research

Defensive AVR (agentic vulnerability research) framework for Rust, Noir, and Solana bug-bounty targets.

## Status

Research monorepo with a hardened core: fixture-first (optional shallow-clone) ingest, rule-fingerprinted static discovery, structural verification gates, persisted Immunefi report shells, cooperative scan cancellation, and an operator dashboard. **Operator must validate on live scope before any bounty submission.** Sentinel-X never auto-submits.

## Monorepo layout

| Package | Role |
| --- | --- |
| `@sentinel-x/contracts` | OpenAPI-aligned types and validators |
| `@sentinel-x/storage` | SQLite persistence (Node 22 `node:sqlite`) with additive migrations |
| `@sentinel-x/agent` | Ingest → discovery → verification → reporting pipeline |
| `@sentinel-x/api` | HTTP API (`/api/*`) + optional API key auth + SSE logs |
| `@sentinel-x/dashboard` | Operator console (Vite/React) |
| `fixtures/repos/` | Sample vulnerable sources for offline scans |

## Quick start

```bash
pnpm install
pnpm run build
pnpm run test
pnpm --filter @sentinel-x/api dev          # http://localhost:8788
pnpm --filter @sentinel-x/dashboard dev    # http://localhost:5174
# or both:
pnpm dev
```

Seed a scan against the bundled Noir fixture:

```bash
curl -s localhost:8788/api/targets -H 'content-type: application/json' -d '{
  "name":"noir-sample",
  "repoUrl":"https://github.com/example/noir-sample",
  "language":"noir",
  "maxPayout":10000
}'
curl -s localhost:8788/api/scans -H 'content-type: application/json' -d '{"targetId":1}'
```

## API surface

See `lib/api-spec/openapi.yaml` — targets, scans, vulnerabilities, reports, dashboard stats, SSE scan logs.

Optional operator auth: set `API_KEY` (API) / `VITE_API_KEY` (dashboard).

## Ingest modes

1. **Fixture** (default offline): resolves `SCAN_FIXTURES_DIR` by target name/language (`noir-sample`, `rust-sample`, `solana-sample`, plus `*-safe` negative controls).
2. **Clone** (optional): shallow `git clone --depth 1` of allowlisted HTTPS hosts (`github.com`, `gitlab.com`, `bitbucket.org`, `codeberg.org`) into `WORKSPACE_CACHE_DIR`. Disable with `ALLOW_CLONE=0`.

## Elite core controls

- **Scan queue**: concurrency (`SCAN_CONCURRENCY`) + timeout (`SCAN_TIMEOUT_MS`)
- **Fingerprint dedupe**: skip re-verifying findings already verified/reported for the same target
- **Confidence lattice**: auditable fusion of base rule score + structural evidence + adapter boost + historical FP rate + prior fingerprint
- **Hypothesis engine**: constrained read-only claims (location reproduce, function blast radius) that adjust confidence before verification
- **Portfolio risk graph**: correlated findings by file/function/type (`GET /api/risk`)
- **Declarative rule packs**: JSON packs (`sentinel-core`) merge with specialized analyzers; CWE-tagged
- **Provenance ledger**: hash-chained per-scan evidence (`GET /api/provenance/:scanId`)
- **Scope firewall**: deny/allow globs on discovered files
- **Differential discovery**: when a prior commit exists, prefer changed files
- **SARIF export**: `GET /api/exports/sarif?scanId=`
- **Metrics**: `GET /api/metrics` (JSON) or `?format=prometheus`
- **Webhooks**: `WEBHOOK_URLS` (comma-separated) + optional `WEBHOOK_SECRET` signature
- **Rate limit**: token bucket via `RATE_LIMIT_PER_MINUTE`
- **Scan attestation**: HMAC-bound manifest of fingerprints + rule-pack hash (`GET /api/attestations/:scanId`, `ATTESTATION_SECRET`)
- **Suppressions**: operator registry by fingerprint/rule/path (`/api/suppressions`)
- **Campaigns**: multi-target orchestration with aggregate risk (`/api/campaigns`)
- **Proof algebra**: composable Kleisli-style evidence stages with auditable trails
- **Calibration**: fixture-labeled reliability diagram + Brier score (`GET /api/calibration`)
- **Causality DAG**: enablement/co-location graph (`GET /api/causality/:language`)
- **Operator challenge**: dual-control echo gate before `reported` status
- **Attention ranking**: information-gain / entropy ordering for operator review (`GET /api/attention/:scanId`)
- **Feedback priors**: Beta updates from reported vs false_positive (`GET /api/priors`)
- **Commit-reveal reviews**: blinded operator notes (`POST /api/reviews/commit|reveal`)
- **Shadow dual-run**: specialized vs declarative pack agreement (`GET /api/shadow/:language`)
- **Campaign Merkle lineage**: attestation rollup (`GET /api/campaigns/:id/lineage`)
- **Audit trail**: operator actions at `GET /api/audit`
- **Tool adapters** (opt-in): `ENABLE_TOOL_ADAPTERS=1` runs `cargo`/`nargo`/`anchor` when present — never invents tool output
- **Request IDs**: every response carries `X-Request-Id`
- **Docker**: `docker compose up --build` serves the API

## Honesty bounds

- Analyzers are static rule packs with fingerprints — not a full formal verifier.
- Verification is a bounded structural/confidence gate, not automated exploit execution.
- Reports are operator-facing shells; live-scope validation remains mandatory.

## Kinhold

Listed on the Kinhold vending wall as a repository-backed Provision lane.
