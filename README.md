# Sentinel-X Research

Defensive AVR (agentic vulnerability research) framework for Rust, Noir, and Solana bug-bounty targets.

## Status

Experimental research monorepo. Static discovery heuristics, bounded verification harnesses, and Immunefi-formatted report shells. Operator must validate on live scope before submission.

## Monorepo layout

| Package | Role |
| --- | --- |
| `@sentinel-x/contracts` | OpenAPI-aligned types and validators |
| `@sentinel-x/storage` | SQLite persistence (Node 22 built-in) |
| `@sentinel-x/agent` | Discovery → verification → reporting pipeline |
| `@sentinel-x/api` | HTTP API (`/api/*`) |
| `fixtures/repos/` | Sample vulnerable sources for offline scans |

## Quick start

```bash
pnpm install
pnpm run build
pnpm run test
pnpm --filter @sentinel-x/api dev   # http://localhost:8788
```

## API surface

See `lib/api-spec/openapi.yaml` — targets, scans, vulnerabilities, reports, dashboard stats, SSE scan logs.

## Kinhold vending slot

Listed on the Kinhold vending wall as a repository-backed **Provision** lane. Source lives in this directory until `Kinhold/sentinel-x-research` is created as a standalone private repo.
