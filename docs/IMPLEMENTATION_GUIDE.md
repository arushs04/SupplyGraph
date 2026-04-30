# SupplyGraph Implementation Guide

## 1. Purpose

This document explains the current SupplyGraph implementation in code terms, not just feature terms. It is meant to be read alongside the repository and should help you answer:

- what the system does today
- how data moves through the codebase
- why the schema looks the way it does
- where normalization and enrichment happen
- how the REST API is built on top of the stored data
- what parts are intentionally incomplete

The repository is now at a meaningful backend milestone:

- Syft JSON can be ingested
- package inventory is normalized and stored
- OSV vulnerabilities are fetched and persisted
- severity is normalized from CVSS vectors into score and label
- findings can be queried through a REST API

This guide focuses on what is implemented right now.

## 2. High-Level Architecture

The system has two main execution paths:

1. ingestion
2. read API

The ingestion path takes a saved Syft JSON file and a scanned asset path, normalizes package inventory, persists relational records, enriches with OSV, and stores findings.

The read path exposes the persisted data through REST endpoints for assets, scans, findings, and summaries.

At a high level:

1. Syft scans a repository or directory and writes JSON.
2. `cmd/ingest` loads that JSON.
3. `internal/syft` parses and normalizes artifacts into package identities and versions.
4. `internal/db` writes assets, scans, components, component versions, scan membership, vulnerabilities, and findings into Postgres.
5. `internal/osv` queries OSV for npm package versions.
6. `internal/severity` parses CVSS vectors into score and severity label.
7. `cmd/api` exposes REST routes backed by repository queries.

This is a deliberate split:

- write-side logic is concentrated in ingestion packages
- read-side logic is concentrated in the API and repository layer

That separation matters because it keeps the system from turning into one large CLI script.

## 3. Repository Layout

Important directories and files:

- [cmd/ingest/main.go](/Users/arushsacheti/Downloads/Arush_Job_Search/projects/SupplyGraph/cmd/ingest/main.go)
- [cmd/api/main.go](/Users/arushsacheti/Downloads/Arush_Job_Search/projects/SupplyGraph/cmd/api/main.go)
- [internal/syft/load.go](/Users/arushsacheti/Downloads/Arush_Job_Search/projects/SupplyGraph/internal/syft/load.go)
- [internal/syft/types.go](/Users/arushsacheti/Downloads/Arush_Job_Search/projects/SupplyGraph/internal/syft/types.go)
- [internal/syft/normalize.go](/Users/arushsacheti/Downloads/Arush_Job_Search/projects/SupplyGraph/internal/syft/normalize.go)
- [internal/ingest/ingest.go](/Users/arushsacheti/Downloads/Arush_Job_Search/projects/SupplyGraph/internal/ingest/ingest.go)
- [internal/osv/client.go](/Users/arushsacheti/Downloads/Arush_Job_Search/projects/SupplyGraph/internal/osv/client.go)
- [internal/osv/types.go](/Users/arushsacheti/Downloads/Arush_Job_Search/projects/SupplyGraph/internal/osv/types.go)
- [internal/severity/normalize.go](/Users/arushsacheti/Downloads/Arush_Job_Search/projects/SupplyGraph/internal/severity/normalize.go)
- [internal/db/db.go](/Users/arushsacheti/Downloads/Arush_Job_Search/projects/SupplyGraph/internal/db/db.go)
- [internal/db/repository.go](/Users/arushsacheti/Downloads/Arush_Job_Search/projects/SupplyGraph/internal/db/repository.go)
- [internal/api/server.go](/Users/arushsacheti/Downloads/Arush_Job_Search/projects/SupplyGraph/internal/api/server.go)
- [internal/model/model.go](/Users/arushsacheti/Downloads/Arush_Job_Search/projects/SupplyGraph/internal/model/model.go)
- [migrations/001_init.sql](/Users/arushsacheti/Downloads/Arush_Job_Search/projects/SupplyGraph/migrations/001_init.sql)
- [migrations/002_vulnerabilities.sql](/Users/arushsacheti/Downloads/Arush_Job_Search/projects/SupplyGraph/migrations/002_vulnerabilities.sql)
- [migrations/003_severity_normalization.sql](/Users/arushsacheti/Downloads/Arush_Job_Search/projects/SupplyGraph/migrations/003_severity_normalization.sql)

If you only read a few files to understand the system, start with:

1. `internal/model/model.go`
2. `internal/ingest/ingest.go`
3. `internal/db/repository.go`
4. `internal/api/server.go`

## 4. Domain Model

The core types are defined in [internal/model/model.go](/Users/arushsacheti/Downloads/Arush_Job_Search/projects/SupplyGraph/internal/model/model.go).

The important types are:

- `Asset`
- `Scan`
- `Component`
- `ComponentVersion`
- `Vulnerability`
- `Finding`
- `ExpandedFinding`
- `ScanSummary`
- `AssetSummary`

### 4.1 Asset

An asset is the thing being scanned.

Current asset strategy:

- `asset_type` is currently `local_path`
- `source` is the scanned filesystem path
- `name` is derived from `filepath.Base(...)`

Assets are deduplicated by:

- `(asset_type, source)`

That means the same local repo path maps to one logical asset, even across repeated scans.

### 4.2 Scan

A scan is a snapshot of an asset at a point in time.

Important fields:

- `asset_id`
- `status`
- `sbom_format`
- `started_at`
- `completed_at`

The design goal is:

- one asset
- many scans

That is why asset deduplication was important early in the project.

### 4.3 Component and ComponentVersion

This distinction is central.

`Component` is the versionless package identity:

- name
- ecosystem
- versionless purl

`ComponentVersion` is the exact installed version:

- component_id
- version

This lets the system represent:

- one package identity
- many concrete versions

That model is necessary for real package inventories and later comparison work.

### 4.4 Finding and Vulnerability

`Vulnerability` is global advisory metadata.

`Finding` is scan-specific evidence that a vulnerability affected a package version in a scan.

That distinction is also important:

- vulnerability rows are reused globally
- findings are per scan

Without that split, the system would duplicate advisory data and make aggregation much harder.

## 5. Database Schema

The schema evolved in three migrations.

### 5.1 `001_init.sql`

This migration creates the inventory model:

- `assets`
- `scans`
- `components`
- `component_versions`
- `scan_component_versions`

Important design decisions:

- `assets` are unique by `(asset_type, source)`
- `components` are unique by `purl`
- `component_versions` are unique by `(component_id, version)`
- `scan_component_versions` are unique by `(scan_id, component_version_id)`

`scan_component_versions` is the table that turns the model from “global package catalog” into “package inventory per scan.”

### 5.2 `002_vulnerabilities.sql`

This migration adds:

- `vulnerabilities`
- `findings`

Important design decisions:

- vulnerabilities are unique by `(source, external_id)`
- findings are unique by `(scan_id, component_version_id, vulnerability_id)`

That uniqueness means rerunning ingest does not multiply the same finding within the same scan.

### 5.3 `003_severity_normalization.sql`

This migration adds:

- `severity_score`
- `severity_label`

to `vulnerabilities`.

The system already stored the raw severity vector string in `severity`, but that was not enough for:

- severity filtering
- severity sorting
- bucketed summaries

Now the table stores:

- raw severity vector
- parsed numeric score
- normalized label

## 6. Syft Parsing and Normalization

Syft-specific code lives in `internal/syft`.

### 6.1 Loading

[internal/syft/load.go](/Users/arushsacheti/Downloads/Arush_Job_Search/projects/SupplyGraph/internal/syft/load.go) loads a saved Syft JSON file into typed Go structs from [internal/syft/types.go](/Users/arushsacheti/Downloads/Arush_Job_Search/projects/SupplyGraph/internal/syft/types.go).

The system currently assumes:

- scans are produced outside the app
- the app ingests saved JSON

That keeps scanner orchestration out of the initial implementation.

### 6.2 Artifact Normalization

[internal/syft/normalize.go](/Users/arushsacheti/Downloads/Arush_Job_Search/projects/SupplyGraph/internal/syft/normalize.go) converts raw Syft artifacts into `model.NormalizedArtifact`.

Normalization currently:

- skips artifacts with empty purl
- skips artifacts with missing or `UNKNOWN` version
- parses purl to extract package identity
- derives ecosystem from the purl
- creates:
  - a versionless `Component`
  - an exact `ComponentVersion`

This step is important because Syft emits many kinds of artifacts, but the DB model only wants true package-like records.

## 7. Ingestion Flow

The CLI entrypoint is [cmd/ingest/main.go](/Users/arushsacheti/Downloads/Arush_Job_Search/projects/SupplyGraph/cmd/ingest/main.go).

Most of the actual work happens in [internal/ingest/ingest.go](/Users/arushsacheti/Downloads/Arush_Job_Search/projects/SupplyGraph/internal/ingest/ingest.go).

The high-level flow is:

1. load Syft JSON
2. open DB
3. find or create asset
4. insert scan
5. persist normalized inventory
6. enrich scan with OSV

### 7.1 PersistInventory

`PersistInventory(...)` loops through raw Syft artifacts and for each normalizable package:

1. `NormalizeArtifact`
2. `FindOrCreateComponent`
3. `FindOrCreateComponentVersion`
4. `FindOrCreateScanComponentVersion`

This is the core inventory persistence path.

The result object tracks counts:

- normalized artifacts
- component upserts
- component version upserts
- scan membership upserts

These counts were useful during development for validating that the system was behaving sensibly on real Syft data.

### 7.2 EnrichScanWithOSV

`EnrichScanWithOSV(...)` loads the scan’s package inventory from the DB and enriches it through OSV.

Current behavior:

- only `npm` packages are queried
- one OSV query per package version
- results are persisted as vulnerabilities and findings

The npm-only scope is intentional. Early experiments showed that sending every ecosystem and artifact type to OSV caused invalid requests, especially around GitHub Actions-style artifacts.

That scoping keeps the enrichment path correct and explainable.

## 8. OSV Integration

OSV integration is intentionally thin.

[internal/osv/client.go](/Users/arushsacheti/Downloads/Arush_Job_Search/projects/SupplyGraph/internal/osv/client.go) posts to:

- `https://api.osv.dev/v1/query`

[internal/osv/types.go](/Users/arushsacheti/Downloads/Arush_Job_Search/projects/SupplyGraph/internal/osv/types.go) models:

- request package
- version
- returned vulnerabilities
- severity entries

The current query shape uses:

- package name
- ecosystem
- version

That matches the normalized DB model well, which is one reason the earlier schema design worked.

## 9. Severity Normalization

This is implemented in [internal/severity/normalize.go](/Users/arushsacheti/Downloads/Arush_Job_Search/projects/SupplyGraph/internal/severity/normalize.go).

The input is the raw OSV severity string, which is currently a CVSS vector like:

- `CVSS:3.1/AV:N/...`
- `CVSS:4.0/AV:N/...`

The code uses [`github.com/pandatix/go-cvss`](https://pkg.go.dev/github.com/pandatix/go-cvss) to parse:

- CVSS 3.0
- CVSS 3.1
- CVSS 4.0

The output is:

- raw string
- numeric score
- normalized label

Example result:

- raw: `CVSS:3.1/...`
- score: `7.5`
- label: `high`

If parsing fails or there is no usable severity string:

- score is `nil`
- label is `unknown`

That fallback matters because not every advisory source is guaranteed to produce a clean vector.

## 10. Repository Layer

[internal/db/repository.go](/Users/arushsacheti/Downloads/Arush_Job_Search/projects/SupplyGraph/internal/db/repository.go) is the main persistence layer.

It intentionally owns both:

- write-side upserts
- read-side queries

Important write methods:

- `FindOrCreateAsset`
- `InsertScan`
- `FindOrCreateComponent`
- `FindOrCreateComponentVersion`
- `FindOrCreateScanComponentVersion`
- `FindOrCreateVulnerability`
- `FindOrCreateFinding`

Important read methods:

- `ListAssets`
- `GetAssetByID`
- `GetScanByID`
- `ListScanPackages`
- `ListExpandedFindingsPageByScanID`
- `ListExpandedFindingsPageByAssetID`
- `GetScanSummary`
- `GetAssetSummary`

### 10.1 Why “expanded findings” exist

The raw `findings` table only holds foreign keys:

- vulnerability_id
- component_version_id

The API, however, wants a fully expanded record in one response.

So the repository provides joined read methods returning `ExpandedFinding`, which includes:

- finding
- vulnerability
- component version
- component

This avoided an N+1 query pattern in the REST layer.

### 10.2 Pagination and filtering

The findings endpoints use `FindingsFilter` and `FindingsPage`.

Current filters:

- `ecosystem`
- `package`
- `status`
- `vulnerability`
- `severity_label`
- `limit`
- `offset`

Current sort keys:

- `id`
- `package`
- `version`
- `vulnerability`
- `severity`
- `scan_id`

The SQL builder uses a whitelist rather than interpolating arbitrary column names.

That is an important safety and maintainability point.

## 11. REST API Design

The REST server is implemented in [internal/api/server.go](/Users/arushsacheti/Downloads/Arush_Job_Search/projects/SupplyGraph/internal/api/server.go), with the entrypoint in [cmd/api/main.go](/Users/arushsacheti/Downloads/Arush_Job_Search/projects/SupplyGraph/cmd/api/main.go).

The API is intentionally read-only right now.

Implemented routes:

- `GET /assets`
- `GET /assets/:id`
- `GET /assets/:id/findings`
- `GET /assets/:id/summary`
- `GET /scans/:id`
- `GET /scans/:id/findings`
- `GET /scans/:id/summary`

### 11.1 Response shaping

The API does not serialize raw `model.*` structs directly for public responses.

Instead it uses explicit response structs such as:

- `assetResponse`
- `scanResponse`
- `findingResponse`
- `vulnerabilityResponse`
- `componentVersionResponse`
- `assetSummaryResponse`
- `scanSummaryResponse`

This matters because it:

- keeps JSON casing consistent
- prevents leaking internal Go naming conventions
- allows the API contract to evolve independently of storage structs

### 11.2 Findings endpoint envelope

Findings routes return:

- `items`
- `total`
- `limit`
- `offset`

That is more stable than returning a raw JSON list, because pagination metadata is now part of the contract.

### 11.3 Summary endpoints

`GET /scans/:id/summary` returns per-scan aggregates.

`GET /assets/:id/summary` returns cross-scan aggregates plus:

- `total_scans`
- `latest_scan_id`

These endpoints are the first product-like “overview” surfaces in the system.

## 12. Why GraphQL Was Removed

The repo briefly explored a GraphQL layer, but it was removed.

Reason:

- it added execution and resolver complexity faster than it added product value
- the user already understood REST much better
- the data needs were well served by straightforward read endpoints

That was the correct decision at this stage.

The important thing is not that REST is universally better. It is that for this repository, at this maturity level, REST was the pragmatic choice.

## 13. Current Product Capabilities

Right now the project can answer useful questions such as:

- what assets have been scanned?
- what scans exist for a given asset?
- what findings are present in a scan?
- what findings exist across an asset?
- how many unique vulnerabilities affect a scan?
- how many findings are high severity?
- which packages are affected by a specific advisory?

That means the backend is already beyond toy status.

## 14. What Is Not Implemented Yet

The major missing capabilities are:

### 14.1 Dependency graph persistence

There is no `dependencies` table yet.

That was intentionally deferred because Syft relationship data needed more care before being treated as a trustworthy dependency graph.

### 14.2 Multi-source vulnerability enrichment

Current enrichment is:

- OSV
- npm only

There is no Trivy integration, no NVD-specific ingestion, and no OS package vulnerability path yet.

### 14.3 Background processing

Ingest and enrichment currently happen inline in the CLI flow.

There is no background queue, scheduler, or async job system.

### 14.4 MCP layer

MCP is not implemented yet.

That said, the project is now at the point where MCP does make sense.

## 15. When MCP Became Justified

MCP becomes worthwhile once there is a stable internal query surface worth exposing as tools.

Earlier in the project, MCP would have been premature because:

- the schema was still changing
- inventory persistence was incomplete
- findings and severity were not normalized yet

Now the project has:

- asset summaries
- scan summaries
- paginated findings queries
- asset findings queries
- normalized severity

That is enough for a meaningful MCP toolset.

The most natural first MCP tools are:

- `get_asset_summary`
- `get_scan_summary`
- `list_asset_findings`
- `list_scan_findings`

The MCP layer should call the same repository and/or service logic that the REST API already uses. It should not introduce a parallel business logic stack.

## 16. Suggested Next Steps

If continuing the backend before MCP, the best next features are:

1. add a backfill command for severity normalization without rerunning full ingest
2. add scan listing per asset
3. add scan comparison
4. add dependency graph persistence

If moving to MCP now, the best path is:

1. define the MCP tool contract around the existing read model
2. keep the tool surface small at first
3. reuse repository queries instead of duplicating logic

## 17. Final State of the Current Milestone

At the end of the current implementation phase, SupplyGraph is a Go/Postgres backend that:

- ingests Syft JSON
- normalizes package inventory
- deduplicates assets and package identities
- stores scan membership
- enriches npm package versions through OSV
- persists vulnerabilities and findings
- normalizes CVSS into score and severity label
- serves filtered, paginated, and sortable findings through REST
- serves scan- and asset-level summaries

That is the foundation you want before layering on MCP, richer graph analysis, or broader vulnerability sources.
