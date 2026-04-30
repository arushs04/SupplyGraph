# SupplyGraph

SupplyGraph is a backend project for scanning software assets, normalizing package inventory, enriching package versions with vulnerability data, and eventually exposing dependency, vulnerability, and risk analysis through structured APIs and MCP tools.

Detailed implementation notes live in [docs/IMPLEMENTATION_GUIDE.md](/Users/arushsacheti/Downloads/Arush_Job_Search/projects/SupplyGraph/docs/IMPLEMENTATION_GUIDE.md).

## Current Status

The project currently supports:

- parsing Syft JSON output from a saved file
- filtering and normalizing package-like artifacts
- persisting assets and scans into PostgreSQL
- persisting normalized components, component versions, and scan membership
- enriching npm package versions with OSV vulnerability data
- persisting vulnerabilities and findings into PostgreSQL
- exposing read APIs over REST

The project does not yet support:

- dependency graph persistence
- Trivy enrichment
- MCP tools
- scheduled or background scan processing
- test coverage

## Tech Stack

- Go
- PostgreSQL
- Docker Compose
- Syft
- OSV

## Local Development

### Start PostgreSQL

```bash
docker compose up -d
```

### Apply database migrations

```bash
docker exec -i supplygraph-postgres psql -U supplygraph -d supplygraph < migrations/001_init.sql
docker exec -i supplygraph-postgres psql -U supplygraph -d supplygraph < migrations/002_vulnerabilities.sql
docker exec -i supplygraph-postgres psql -U supplygraph -d supplygraph < migrations/003_severity_normalization.sql
```

### Set the database connection string

If your Docker PostgreSQL instance is exposed on port `5432`:

```bash
export DATABASE_URL="postgres://supplygraph:supplygraph@localhost:5432/supplygraph?sslmode=disable"
```

If you remap the container to a different host port, update the URL accordingly.

### Generate a Syft JSON scan

```bash
syft /path/to/asset -o json > deps.json
```

### Run ingestion against a saved Syft JSON file

```bash
go run ./cmd/ingest /path/to/deps.json /path/to/scanned/asset
```

Example:

```bash
go run ./cmd/ingest /Users/arushsacheti/Downloads/argo-cd-master/deps.json /Users/arushsacheti/Downloads/argo-cd-master
```

### Run the REST API

```bash
go run ./cmd/api
```

By default the API listens on `:8080`.

## REST API

Implemented endpoints:

- `GET /assets`
- `GET /assets/:id`
- `GET /assets/:id/findings`
- `GET /assets/:id/summary`
- `GET /scans/:id`
- `GET /scans/:id/findings`
- `GET /scans/:id/summary`

Example requests:

```bash
curl http://localhost:8080/assets
curl http://localhost:8080/assets/<asset-id>/findings
curl http://localhost:8080/assets/<asset-id>/summary
curl http://localhost:8080/scans/<scan-id>
curl http://localhost:8080/scans/<scan-id>/findings
curl http://localhost:8080/scans/<scan-id>/summary
```

Filtering and pagination for findings endpoints:

```bash
curl "http://localhost:8080/scans/<scan-id>/findings?limit=10&offset=0"
curl "http://localhost:8080/scans/<scan-id>/findings?package=minimatch"
curl "http://localhost:8080/scans/<scan-id>/findings?ecosystem=npm&status=open"
curl "http://localhost:8080/scans/<scan-id>/findings?vulnerability=GHSA-2g4f-4pwh-qvx6"
curl "http://localhost:8080/scans/<scan-id>/findings?severity_label=high"
curl "http://localhost:8080/assets/<asset-id>/findings?limit=25&package=axios"
curl "http://localhost:8080/scans/<scan-id>/findings?sort_by=package&order=asc"
curl "http://localhost:8080/scans/<scan-id>/findings?sort_by=vulnerability&order=desc"
curl "http://localhost:8080/scans/<scan-id>/findings?sort_by=severity&order=desc"
```

Supported sorting:

- `sort_by=id`
- `sort_by=package`
- `sort_by=version`
- `sort_by=vulnerability`
- `sort_by=severity`
- `sort_by=scan_id`
- `order=asc|desc`

Findings endpoints now return a paginated envelope:

```json
{
  "items": [
    {
      "id": "d402fab2-2a53-4bca-9ffd-27b123e7f142",
      "scan_id": "3aa17844-84ea-4868-9f8c-bbbd7906485d",
      "status": "open",
      "fixed_version": "",
      "vulnerability": {
        "id": "343614b0-4e78-47d9-be83-6b1acef162cc",
        "external_id": "GHSA-2g4f-4pwh-qvx6",
        "source": "osv",
        "severity": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:L/SC:N/SI:N/SA:N/E:P",
        "severity_score": 5.3,
        "severity_label": "medium",
        "summary": "ajv has ReDoS when using `$data` option"
      },
      "component_version": {
        "id": "8822e382-cf94-4387-924f-3b5050e1a93d",
        "version": "6.12.6",
        "component": {
          "id": "5c7b1652-fc36-4c9d-8674-f5120c4bdab4",
          "name": "ajv",
          "ecosystem": "npm",
          "purl": "pkg:npm/ajv"
        }
      }
    }
  ],
  "total": 66,
  "limit": 10,
  "offset": 0
}
```

Example summary response:

```json
{
  "scan_id": "3aa17844-84ea-4868-9f8c-bbbd7906485d",
  "total_findings": 66,
  "unique_vulnerabilities": 40,
  "unique_packages_affected": 29,
  "ecosystem_counts": {
    "npm": 66
  },
  "severity_counts": {
    "critical": 0,
    "high": 12,
    "medium": 39,
    "low": 10,
    "unknown": 5
  }
}
```

Example asset summary response:

```json
{
  "asset_id": "28e76e7f-0b38-4532-930c-cfe478c1a2bd",
  "total_scans": 4,
  "latest_scan_id": "3aa17844-84ea-4868-9f8c-bbbd7906485d",
  "total_findings": 66,
  "unique_vulnerabilities": 45,
  "unique_packages_affected": 40,
  "ecosystem_counts": {
    "npm": 66
  },
  "severity_counts": {
    "critical": 1,
    "high": 32,
    "medium": 19,
    "low": 10,
    "none": 0,
    "unknown": 4
  }
}
```

### Inspect stored data

```bash
docker exec -it supplygraph-postgres psql -U supplygraph -d supplygraph
```

Example queries:

```sql
SELECT * FROM assets;
SELECT COUNT(*) FROM scans;
SELECT COUNT(*) FROM components;
SELECT COUNT(*) FROM component_versions;
SELECT COUNT(*) FROM vulnerabilities;
SELECT COUNT(*) FROM findings;
```

## Current Data Model

Implemented tables:

- `assets`
- `scans`
- `components`
- `component_versions`
- `scan_component_versions`
- `vulnerabilities`
- `findings`

## Project Layout

```text
cmd/ingest/          CLI entrypoint for ingestion workflow
cmd/api/             REST API entrypoint
docs/                Longer implementation documentation
internal/ingest/     Inventory persistence and OSV enrichment workflows
internal/api/        REST handlers and response shaping
internal/db/         PostgreSQL connection and persistence helpers
internal/model/      Normalized application/domain models
internal/osv/        OSV client and response types
internal/severity/   CVSS parsing and severity normalization
internal/syft/       Syft JSON parsing and normalization logic
migrations/          Database schema SQL
docker-compose.yml   Local PostgreSQL development environment
```
