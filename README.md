# RepoRadar

RepoRadar scans public repositories, generates an SBOM with Syft, normalizes package inventory into PostgreSQL, enriches npm packages with OSV vulnerability data, exposes the results through REST and MCP, and provides a local AI-assisted UI for reviewing findings.

Detailed code-level notes live in [docs/IMPLEMENTATION_GUIDE.md](/Users/arushsacheti/Downloads/Arush_Job_Search/projects/SupplyGraph/docs/IMPLEMENTATION_GUIDE.md).

## What It Does

- accepts a public GitHub repository URL
- creates a scan job
- downloads and extracts the repository tarball
- runs `syft` automatically
- persists assets, scans, components, component versions, vulnerabilities, and findings
- normalizes CVSS vectors into `severity_score` and `severity_label`
- serves a browser UI at `http://localhost:8080/`
- exposes the same read model over REST and MCP
- adds a local Ollama-powered chat layer on top of scan results

## Current Scope

Implemented:

- public GitHub repo scanning
- Syft JSON ingestion
- npm vulnerability enrichment via OSV
- severity normalization for CVSS 3.x and 4.0 vectors
- scan and asset summaries
- findings filtering, pagination, and sorting
- MCP read tools
- embedded browser UI
- local AI analyst chat

Not implemented:

- dependency graph persistence
- ecosystems beyond the current OSV enrichment path
- external auth or multi-user support
- production-grade background worker separation
- broad automated test coverage

## Architecture

Main runtime pieces:

- [cmd/api/main.go](/Users/arushsacheti/Downloads/Arush_Job_Search/projects/SupplyGraph/cmd/api/main.go): API entrypoint, embedded UI host, scan job runner bootstrap, Ollama wiring
- [cmd/ingest/main.go](/Users/arushsacheti/Downloads/Arush_Job_Search/projects/SupplyGraph/cmd/ingest/main.go): ingest a saved Syft JSON file directly
- [cmd/mcp/main.go](/Users/arushsacheti/Downloads/Arush_Job_Search/projects/SupplyGraph/cmd/mcp/main.go): stdio MCP server
- [internal/scanjobs/runner.go](/Users/arushsacheti/Downloads/Arush_Job_Search/projects/SupplyGraph/internal/scanjobs/runner.go): repo scan orchestration
- [internal/github/public_repo.go](/Users/arushsacheti/Downloads/Arush_Job_Search/projects/SupplyGraph/internal/github/public_repo.go): public GitHub resolution and tarball extraction
- [internal/ingest/ingest.go](/Users/arushsacheti/Downloads/Arush_Job_Search/projects/SupplyGraph/internal/ingest/ingest.go): inventory persistence and enrichment orchestration
- [internal/api/server.go](/Users/arushsacheti/Downloads/Arush_Job_Search/projects/SupplyGraph/internal/api/server.go): REST handlers and static UI serving
- [internal/mcpserver/server.go](/Users/arushsacheti/Downloads/Arush_Job_Search/projects/SupplyGraph/internal/mcpserver/server.go): MCP tool layer
- [internal/ai/chat.go](/Users/arushsacheti/Downloads/Arush_Job_Search/projects/SupplyGraph/internal/ai/chat.go): AI prompt orchestration
- [internal/ollama/client.go](/Users/arushsacheti/Downloads/Arush_Job_Search/projects/SupplyGraph/internal/ollama/client.go): local Ollama client

## Local Setup

### 1. Start PostgreSQL

```bash
docker compose up -d
```

### 2. Apply migrations

```bash
docker exec -i reporadar-postgres psql -U reporadar -d reporadar < migrations/001_init.sql
docker exec -i reporadar-postgres psql -U reporadar -d reporadar < migrations/002_vulnerabilities.sql
docker exec -i reporadar-postgres psql -U reporadar -d reporadar < migrations/003_severity_normalization.sql
docker exec -i reporadar-postgres psql -U reporadar -d reporadar < migrations/004_scan_jobs.sql
```

### 3. Set `DATABASE_URL`

If Postgres is exposed on `5433`:

```bash
export DATABASE_URL="postgres://reporadar:reporadar@localhost:5433/reporadar?sslmode=disable"
```

If your container is mapped to `5432`, use that instead.

Verify it:

```bash
echo $DATABASE_URL
```

### 4. Install Syft

RepoRadar shells out to `syft` during repo scans, so `syft` must be installed on the machine running the API.

Example check:

```bash
syft version
```

### 5. Optional: install Ollama for local AI chat

If you want the AI panel:

```bash
brew install ollama
ollama serve
```

In another terminal:

```bash
ollama pull qwen2.5:1.5b
```

If Ollama is not installed or not running, the main app still works, but `/chat` and the AI panel will not.

## Running the App

Start the API and UI:

```bash
cd /Users/arushsacheti/Downloads/Arush_Job_Search/projects/SupplyGraph
go run ./cmd/api
```

Default address:

```text
http://localhost:8080/
```

Optional env vars:

```bash
export API_ADDR=":8080"
export OLLAMA_BASE_URL="http://127.0.0.1:11434"
export OLLAMA_MODEL="qwen2.5:1.5b"
```

## Browser Demo Flow

1. Open `http://localhost:8080/`
2. Paste a public GitHub repo URL
3. Submit the scan job
4. Watch job progress
5. Review asset summary, scan summary, and findings
6. Filter and sort findings
7. Ask the local AI questions about the current scan

The embedded UI supports:

- repo submission
- scan job tracking
- recent job history
- asset and scan summaries
- findings filtering by severity and package
- findings sorting
- local AI analyst chat

## Demo Videos

### Demo 1: End-to-end repo scan

Technical focus: repository scan orchestration. This demo shows the UI submitting `POST /scan-jobs`, the backend resolving a public GitHub repo, downloading the tarball, running `syft`, persisting normalized inventory into PostgreSQL, enriching npm packages with OSV, and exposing the completed scan through the results view.

<video src="https://raw.githubusercontent.com/arushs04/RepoRadar/main/docs/demo/v1.mp4" controls width="100%"></video>

Fallback file: [v1.mp4](docs/demo/v1.mp4)

### Demo 2: API-backed findings exploration

Technical focus: findings exploration through the API-backed UI. This demo shows severity and package filters, server-side sorting, and paginated findings retrieval driven by `GET /scans/:id/findings` with query params such as `severity_label`, `package`, `sort_by`, and `order`.

<video src="https://raw.githubusercontent.com/arushs04/RepoRadar/main/docs/demo/v2.mp4" controls width="100%"></video>

Fallback file: [v2.mp4](docs/demo/v2.mp4)

### Demo 3: Grounded local AI chat

Technical focus: grounded local AI analysis. This demo shows the chat layer calling `POST /chat`, assembling context from the current asset summary, scan summary, and top findings, and sending that context to a local Ollama model for scan-specific answers rather than generic LLM output.

<video src="https://raw.githubusercontent.com/arushs04/RepoRadar/main/docs/demo/v3.mp4" controls width="100%"></video>

Fallback file: [v3.mp4](docs/demo/v3.mp4)

## REST API

Implemented endpoints:

- `GET /assets`
- `GET /assets/:id`
- `GET /assets/:id/findings`
- `GET /assets/:id/summary`
- `GET /scan-jobs`
- `POST /scan-jobs`
- `GET /scan-jobs/:id`
- `GET /scans/:id`
- `GET /scans/:id/findings`
- `GET /scans/:id/summary`
- `POST /chat`

### Example scan submission

```bash
curl -X POST http://localhost:8080/scan-jobs \
  -H "Content-Type: application/json" \
  -d '{"repo_url":"https://github.com/argoproj/argo-cd"}'
```

### Poll a job

```bash
curl http://localhost:8080/scan-jobs/<job-id>
```

### List assets

```bash
curl http://localhost:8080/assets
```

### Fetch summaries

```bash
curl http://localhost:8080/assets/<asset-id>/summary
curl http://localhost:8080/scans/<scan-id>/summary
```

### Findings queries

```bash
curl "http://localhost:8080/scans/<scan-id>/findings?limit=10&offset=0"
curl "http://localhost:8080/scans/<scan-id>/findings?severity_label=high"
curl "http://localhost:8080/scans/<scan-id>/findings?package=minimatch"
curl "http://localhost:8080/scans/<scan-id>/findings?sort_by=severity&order=desc"
curl "http://localhost:8080/assets/<asset-id>/findings?package=axios&limit=5"
```

Supported findings filters:

- `limit`
- `offset`
- `ecosystem`
- `package`
- `status`
- `vulnerability`
- `severity_label`
- `sort_by`
- `order`

Supported `sort_by` values:

- `id`
- `package`
- `version`
- `vulnerability`
- `severity`
- `scan_id`

`order` must be `asc` or `desc`.

### Findings response shape

Findings endpoints return a paginated envelope:

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

## MCP

Run the MCP server:

```bash
go run ./cmd/mcp
```

Exposed tools:

- `list_assets`
- `get_asset_summary`
- `get_scan_summary`
- `list_asset_findings`
- `list_scan_findings`

These MCP tools expose the same read model as the REST API, but for AI tool calling instead of HTTP clients.

## Direct Ingestion Mode

If you already have a Syft JSON file, you can bypass repo scanning and ingest directly:

```bash
go run ./cmd/ingest /path/to/deps.json /path/to/scanned/asset
```

Example:

```bash
go run ./cmd/ingest /Users/arushsacheti/Downloads/argo-cd-master/deps.json /Users/arushsacheti/Downloads/argo-cd-master
```

## Inspecting the Database

Open psql:

```bash
docker exec -it reporadar-postgres psql -U reporadar -d reporadar
```

Useful checks:

```sql
SELECT COUNT(*) FROM assets;
SELECT COUNT(*) FROM scans;
SELECT COUNT(*) FROM vulnerabilities;
SELECT COUNT(*) FROM findings;
SELECT external_id, severity, severity_score, severity_label
FROM vulnerabilities
LIMIT 20;
```

## Troubleshooting

### `DATABASE_URL is not set`

Set the env var before `go run ./cmd/api`:

```bash
export DATABASE_URL="postgres://reporadar:reporadar@localhost:5433/reporadar?sslmode=disable"
```

### `role "reporadar" does not exist`

You are likely pointing at the wrong Postgres instance or wrong host port. Check:

```bash
docker ps
echo $DATABASE_URL
```

### `zsh: command not found: ollama`

Install Ollama first:

```bash
brew install ollama
```

### Repo scan fails before ingest

Check:

- `syft` is installed and available in `PATH`
- `DATABASE_URL` points at the correct Postgres instance
- the submitted repo is public and on `github.com`

## Project Layout

```text
cmd/api/             API entrypoint and embedded UI host
cmd/ingest/          Direct Syft JSON ingest entrypoint
cmd/mcp/             MCP entrypoint
docs/                Longer implementation documentation
internal/ai/         AI chat orchestration
internal/api/        REST handlers and embedded web assets
internal/db/         PostgreSQL connection and repository methods
internal/github/     Public GitHub resolution and tarball extraction
internal/ingest/     Inventory persistence and OSV enrichment
internal/mcpserver/  MCP server and tool definitions
internal/model/      Domain models
internal/ollama/     Local Ollama client
internal/osv/        OSV client and response types
internal/scanjobs/   Repo scanning job runner
internal/severity/   CVSS normalization
internal/syft/       Syft JSON parsing and normalization
migrations/          Schema migrations
docker-compose.yml   Local Postgres
```

