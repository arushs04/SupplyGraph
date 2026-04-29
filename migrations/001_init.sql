CREATE EXTENSION IF NOT EXISTS "pgcrypto"; -- For gen_random_uuid() function

CREATE TABLE assets (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(), -- Unique identifier for each asset
    name TEXT NOT NULL, -- Name of the asset
    asset_type TEXT NOT NULL, -- Type of the asset (local_path or repo_url)
    source TEXT NOT NULL, -- Source of the asset (actual GitHub link, local path)
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (asset_type, source)
);

CREATE TABLE scans (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(), -- Unique identifier for each scan
    asset_id UUID NOT NULL REFERENCES assets(id) ON DELETE CASCADE, -- Foreign key to the assets table, every scan will belong to an asset
    status TEXT NOT NULL, -- Status of the scan (e.g., pending, running, completed, failed)
    sbom_format TEXT NOT NULL, -- Format of the SBOM (e.g., SPDX, CycloneDX)
    started_at TIMESTAMPTZ NOT NULL, -- Timestamp when the scan was started
    completed_at TIMESTAMPTZ -- Timestamp when the scan was completed   
);

CREATE TABLE components (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(), -- Unique identifier for each component(e.g., a library or package)
    name TEXT NOT NULL,
    ecosystem TEXT, -- Ecosystem of the component (e.g., npm, PyPI, Maven)
    purl TEXT NOT NULL UNIQUE -- Package URL (PURL) for the component, which provides a standardized way to identify and locate software packages
);

CREATE TABLE component_versions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),  -- Unique identifier for each component version
    component_id UUID NOT NULL REFERENCES components(id) ON DELETE CASCADE, -- Foreign key to the components table, each version belongs to a component
    version TEXT NOT NULL, -- Version of the component (e.g., 1.0.0)
    UNIQUE (component_id, version) -- Ensure that each component can only have one entry per version
);

CREATE TABLE scan_component_versions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    scan_id UUID NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    component_version_id UUID NOT NULL REFERENCES component_versions(id) ON DELETE CASCADE,
    UNIQUE (scan_id, component_version_id)
);
