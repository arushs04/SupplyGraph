package db

import (
	"context"
	"database/sql"
	"fmt"

	"supplygraph/internal/model"
)

type Repository struct {
	db *sql.DB
}

func NewRepository(db *sql.DB) *Repository {
	return &Repository{db: db}
}

// FindOrCreateAsset reuses an existing asset by (asset_type, source) or creates a new one.
func (r *Repository) FindOrCreateAsset(ctx context.Context, asset model.Asset) (string, error) {
	const query = `
		INSERT INTO assets (name, asset_type, source)
		VALUES ($1, $2, $3)
		ON CONFLICT (asset_type, source)
		DO UPDATE SET
			name = EXCLUDED.name
		RETURNING id
	`

	var id string
	if err := r.db.QueryRowContext(ctx, query, asset.Name, asset.AssetType, asset.Source).Scan(&id); err != nil {
		return "", fmt.Errorf("find or create asset: %w", err)
	}

	return id, nil
}

// InsertScan inserts a new scan into the database and returns its generated ID.
func (r *Repository) InsertScan(ctx context.Context, scan model.Scan) (string, error) {
	const query = `
		INSERT INTO scans (asset_id, status, sbom_format, started_at, completed_at)
		VALUES ($1, $2, $3, $4, $5)
		RETURNING id
	`

	var id string
	if err := r.db.QueryRowContext(
		ctx,
		query,
		scan.AssetID,
		scan.Status,
		scan.SBOMFormat,
		scan.StartedAt,
		scan.CompletedAt,
	).Scan(&id); err != nil {
		return "", fmt.Errorf("insert scan: %w", err)
	}

	return id, nil
}

// FindOrCreateComponent attempts to find a component by its PURL, and if it doesn't exist, it creates a new one. It returns the ID of the found or created component.
func (r *Repository) FindOrCreateComponent(ctx context.Context, component model.Component) (string, error) {
	// // DO NOTHING makes it harder to get the row id back directly
	const query = `
		INSERT INTO components (name, ecosystem, purl)
		VALUES ($1, $2, $3)
		ON CONFLICT (purl)
		DO UPDATE SET
			name = EXCLUDED.name,
			ecosystem = EXCLUDED.ecosystem
		RETURNING id
	`

	var id string
	if err := r.db.QueryRowContext(ctx, query, component.Name, component.Ecosystem, component.PURL).Scan(&id); err != nil {
		return "", fmt.Errorf("find or create component: %w", err)
	}

	return id, nil
}

// FindOrCreateComponentVersion attempts to find a component version by its component ID and version, and if it doesn't exist, it creates a new one. It returns the ID of the found or created component version.
func (r *Repository) FindOrCreateComponentVersion(
	ctx context.Context,
	componentVersion model.ComponentVersion,
) (string, error) {
	// DO NOTHING makes it harder to get the row id back directly
	const query = `
		INSERT INTO component_versions (component_id, version)
		VALUES ($1, $2)
		ON CONFLICT (component_id, version)
		DO UPDATE SET
			version = EXCLUDED.version
		RETURNING id
	`

	var id string
	if err := r.db.QueryRowContext(
		ctx,
		query,
		componentVersion.ComponentID,
		componentVersion.Version,
	).Scan(&id); err != nil {
		return "", fmt.Errorf("find or create component version: %w", err)
	}

	return id, nil
}

// FindOrCreateScanComponentVersion records that a specific scan contains a specific component version.
func (r *Repository) FindOrCreateScanComponentVersion(
	ctx context.Context,
	scanID string,
	componentVersionID string,
) (string, error) {
	const query = `
		INSERT INTO scan_component_versions (scan_id, component_version_id)
		VALUES ($1, $2)
		ON CONFLICT (scan_id, component_version_id)
		DO UPDATE SET
			component_version_id = EXCLUDED.component_version_id
		RETURNING id
	`

	var id string
	if err := r.db.QueryRowContext(ctx, query, scanID, componentVersionID).Scan(&id); err != nil {
		return "", fmt.Errorf("find or create scan component version: %w", err)
	}

	return id, nil
}
