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

func (r *Repository) ListScanPackages(ctx context.Context, scanID string) ([]model.ScanPackage, error) {
	const query = `
		SELECT
			cv.id,
			c.name,
			c.ecosystem,
			cv.version,
			c.purl
		FROM scan_component_versions scv
		JOIN component_versions cv ON cv.id = scv.component_version_id
		JOIN components c ON c.id = cv.component_id
		WHERE scv.scan_id = $1
		ORDER BY c.name, cv.version
	`

	rows, err := r.db.QueryContext(ctx, query, scanID)
	if err != nil {
		return nil, fmt.Errorf("list scan packages: %w", err)
	}
	defer rows.Close()

	var packages []model.ScanPackage
	for rows.Next() {
		var pkg model.ScanPackage
		if err := rows.Scan(
			&pkg.ComponentVersionID,
			&pkg.Name,
			&pkg.Ecosystem,
			&pkg.Version,
			&pkg.PURL,
		); err != nil {
			return nil, fmt.Errorf("scan scan package row: %w", err)
		}

		packages = append(packages, pkg)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate scan packages: %w", err)
	}

	return packages, nil
}

func (r *Repository) FindOrCreateVulnerability(ctx context.Context, vulnerability model.Vulnerability) (string, error) {
	const query = `
		INSERT INTO vulnerabilities (external_id, source, severity, summary)
		VALUES ($1, $2, $3, $4)
		ON CONFLICT (source, external_id)
		DO UPDATE SET
			severity = EXCLUDED.severity,
			summary = EXCLUDED.summary
		RETURNING id
	`

	var id string
	if err := r.db.QueryRowContext(
		ctx,
		query,
		vulnerability.ExternalID,
		vulnerability.Source,
		vulnerability.Severity,
		vulnerability.Summary,
	).Scan(&id); err != nil {
		return "", fmt.Errorf("find or create vulnerability: %w", err)
	}

	return id, nil
}

func (r *Repository) FindOrCreateFinding(ctx context.Context, finding model.Finding) (string, error) {
	const query = `
		INSERT INTO findings (scan_id, component_version_id, vulnerability_id, fixed_version, status)
		VALUES ($1, $2, $3, $4, $5)
		ON CONFLICT (scan_id, component_version_id, vulnerability_id)
		DO UPDATE SET
			fixed_version = EXCLUDED.fixed_version,
			status = EXCLUDED.status
		RETURNING id
	`

	var id string
	if err := r.db.QueryRowContext(
		ctx,
		query,
		finding.ScanID,
		finding.ComponentVersionID,
		finding.VulnerabilityID,
		finding.FixedVersion,
		finding.Status,
	).Scan(&id); err != nil {
		return "", fmt.Errorf("find or create finding: %w", err)
	}

	return id, nil
}
