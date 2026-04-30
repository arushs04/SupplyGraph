package db

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"

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

func (r *Repository) ListAssets(ctx context.Context) ([]*model.Asset, error) {
	const query = `
		SELECT id, name, asset_type, source, created_at
		FROM assets
		ORDER BY created_at DESC, name ASC
	`

	rows, err := r.db.QueryContext(ctx, query)
	if err != nil {
		return nil, fmt.Errorf("list assets: %w", err)
	}
	defer rows.Close()

	var assets []*model.Asset
	for rows.Next() {
		asset := &model.Asset{}
		if err := rows.Scan(
			&asset.ID,
			&asset.Name,
			&asset.AssetType,
			&asset.Source,
			&asset.CreatedAt,
		); err != nil {
			return nil, fmt.Errorf("scan asset row: %w", err)
		}

		assets = append(assets, asset)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate assets: %w", err)
	}

	return assets, nil
}

func (r *Repository) GetAssetByID(ctx context.Context, id string) (*model.Asset, error) {
	const query = `
		SELECT id, name, asset_type, source, created_at
		FROM assets
		WHERE id = $1
	`

	asset := &model.Asset{}
	if err := r.db.QueryRowContext(ctx, query, id).Scan(
		&asset.ID,
		&asset.Name,
		&asset.AssetType,
		&asset.Source,
		&asset.CreatedAt,
	); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		return nil, fmt.Errorf("get asset by id: %w", err)
	}

	return asset, nil
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

func (r *Repository) GetScanByID(ctx context.Context, id string) (*model.Scan, error) {
	const query = `
		SELECT id, asset_id, status, sbom_format, started_at, completed_at
		FROM scans
		WHERE id = $1
	`

	scan := &model.Scan{}
	if err := r.db.QueryRowContext(ctx, query, id).Scan(
		&scan.ID,
		&scan.AssetID,
		&scan.Status,
		&scan.SBOMFormat,
		&scan.StartedAt,
		&scan.CompletedAt,
	); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		return nil, fmt.Errorf("get scan by id: %w", err)
	}

	return scan, nil
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

func (r *Repository) GetComponentByID(ctx context.Context, id string) (*model.Component, error) {
	const query = `
		SELECT id, name, ecosystem, purl
		FROM components
		WHERE id = $1
	`

	component := &model.Component{}
	if err := r.db.QueryRowContext(ctx, query, id).Scan(
		&component.ID,
		&component.Name,
		&component.Ecosystem,
		&component.PURL,
	); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		return nil, fmt.Errorf("get component by id: %w", err)
	}

	return component, nil
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

func (r *Repository) GetComponentVersionByID(ctx context.Context, id string) (*model.ComponentVersion, error) {
	const query = `
		SELECT id, component_id, version
		FROM component_versions
		WHERE id = $1
	`

	componentVersion := &model.ComponentVersion{}
	if err := r.db.QueryRowContext(ctx, query, id).Scan(
		&componentVersion.ID,
		&componentVersion.ComponentID,
		&componentVersion.Version,
	); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		return nil, fmt.Errorf("get component version by id: %w", err)
	}

	return componentVersion, nil
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
		INSERT INTO vulnerabilities (external_id, source, severity, severity_score, severity_label, summary)
		VALUES ($1, $2, $3, $4, $5, $6)
		ON CONFLICT (source, external_id)
		DO UPDATE SET
			severity = EXCLUDED.severity,
			severity_score = EXCLUDED.severity_score,
			severity_label = EXCLUDED.severity_label,
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
		vulnerability.SeverityScore,
		vulnerability.SeverityLabel,
		vulnerability.Summary,
	).Scan(&id); err != nil {
		return "", fmt.Errorf("find or create vulnerability: %w", err)
	}

	return id, nil
}

func (r *Repository) GetVulnerabilityByID(ctx context.Context, id string) (*model.Vulnerability, error) {
	const query = `
		SELECT id, external_id, source, severity, severity_score, severity_label, summary
		FROM vulnerabilities
		WHERE id = $1
	`

	vulnerability := &model.Vulnerability{}
	var severityScore sql.NullFloat64
	if err := r.db.QueryRowContext(ctx, query, id).Scan(
		&vulnerability.ID,
		&vulnerability.ExternalID,
		&vulnerability.Source,
		&vulnerability.Severity,
		&severityScore,
		&vulnerability.SeverityLabel,
		&vulnerability.Summary,
	); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		return nil, fmt.Errorf("get vulnerability by id: %w", err)
	}
	if severityScore.Valid {
		vulnerability.SeverityScore = &severityScore.Float64
	}

	return vulnerability, nil
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

func (r *Repository) ListFindingsByScanID(ctx context.Context, scanID string) ([]*model.Finding, error) {
	const query = `
		SELECT id, scan_id, component_version_id, vulnerability_id, fixed_version, status
		FROM findings
		WHERE scan_id = $1
		ORDER BY id ASC
	`

	rows, err := r.db.QueryContext(ctx, query, scanID)
	if err != nil {
		return nil, fmt.Errorf("list findings by scan id: %w", err)
	}
	defer rows.Close()

	var findings []*model.Finding
	for rows.Next() {
		finding := &model.Finding{}
		if err := rows.Scan(
			&finding.ID,
			&finding.ScanID,
			&finding.ComponentVersionID,
			&finding.VulnerabilityID,
			&finding.FixedVersion,
			&finding.Status,
		); err != nil {
			return nil, fmt.Errorf("scan finding row: %w", err)
		}

		findings = append(findings, finding)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate findings: %w", err)
	}

	return findings, nil
}

func (r *Repository) ListExpandedFindingsByScanID(
	ctx context.Context,
	scanID string,
) ([]model.ExpandedFinding, error) {
	page, err := r.ListExpandedFindingsPageByScanID(ctx, scanID, model.FindingsFilter{})
	if err != nil {
		return nil, err
	}
	return page.Items, nil
}

func (r *Repository) ListExpandedFindingsPageByScanID(
	ctx context.Context,
	scanID string,
	filter model.FindingsFilter,
) (*model.FindingsPage, error) {
	baseConditions := []string{"f.scan_id = $1"}
	baseArgs := []any{scanID}
	return r.listExpandedFindingsPage(ctx, baseConditions, baseArgs, filter, false)
}

func (r *Repository) ListExpandedFindingsByAssetID(
	ctx context.Context,
	assetID string,
) ([]model.ExpandedFinding, error) {
	page, err := r.ListExpandedFindingsPageByAssetID(ctx, assetID, model.FindingsFilter{})
	if err != nil {
		return nil, err
	}
	return page.Items, nil
}

func (r *Repository) ListExpandedFindingsPageByAssetID(
	ctx context.Context,
	assetID string,
	filter model.FindingsFilter,
) (*model.FindingsPage, error) {
	baseConditions := []string{"s.asset_id = $1"}
	baseArgs := []any{assetID}
	return r.listExpandedFindingsPage(ctx, baseConditions, baseArgs, filter, true)
}

func (r *Repository) GetScanSummary(ctx context.Context, scanID string) (*model.ScanSummary, error) {
	const summaryQuery = `
		SELECT
			COUNT(*) AS total_findings,
			COUNT(DISTINCT vulnerability_id) AS unique_vulnerabilities,
			COUNT(DISTINCT component_version_id) AS unique_packages_affected
		FROM findings
		WHERE scan_id = $1
	`

	summary := &model.ScanSummary{
		ScanID:          scanID,
		EcosystemCounts: map[string]int{},
		SeverityCounts:  map[string]int{},
	}

	if err := r.db.QueryRowContext(ctx, summaryQuery, scanID).Scan(
		&summary.TotalFindings,
		&summary.UniqueVulnerabilities,
		&summary.UniquePackagesAffected,
	); err != nil {
		return nil, fmt.Errorf("get scan summary: %w", err)
	}

	const ecosystemQuery = `
		SELECT c.ecosystem, COUNT(*)
		FROM findings f
		JOIN component_versions cv ON cv.id = f.component_version_id
		JOIN components c ON c.id = cv.component_id
		WHERE f.scan_id = $1
		GROUP BY c.ecosystem
		ORDER BY c.ecosystem ASC
	`

	rows, err := r.db.QueryContext(ctx, ecosystemQuery, scanID)
	if err != nil {
		return nil, fmt.Errorf("get scan summary ecosystems: %w", err)
	}
	defer rows.Close()

	for rows.Next() {
		var ecosystem string
		var count int
		if err := rows.Scan(&ecosystem, &count); err != nil {
			return nil, fmt.Errorf("scan summary ecosystem row: %w", err)
		}
		summary.EcosystemCounts[ecosystem] = count
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate scan summary ecosystems: %w", err)
	}

	const severityQuery = `
		SELECT v.severity_label, COUNT(*)
		FROM findings f
		JOIN vulnerabilities v ON v.id = f.vulnerability_id
		WHERE f.scan_id = $1
		GROUP BY v.severity_label
		ORDER BY v.severity_label ASC
	`

	rows, err = r.db.QueryContext(ctx, severityQuery, scanID)
	if err != nil {
		return nil, fmt.Errorf("get scan summary severities: %w", err)
	}
	defer rows.Close()

	for rows.Next() {
		var label string
		var count int
		if err := rows.Scan(&label, &count); err != nil {
			return nil, fmt.Errorf("scan summary severity row: %w", err)
		}
		summary.SeverityCounts[label] = count
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate scan summary severities: %w", err)
	}

	return summary, nil
}

func (r *Repository) GetAssetSummary(ctx context.Context, assetID string) (*model.AssetSummary, error) {
	const summaryQuery = `
		SELECT
			COUNT(DISTINCT s.id) AS total_scans,
			COALESCE(
				(
					SELECT s2.id::text
					FROM scans s2
					WHERE s2.asset_id = $1
					ORDER BY s2.started_at DESC, s2.id DESC
					LIMIT 1
				),
				''
			) AS latest_scan_id,
			COUNT(f.id) AS total_findings,
			COUNT(DISTINCT f.vulnerability_id) AS unique_vulnerabilities,
			COUNT(DISTINCT f.component_version_id) AS unique_packages_affected
		FROM scans s
		LEFT JOIN findings f ON f.scan_id = s.id
		WHERE s.asset_id = $1
	`

	summary := &model.AssetSummary{
		AssetID:         assetID,
		EcosystemCounts: map[string]int{},
		SeverityCounts:  map[string]int{},
	}

	if err := r.db.QueryRowContext(ctx, summaryQuery, assetID).Scan(
		&summary.TotalScans,
		&summary.LatestScanID,
		&summary.TotalFindings,
		&summary.UniqueVulnerabilities,
		&summary.UniquePackagesAffected,
	); err != nil {
		return nil, fmt.Errorf("get asset summary: %w", err)
	}

	const ecosystemQuery = `
		SELECT c.ecosystem, COUNT(*)
		FROM scans s
		JOIN findings f ON f.scan_id = s.id
		JOIN component_versions cv ON cv.id = f.component_version_id
		JOIN components c ON c.id = cv.component_id
		WHERE s.asset_id = $1
		GROUP BY c.ecosystem
		ORDER BY c.ecosystem ASC
	`

	rows, err := r.db.QueryContext(ctx, ecosystemQuery, assetID)
	if err != nil {
		return nil, fmt.Errorf("get asset summary ecosystems: %w", err)
	}
	defer rows.Close()

	for rows.Next() {
		var ecosystem string
		var count int
		if err := rows.Scan(&ecosystem, &count); err != nil {
			return nil, fmt.Errorf("asset summary ecosystem row: %w", err)
		}
		summary.EcosystemCounts[ecosystem] = count
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate asset summary ecosystems: %w", err)
	}

	const severityQuery = `
		SELECT v.severity_label, COUNT(*)
		FROM scans s
		JOIN findings f ON f.scan_id = s.id
		JOIN vulnerabilities v ON v.id = f.vulnerability_id
		WHERE s.asset_id = $1
		GROUP BY v.severity_label
		ORDER BY v.severity_label ASC
	`

	rows, err = r.db.QueryContext(ctx, severityQuery, assetID)
	if err != nil {
		return nil, fmt.Errorf("get asset summary severities: %w", err)
	}
	defer rows.Close()

	for rows.Next() {
		var label string
		var count int
		if err := rows.Scan(&label, &count); err != nil {
			return nil, fmt.Errorf("asset summary severity row: %w", err)
		}
		summary.SeverityCounts[label] = count
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate asset summary severities: %w", err)
	}

	return summary, nil
}

func (r *Repository) listExpandedFindingsPage(
	ctx context.Context,
	baseConditions []string,
	baseArgs []any,
	filter model.FindingsFilter,
	joinScans bool,
) (*model.FindingsPage, error) {
	conditions, args := buildFindingsConditions(baseConditions, baseArgs, filter)
	whereClause := strings.Join(conditions, " AND ")

	fromClause := `
		FROM findings f
	`
	if joinScans {
		fromClause += `
		JOIN scans s ON s.id = f.scan_id
		`
	}
	fromClause += `
		JOIN vulnerabilities v ON v.id = f.vulnerability_id
		JOIN component_versions cv ON cv.id = f.component_version_id
		JOIN components c ON c.id = cv.component_id
	`

	countQuery := `
		SELECT COUNT(*)
	` + fromClause + `
		WHERE ` + whereClause

	page := &model.FindingsPage{
		Limit:  filter.Limit,
		Offset: filter.Offset,
	}

	if err := r.db.QueryRowContext(ctx, countQuery, args...).Scan(&page.Total); err != nil {
		return nil, fmt.Errorf("count expanded findings: %w", err)
	}

	selectQuery := `
		SELECT
			f.id,
			f.scan_id,
			f.component_version_id,
			f.vulnerability_id,
			f.fixed_version,
			f.status,
			v.id,
			v.external_id,
			v.source,
			v.severity,
			v.severity_score,
			v.severity_label,
			v.summary,
			cv.id,
			cv.component_id,
			cv.version,
			c.id,
			c.name,
			c.ecosystem,
			c.purl
	` + fromClause + `
		WHERE ` + whereClause + `
		ORDER BY ` + buildFindingsOrderClause(filter) + `
		LIMIT $` + fmt.Sprintf("%d", len(args)+1) + `
		OFFSET $` + fmt.Sprintf("%d", len(args)+2)

	queryArgs := append(append([]any{}, args...), filter.Limit, filter.Offset)
	rows, err := r.db.QueryContext(ctx, selectQuery, queryArgs...)
	if err != nil {
		return nil, fmt.Errorf("list expanded findings page: %w", err)
	}
	defer rows.Close()

	for rows.Next() {
		var finding model.ExpandedFinding
		var severityScore sql.NullFloat64
		if err := rows.Scan(
			&finding.Finding.ID,
			&finding.Finding.ScanID,
			&finding.Finding.ComponentVersionID,
			&finding.Finding.VulnerabilityID,
			&finding.Finding.FixedVersion,
			&finding.Finding.Status,
			&finding.Vulnerability.ID,
			&finding.Vulnerability.ExternalID,
			&finding.Vulnerability.Source,
			&finding.Vulnerability.Severity,
			&severityScore,
			&finding.Vulnerability.SeverityLabel,
			&finding.Vulnerability.Summary,
			&finding.ComponentVersion.ID,
			&finding.ComponentVersion.ComponentID,
			&finding.ComponentVersion.Version,
			&finding.Component.ID,
			&finding.Component.Name,
			&finding.Component.Ecosystem,
			&finding.Component.PURL,
		); err != nil {
			return nil, fmt.Errorf("scan expanded finding row: %w", err)
		}
		if severityScore.Valid {
			finding.Vulnerability.SeverityScore = &severityScore.Float64
		}

		page.Items = append(page.Items, finding)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate expanded findings page: %w", err)
	}

	return page, nil
}

func buildFindingsConditions(
	baseConditions []string,
	baseArgs []any,
	filter model.FindingsFilter,
) ([]string, []any) {
	conditions := append([]string{}, baseConditions...)
	args := append([]any{}, baseArgs...)

	if filter.Ecosystem != "" {
		args = append(args, filter.Ecosystem)
		conditions = append(conditions, fmt.Sprintf("c.ecosystem = $%d", len(args)))
	}
	if filter.Package != "" {
		args = append(args, filter.Package)
		conditions = append(conditions, fmt.Sprintf("c.name = $%d", len(args)))
	}
	if filter.Status != "" {
		args = append(args, filter.Status)
		conditions = append(conditions, fmt.Sprintf("f.status = $%d", len(args)))
	}
	if filter.VulnerabilityExternalID != "" {
		args = append(args, filter.VulnerabilityExternalID)
		conditions = append(conditions, fmt.Sprintf("v.external_id = $%d", len(args)))
	}
	if filter.SeverityLabel != "" {
		args = append(args, filter.SeverityLabel)
		conditions = append(conditions, fmt.Sprintf("v.severity_label = $%d", len(args)))
	}

	return conditions, args
}

func buildFindingsOrderClause(filter model.FindingsFilter) string {
	direction := "ASC"
	if strings.EqualFold(filter.Order, "desc") {
		direction = "DESC"
	}

	switch filter.SortBy {
	case "severity":
		return "v.severity_score " + direction + " NULLS LAST, v.external_id ASC, f.id ASC"
	case "package":
		return "c.name " + direction + ", cv.version ASC, f.id ASC"
	case "version":
		return "cv.version " + direction + ", c.name ASC, f.id ASC"
	case "vulnerability":
		return "v.external_id " + direction + ", c.name ASC, f.id ASC"
	case "scan_id":
		return "f.scan_id " + direction + ", f.id ASC"
	case "id", "":
		return "f.id " + direction
	default:
		return "f.scan_id ASC, f.id ASC"
	}
}
