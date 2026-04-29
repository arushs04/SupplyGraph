package ingest

import (
	"context"
	"fmt"
	"net/http"

	"supplygraph/internal/db"
	"supplygraph/internal/model"
	"supplygraph/internal/osv"
	"supplygraph/internal/syft"
)

type InventoryResult struct {
	NormalizedArtifacts       int
	ComponentUpserts          int
	ComponentVersionUpserts   int
	ScanMembershipUpserts     int
}

type EnrichmentResult struct {
	PackagesChecked           int
	PackagesWithVulns         int
	TotalVulnerabilities      int
	VulnerabilitiesPersisted  int
	FindingsPersisted         int
}

func PersistInventory(
	ctx context.Context,
	repo *db.Repository,
	scanID string,
	artifacts []syft.Artifact,
) (InventoryResult, error) {
	var result InventoryResult

	for _, artifact := range artifacts {
		normalized, ok, err := syft.NormalizeArtifact(artifact)
		if err != nil {
			return InventoryResult{}, fmt.Errorf("normalize artifact %q: %w", artifact.Name, err)
		}
		if !ok {
			continue
		}

		componentID, err := repo.FindOrCreateComponent(ctx, normalized.Component)
		if err != nil {
			return InventoryResult{}, fmt.Errorf("persist component %q: %w", normalized.Component.Name, err)
		}

		normalized.ComponentVersion.ComponentID = componentID
		componentVersionID, err := repo.FindOrCreateComponentVersion(ctx, normalized.ComponentVersion)
		if err != nil {
			return InventoryResult{}, fmt.Errorf(
				"persist component version %q@%q: %w",
				normalized.Component.Name,
				normalized.ComponentVersion.Version,
				err,
			)
		}

		if _, err := repo.FindOrCreateScanComponentVersion(ctx, scanID, componentVersionID); err != nil {
			return InventoryResult{}, fmt.Errorf(
				"persist scan membership %q@%q: %w",
				normalized.Component.Name,
				normalized.ComponentVersion.Version,
				err,
			)
		}

		result.NormalizedArtifacts++
		result.ComponentUpserts++
		result.ComponentVersionUpserts++
		result.ScanMembershipUpserts++
	}

	return result, nil
}

func EnrichScanWithOSV(
	ctx context.Context,
	repo *db.Repository,
	scanID string,
) (EnrichmentResult, error) {
	scanPackages, err := repo.ListScanPackages(ctx, scanID)
	if err != nil {
		return EnrichmentResult{}, fmt.Errorf("list scan packages: %w", err)
	}

	client := osv.NewClient(http.DefaultClient)
	var result EnrichmentResult

	for _, pkg := range scanPackages {
		if pkg.Ecosystem == "" || pkg.Name == "" || pkg.Version == "" || pkg.Ecosystem != "npm" {
			continue
		}

		result.PackagesChecked++
		response, err := client.Query(ctx, osv.QueryRequest{
			Version: pkg.Version,
			Package: osv.QueryPackage{
				Name:      pkg.Name,
				Ecosystem: pkg.Ecosystem,
			},
		})
		if err != nil {
			return EnrichmentResult{}, fmt.Errorf("query osv for %s@%s: %w", pkg.Name, pkg.Version, err)
		}

		if len(response.Vulns) == 0 {
			continue
		}

		result.PackagesWithVulns++
		result.TotalVulnerabilities += len(response.Vulns)

		for _, vuln := range response.Vulns {
			severity := ""
			if len(vuln.Severity) > 0 {
				severity = vuln.Severity[0].Score
			}

			vulnerabilityID, err := repo.FindOrCreateVulnerability(ctx, model.Vulnerability{
				ExternalID: vuln.ID,
				Source:     "osv",
				Severity:   severity,
				Summary:    vuln.Summary,
			})
			if err != nil {
				return EnrichmentResult{}, fmt.Errorf("persist vulnerability %q: %w", vuln.ID, err)
			}
			result.VulnerabilitiesPersisted++

			if _, err := repo.FindOrCreateFinding(ctx, model.Finding{
				ScanID:             scanID,
				ComponentVersionID: pkg.ComponentVersionID,
				VulnerabilityID:    vulnerabilityID,
				FixedVersion:       "",
				Status:             "open",
			}); err != nil {
				return EnrichmentResult{}, fmt.Errorf(
					"persist finding for %s@%s and %s: %w",
					pkg.Name,
					pkg.Version,
					vuln.ID,
					err,
				)
			}
			result.FindingsPersisted++
		}
	}

	return result, nil
}
