package main

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"supplygraph/internal/db"
	"supplygraph/internal/model"
	"supplygraph/internal/syft"
)

func main() {
	if len(os.Args) < 3 {
		fmt.Println("usage: ingest <path-to-syft-json> <scanned-asset-path>")
		os.Exit(1)
	}

	syftJSONPath := os.Args[1]
	scannedAssetPath := os.Args[2]

	doc, err := syft.LoadDocument(syftJSONPath)
	if err != nil {
		fmt.Printf("error: %v\n", err)
		os.Exit(1)
	}

	database, err := db.Open()
	if err != nil {
		fmt.Printf("error: %v\n", err)
		os.Exit(1)
	}
	defer database.Close()

	repo := db.NewRepository(database)
	ctx := context.Background()

	fmt.Printf("source name: %s\n", doc.Source.Name)
	fmt.Printf("source type: %s\n", doc.Source.Type)
	fmt.Printf("source path: %s\n", doc.Source.Metadata.Path)
	fmt.Printf("scanner: %s %s\n", doc.Descriptor.Name, doc.Descriptor.Version)
	fmt.Printf("artifacts found: %d\n", len(doc.Artifacts))

	limit := min(len(doc.Artifacts), 5)
	for i := 0; i < limit; i++ {
		artifact := doc.Artifacts[i]
		fmt.Printf(
			"artifact %d: name=%q version=%q type=%q purl=%q\n",
			i+1,
			artifact.Name,
			artifact.Version,
			artifact.Type,
			artifact.PURL,
		)
	}

	normalizedCount := 0
	for _, artifact := range doc.Artifacts {
		_, ok, err := syft.NormalizeArtifact(artifact)
		if err != nil {
			fmt.Printf("normalize error for %q: %v\n", artifact.Name, err)
			continue
		}
		if ok {
			normalizedCount++
		}
	}

	fmt.Printf("artifacts eligible for normalization: %d\n", normalizedCount)

	// Insert the scanned asset and scan metadata into the database, so that we have a record of what was scanned and when. This also allows us to link the discovered components back to this scan in the future.
	asset := model.Asset{
		Name:      filepath.Base(scannedAssetPath),
		AssetType: "local_path",
		Source:    scannedAssetPath,
	}

	// Insert the asset into the database and get its generated ID, which we will use to link the scan to this asset.
	assetID, err := repo.FindOrCreateAsset(ctx, asset)
	if err != nil {
		fmt.Printf("error inserting asset: %v\n", err)
		os.Exit(1)
	}

	now := time.Now().UTC()
	scan := model.Scan{
		AssetID:    assetID,
		Status:     "completed",
		SBOMFormat: "syft-json",
		StartedAt:  now,
		CompletedAt: func() *time.Time {
			t := now
			return &t
		}(),
	}

	// Insert the scan into the database and get its generated ID, which we could use to link discovered components to this scan in the future if we wanted to.
	scanID, err := repo.InsertScan(ctx, scan)
	if err != nil {
		fmt.Printf("error inserting scan: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("inserted asset id: %s\n", assetID)
	fmt.Printf("inserted scan id: %s\n", scanID)

	normalizedProcessed := 0
	componentPersisted := 0
	componentVersionPersisted := 0
	scanMembershipPersisted := 0

	for _, artifact := range doc.Artifacts {
		normalized, ok, err := syft.NormalizeArtifact(artifact)
		if err != nil {
			fmt.Printf("normalize error for %q: %v\n", artifact.Name, err)
			continue
		}
		if !ok {
			continue
		}

		componentID, err := repo.FindOrCreateComponent(ctx, normalized.Component)
		if err != nil {
			fmt.Printf("error persisting component %q: %v\n", normalized.Component.Name, err)
			continue
		}

		normalized.ComponentVersion.ComponentID = componentID
		componentVersionID, err := repo.FindOrCreateComponentVersion(ctx, normalized.ComponentVersion)
		if err != nil {
			fmt.Printf(
				"error persisting component version %q@%q: %v\n",
				normalized.Component.Name,
				normalized.ComponentVersion.Version,
				err,
			)
			continue
		}

		_, err = repo.FindOrCreateScanComponentVersion(ctx, scanID, componentVersionID)
		if err != nil {
			fmt.Printf(
				"error persisting scan membership for %q@%q: %v\n",
				normalized.Component.Name,
				normalized.ComponentVersion.Version,
				err,
			)
			continue
		}

		normalizedProcessed++
		componentPersisted++
		componentVersionPersisted++
		scanMembershipPersisted++
	}

	fmt.Printf("normalized artifacts persisted: %d\n", normalizedProcessed)
	fmt.Printf("component upserts attempted: %d\n", componentPersisted)
	fmt.Printf("component version upserts attempted: %d\n", componentVersionPersisted)
	fmt.Printf("scan membership upserts attempted: %d\n", scanMembershipPersisted)
}
