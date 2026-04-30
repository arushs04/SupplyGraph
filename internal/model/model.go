package model

import "time"

type Asset struct {
	ID        string
	Name      string
	AssetType string
	Source    string
	CreatedAt time.Time
}

type Scan struct {
	ID          string
	AssetID     string
	Status      string
	SBOMFormat  string
	StartedAt   time.Time
	CompletedAt *time.Time
}

type Component struct {
	ID        string
	Name      string
	Ecosystem string
	PURL      string
}

type ComponentVersion struct {
	ID          string
	ComponentID string
	Version     string
}

type NormalizedArtifact struct {
	Component        Component
	ComponentVersion ComponentVersion
}

type Vulnerability struct {
	ID            string
	ExternalID    string
	Source        string
	Severity      string
	SeverityScore *float64
	SeverityLabel string
	Summary       string
}

type Finding struct {
	ID                 string
	ScanID             string
	ComponentVersionID string
	VulnerabilityID    string
	FixedVersion       string
	Status             string
}

type ScanPackage struct {
	ComponentVersionID string
	Name               string
	Ecosystem          string
	Version            string
	PURL               string
}

type ExpandedFinding struct {
	Finding          Finding
	Vulnerability    Vulnerability
	ComponentVersion ComponentVersion
	Component        Component
}

type ScanSummary struct {
	ScanID                 string
	TotalFindings          int
	UniqueVulnerabilities  int
	UniquePackagesAffected int
	EcosystemCounts        map[string]int
	SeverityCounts         map[string]int
}

type AssetSummary struct {
	AssetID                string
	TotalScans             int
	LatestScanID           string
	TotalFindings          int
	UniqueVulnerabilities  int
	UniquePackagesAffected int
	EcosystemCounts        map[string]int
	SeverityCounts         map[string]int
}

type FindingsFilter struct {
	Limit                   int
	Offset                  int
	Ecosystem               string
	Package                 string
	Status                  string
	VulnerabilityExternalID string
	SeverityLabel           string
	SortBy                  string
	Order                   string
}

type FindingsPage struct {
	Items  []ExpandedFinding
	Total  int
	Limit  int
	Offset int
}
