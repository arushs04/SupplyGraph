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
	ID         string
	ExternalID string
	Source     string
	Severity   string
	Summary    string
}

type Finding struct {
	ID               string
	ScanID           string
	ComponentVersionID string
	VulnerabilityID  string
	FixedVersion     string
	Status           string
}

type ScanPackage struct {
	ComponentVersionID string
	Name               string
	Ecosystem          string
	Version            string
	PURL               string
}
