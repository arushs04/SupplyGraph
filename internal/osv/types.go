package osv

type QueryRequest struct {
	Version string         `json:"version,omitempty"`
	Package QueryPackage   `json:"package"`
}

type QueryPackage struct {
	Name      string `json:"name,omitempty"`
	Ecosystem string `json:"ecosystem,omitempty"`
	PURL      string `json:"purl,omitempty"`
}

type QueryResponse struct {
	Vulns []Vulnerability `json:"vulns"`
}

type Vulnerability struct {
	ID       string     `json:"id"`
	Summary  string     `json:"summary"`
	Aliases  []string   `json:"aliases"`
	Modified string     `json:"modified"`
	Severity []Severity `json:"severity"`
}

type Severity struct {
	Type  string `json:"type"`
	Score string `json:"score"`
}
