package api

import (
	"embed"
	"encoding/json"
	"fmt"
	"io/fs"
	"net/http"
	"strconv"
	"strings"
	"time"

	"supplygraph/internal/db"
	"supplygraph/internal/model"
	"supplygraph/internal/scanjobs"
)

//go:embed web/*
var webFS embed.FS

type Server struct {
	repo   *db.Repository
	runner *scanjobs.Runner
	mux    *http.ServeMux
}

func NewServer(repo *db.Repository, runner *scanjobs.Runner) *Server {
	server := &Server{
		repo:   repo,
		runner: runner,
		mux:    http.NewServeMux(),
	}

	server.routes()

	return server
}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.mux.ServeHTTP(w, r)
}

func (s *Server) routes() {
	webRoot, err := fs.Sub(webFS, "web")
	if err != nil {
		panic(fmt.Sprintf("load embedded web assets: %v", err))
	}

	s.mux.Handle("/", http.FileServer(http.FS(webRoot)))
	s.mux.Handle("/static/", http.StripPrefix("/static/", http.FileServer(http.FS(webRoot))))
	s.mux.HandleFunc("/assets", s.handleAssets)
	s.mux.HandleFunc("/assets/", s.handleAssetByID)
	s.mux.HandleFunc("/scan-jobs", s.handleScanJobs)
	s.mux.HandleFunc("/scan-jobs/", s.handleScanJobByID)
	s.mux.HandleFunc("/scans/", s.handleScans)
}

func (s *Server) handleScanJobs(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		s.handleListScanJobs(w, r)
	case http.MethodPost:
		s.handleCreateScanJob(w, r)
	default:
		writeMethodNotAllowed(w)
	}
}

func (s *Server) handleScanJobByID(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeMethodNotAllowed(w)
		return
	}

	id := strings.TrimPrefix(r.URL.Path, "/scan-jobs/")
	if id == "" || strings.Contains(id, "/") {
		writeNotFound(w)
		return
	}

	job, err := s.repo.GetScanJobByID(r.Context(), id)
	if err != nil {
		writeInternalError(w, err)
		return
	}
	if job == nil {
		writeNotFound(w)
		return
	}

	writeJSON(w, http.StatusOK, newScanJobResponse(job))
}

func (s *Server) handleListScanJobs(w http.ResponseWriter, r *http.Request) {
	jobs, err := s.repo.ListScanJobs(r.Context(), 25)
	if err != nil {
		writeInternalError(w, err)
		return
	}

	response := make([]scanJobResponse, 0, len(jobs))
	for _, job := range jobs {
		response = append(response, newScanJobResponse(job))
	}

	writeJSON(w, http.StatusOK, response)
}

func (s *Server) handleCreateScanJob(w http.ResponseWriter, r *http.Request) {
	if s.runner == nil {
		writeInternalError(w, fmt.Errorf("scan job runner is not configured"))
		return
	}

	var request createScanJobRequest
	if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
		writeBadRequest(w, "invalid json body")
		return
	}

	job, err := s.runner.SubmitGitHubRepo(r.Context(), request.RepoURL)
	if err != nil {
		writeBadRequest(w, err.Error())
		return
	}

	writeJSON(w, http.StatusAccepted, newScanJobResponse(job))
}

func (s *Server) handleAssets(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeMethodNotAllowed(w)
		return
	}

	assets, err := s.repo.ListAssets(r.Context())
	if err != nil {
		writeInternalError(w, err)
		return
	}

	response := make([]assetResponse, 0, len(assets))
	for _, asset := range assets {
		response = append(response, newAssetResponse(asset))
	}

	writeJSON(w, http.StatusOK, response)
}

func (s *Server) handleAssetByID(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeMethodNotAllowed(w)
		return
	}

	path := strings.TrimPrefix(r.URL.Path, "/assets/")
	if path == "" {
		writeNotFound(w)
		return
	}

	parts := strings.Split(path, "/")
	if len(parts) == 1 {
		s.handleAsset(w, r, parts[0])
		return
	}

	if len(parts) == 2 && parts[1] == "findings" {
		s.handleAssetFindings(w, r, parts[0])
		return
	}

	if len(parts) == 2 && parts[1] == "summary" {
		s.handleAssetSummary(w, r, parts[0])
		return
	}

	writeNotFound(w)
}

func (s *Server) handleAsset(w http.ResponseWriter, r *http.Request, id string) {
	asset, err := s.repo.GetAssetByID(r.Context(), id)
	if err != nil {
		writeInternalError(w, err)
		return
	}
	if asset == nil {
		writeNotFound(w)
		return
	}

	writeJSON(w, http.StatusOK, newAssetResponse(asset))
}

func (s *Server) handleAssetFindings(w http.ResponseWriter, r *http.Request, assetID string) {
	filter, err := parseFindingsFilter(r)
	if err != nil {
		writeBadRequest(w, err.Error())
		return
	}

	findings, err := s.repo.ListExpandedFindingsPageByAssetID(r.Context(), assetID, filter)
	if err != nil {
		writeInternalError(w, err)
		return
	}

	response := make([]findingResponse, 0, len(findings.Items))
	for _, finding := range findings.Items {
		response = append(response, newFindingResponse(finding))
	}

	writeJSON(w, http.StatusOK, findingsPageResponse{
		Items:  response,
		Total:  findings.Total,
		Limit:  findings.Limit,
		Offset: findings.Offset,
	})
}

func (s *Server) handleAssetSummary(w http.ResponseWriter, r *http.Request, assetID string) {
	summary, err := s.repo.GetAssetSummary(r.Context(), assetID)
	if err != nil {
		writeInternalError(w, err)
		return
	}

	writeJSON(w, http.StatusOK, newAssetSummaryResponse(summary))
}

func (s *Server) handleScans(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeMethodNotAllowed(w)
		return
	}

	path := strings.TrimPrefix(r.URL.Path, "/scans/")
	if path == "" {
		writeNotFound(w)
		return
	}

	parts := strings.Split(path, "/")
	if len(parts) == 1 {
		s.handleScanByID(w, r, parts[0])
		return
	}

	if len(parts) == 2 && parts[1] == "findings" {
		s.handleScanFindings(w, r, parts[0])
		return
	}

	if len(parts) == 2 && parts[1] == "summary" {
		s.handleScanSummary(w, r, parts[0])
		return
	}

	writeNotFound(w)
}

func (s *Server) handleScanByID(w http.ResponseWriter, r *http.Request, id string) {
	scan, err := s.repo.GetScanByID(r.Context(), id)
	if err != nil {
		writeInternalError(w, err)
		return
	}
	if scan == nil {
		writeNotFound(w)
		return
	}

	writeJSON(w, http.StatusOK, newScanResponse(scan))
}

func (s *Server) handleScanFindings(w http.ResponseWriter, r *http.Request, scanID string) {
	filter, err := parseFindingsFilter(r)
	if err != nil {
		writeBadRequest(w, err.Error())
		return
	}

	findings, err := s.repo.ListExpandedFindingsPageByScanID(r.Context(), scanID, filter)
	if err != nil {
		writeInternalError(w, err)
		return
	}

	response := make([]findingResponse, 0, len(findings.Items))
	for _, finding := range findings.Items {
		response = append(response, newFindingResponse(finding))
	}

	writeJSON(w, http.StatusOK, findingsPageResponse{
		Items:  response,
		Total:  findings.Total,
		Limit:  findings.Limit,
		Offset: findings.Offset,
	})
}

func (s *Server) handleScanSummary(w http.ResponseWriter, r *http.Request, scanID string) {
	summary, err := s.repo.GetScanSummary(r.Context(), scanID)
	if err != nil {
		writeInternalError(w, err)
		return
	}

	writeJSON(w, http.StatusOK, newScanSummaryResponse(summary))
}

type scanResponse struct {
	ID          string  `json:"id"`
	AssetID     string  `json:"asset_id"`
	Status      string  `json:"status"`
	SBOMFormat  string  `json:"sbom_format"`
	StartedAt   string  `json:"started_at"`
	CompletedAt *string `json:"completed_at"`
}

type assetResponse struct {
	ID        string `json:"id"`
	Name      string `json:"name"`
	AssetType string `json:"asset_type"`
	Source    string `json:"source"`
	CreatedAt string `json:"created_at"`
}

func newAssetResponse(asset *model.Asset) assetResponse {
	return assetResponse{
		ID:        asset.ID,
		Name:      asset.Name,
		AssetType: asset.AssetType,
		Source:    asset.Source,
		CreatedAt: asset.CreatedAt.UTC().Format(time.RFC3339Nano),
	}
}

func newScanResponse(scan *model.Scan) scanResponse {
	var completedAt *string
	if scan.CompletedAt != nil {
		value := scan.CompletedAt.UTC().Format(time.RFC3339)
		completedAt = &value
	}

	return scanResponse{
		ID:          scan.ID,
		AssetID:     scan.AssetID,
		Status:      scan.Status,
		SBOMFormat:  scan.SBOMFormat,
		StartedAt:   scan.StartedAt.UTC().Format(time.RFC3339),
		CompletedAt: completedAt,
	}
}

type findingResponse struct {
	ID               string                   `json:"id"`
	ScanID           string                   `json:"scan_id"`
	Status           string                   `json:"status"`
	FixedVersion     string                   `json:"fixed_version"`
	Vulnerability    *vulnerabilityResponse   `json:"vulnerability"`
	ComponentVersion componentVersionResponse `json:"component_version"`
}

type componentVersionResponse struct {
	ID        string             `json:"id"`
	Version   string             `json:"version"`
	Component *componentResponse `json:"component"`
}

type vulnerabilityResponse struct {
	ID            string   `json:"id"`
	ExternalID    string   `json:"external_id"`
	Source        string   `json:"source"`
	Severity      string   `json:"severity"`
	SeverityScore *float64 `json:"severity_score"`
	SeverityLabel string   `json:"severity_label"`
	Summary       string   `json:"summary"`
}

type componentResponse struct {
	ID        string `json:"id"`
	Name      string `json:"name"`
	Ecosystem string `json:"ecosystem"`
	PURL      string `json:"purl"`
}

type scanSummaryResponse struct {
	ScanID                 string         `json:"scan_id"`
	TotalFindings          int            `json:"total_findings"`
	UniqueVulnerabilities  int            `json:"unique_vulnerabilities"`
	UniquePackagesAffected int            `json:"unique_packages_affected"`
	EcosystemCounts        map[string]int `json:"ecosystem_counts"`
	SeverityCounts         map[string]int `json:"severity_counts"`
}

type assetSummaryResponse struct {
	AssetID                string         `json:"asset_id"`
	TotalScans             int            `json:"total_scans"`
	LatestScanID           string         `json:"latest_scan_id"`
	TotalFindings          int            `json:"total_findings"`
	UniqueVulnerabilities  int            `json:"unique_vulnerabilities"`
	UniquePackagesAffected int            `json:"unique_packages_affected"`
	EcosystemCounts        map[string]int `json:"ecosystem_counts"`
	SeverityCounts         map[string]int `json:"severity_counts"`
}

type findingsPageResponse struct {
	Items  []findingResponse `json:"items"`
	Total  int               `json:"total"`
	Limit  int               `json:"limit"`
	Offset int               `json:"offset"`
}

type createScanJobRequest struct {
	RepoURL string `json:"repo_url"`
}

type scanJobResponse struct {
	ID                string  `json:"id"`
	RepoURL           string  `json:"repo_url"`
	RepoOwner         string  `json:"repo_owner"`
	RepoName          string  `json:"repo_name"`
	RepoDefaultBranch *string `json:"repo_default_branch"`
	Status            string  `json:"status"`
	AssetID           *string `json:"asset_id"`
	ScanID            *string `json:"scan_id"`
	Error             *string `json:"error"`
	CreatedAt         string  `json:"created_at"`
	StartedAt         *string `json:"started_at"`
	CompletedAt       *string `json:"completed_at"`
}

func newFindingResponse(finding model.ExpandedFinding) findingResponse {
	return findingResponse{
		ID:            finding.Finding.ID,
		ScanID:        finding.Finding.ScanID,
		Status:        finding.Finding.Status,
		FixedVersion:  finding.Finding.FixedVersion,
		Vulnerability: newVulnerabilityResponse(finding.Vulnerability),
		ComponentVersion: componentVersionResponse{
			ID:        finding.ComponentVersion.ID,
			Version:   finding.ComponentVersion.Version,
			Component: newComponentResponse(finding.Component),
		},
	}
}

func newScanJobResponse(job *model.ScanJob) scanJobResponse {
	var startedAt *string
	if job.StartedAt != nil {
		value := job.StartedAt.UTC().Format(time.RFC3339)
		startedAt = &value
	}

	var completedAt *string
	if job.CompletedAt != nil {
		value := job.CompletedAt.UTC().Format(time.RFC3339)
		completedAt = &value
	}

	return scanJobResponse{
		ID:                job.ID,
		RepoURL:           job.RepoURL,
		RepoOwner:         job.RepoOwner,
		RepoName:          job.RepoName,
		RepoDefaultBranch: job.RepoDefaultBranch,
		Status:            job.Status,
		AssetID:           job.AssetID,
		ScanID:            job.ScanID,
		Error:             job.Error,
		CreatedAt:         job.CreatedAt.UTC().Format(time.RFC3339Nano),
		StartedAt:         startedAt,
		CompletedAt:       completedAt,
	}
}

func newVulnerabilityResponse(vulnerability model.Vulnerability) *vulnerabilityResponse {
	return &vulnerabilityResponse{
		ID:            vulnerability.ID,
		ExternalID:    vulnerability.ExternalID,
		Source:        vulnerability.Source,
		Severity:      vulnerability.Severity,
		SeverityScore: vulnerability.SeverityScore,
		SeverityLabel: vulnerability.SeverityLabel,
		Summary:       vulnerability.Summary,
	}
}

func newComponentResponse(component model.Component) *componentResponse {
	return &componentResponse{
		ID:        component.ID,
		Name:      component.Name,
		Ecosystem: component.Ecosystem,
		PURL:      component.PURL,
	}
}

func newScanSummaryResponse(summary *model.ScanSummary) scanSummaryResponse {
	severityCounts := defaultSeverityCounts(summary.SeverityCounts)

	return scanSummaryResponse{
		ScanID:                 summary.ScanID,
		TotalFindings:          summary.TotalFindings,
		UniqueVulnerabilities:  summary.UniqueVulnerabilities,
		UniquePackagesAffected: summary.UniquePackagesAffected,
		EcosystemCounts:        summary.EcosystemCounts,
		SeverityCounts:         severityCounts,
	}
}

func newAssetSummaryResponse(summary *model.AssetSummary) assetSummaryResponse {
	severityCounts := defaultSeverityCounts(summary.SeverityCounts)

	return assetSummaryResponse{
		AssetID:                summary.AssetID,
		TotalScans:             summary.TotalScans,
		LatestScanID:           summary.LatestScanID,
		TotalFindings:          summary.TotalFindings,
		UniqueVulnerabilities:  summary.UniqueVulnerabilities,
		UniquePackagesAffected: summary.UniquePackagesAffected,
		EcosystemCounts:        summary.EcosystemCounts,
		SeverityCounts:         severityCounts,
	}
}

func defaultSeverityCounts(counts map[string]int) map[string]int {
	severityCounts := map[string]int{
		"critical": 0,
		"high":     0,
		"medium":   0,
		"low":      0,
		"none":     0,
		"unknown":  0,
	}
	for label, count := range counts {
		severityCounts[label] = count
	}
	return severityCounts
}

func parseFindingsFilter(r *http.Request) (model.FindingsFilter, error) {
	const (
		defaultLimit = 50
		maxLimit     = 200
	)

	query := r.URL.Query()
	filter := model.FindingsFilter{
		Limit:                   defaultLimit,
		Offset:                  0,
		Ecosystem:               query.Get("ecosystem"),
		Package:                 query.Get("package"),
		Status:                  query.Get("status"),
		VulnerabilityExternalID: query.Get("vulnerability"),
		SeverityLabel:           query.Get("severity_label"),
		SortBy:                  query.Get("sort_by"),
		Order:                   query.Get("order"),
	}

	if rawLimit := query.Get("limit"); rawLimit != "" {
		limit, err := strconv.Atoi(rawLimit)
		if err != nil || limit < 0 {
			return model.FindingsFilter{}, fmt.Errorf("invalid limit")
		}
		if limit > maxLimit {
			limit = maxLimit
		}
		filter.Limit = limit
	}

	if rawOffset := query.Get("offset"); rawOffset != "" {
		offset, err := strconv.Atoi(rawOffset)
		if err != nil || offset < 0 {
			return model.FindingsFilter{}, fmt.Errorf("invalid offset")
		}
		filter.Offset = offset
	}

	if filter.Order != "" && filter.Order != "asc" && filter.Order != "desc" {
		return model.FindingsFilter{}, fmt.Errorf("invalid order")
	}

	return filter, nil
}

func writeJSON(w http.ResponseWriter, statusCode int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	_ = json.NewEncoder(w).Encode(value)
}

func writeMethodNotAllowed(w http.ResponseWriter) {
	writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
}

func writeBadRequest(w http.ResponseWriter, message string) {
	writeJSON(w, http.StatusBadRequest, map[string]string{"error": message})
}

func writeNotFound(w http.ResponseWriter) {
	writeJSON(w, http.StatusNotFound, map[string]string{"error": "not found"})
}

func writeInternalError(w http.ResponseWriter, err error) {
	message := "internal server error"
	if err != nil {
		message = err.Error()
	}

	writeJSON(w, http.StatusInternalServerError, map[string]string{"error": message})
}
