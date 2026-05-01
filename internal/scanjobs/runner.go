package scanjobs

import (
	"bytes"
	"context"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"time"

	"supplygraph/internal/db"
	gh "supplygraph/internal/github"
	"supplygraph/internal/ingest"
	"supplygraph/internal/model"
	"supplygraph/internal/syft"
)

type Runner struct {
	repo       *db.Repository
	httpClient *http.Client
}

func NewRunner(repo *db.Repository) *Runner {
	return &Runner{
		repo:       repo,
		httpClient: http.DefaultClient,
	}
}

func (r *Runner) ResumeQueuedJobs(ctx context.Context) error {
	jobs, err := r.repo.ListRunnableScanJobs(ctx)
	if err != nil {
		return err
	}

	for _, job := range jobs {
		if job == nil {
			continue
		}
		go r.processJob(context.Background(), job.ID)
	}

	return nil
}

func (r *Runner) SubmitGitHubRepo(ctx context.Context, repoURL string) (*model.ScanJob, error) {
	repoInfo, err := gh.ResolvePublicRepo(ctx, r.httpClient, repoURL)
	if err != nil {
		return nil, err
	}

	job := model.ScanJob{
		RepoURL:   repoInfo.CanonicalURL,
		RepoOwner: repoInfo.Owner,
		RepoName:  repoInfo.Name,
		Status:    "pending",
	}

	jobID, err := r.repo.CreateScanJob(ctx, job)
	if err != nil {
		return nil, err
	}
	job.ID = jobID

	storedJob, err := r.repo.GetScanJobByID(ctx, jobID)
	if err != nil {
		return nil, err
	}

	go r.processJob(context.Background(), jobID)

	return storedJob, nil
}

func (r *Runner) processJob(ctx context.Context, jobID string) {
	job, err := r.repo.GetScanJobByID(ctx, jobID)
	if err != nil || job == nil {
		return
	}

	repoInfo, err := gh.ResolvePublicRepo(ctx, r.httpClient, job.RepoURL)
	if err != nil {
		r.failJob(ctx, jobID, err)
		return
	}

	startedAt := time.Now().UTC()
	if err := r.repo.MarkScanJobRunning(ctx, jobID, repoInfo.DefaultBranch, startedAt); err != nil {
		r.failJob(ctx, jobID, err)
		return
	}

	tmpDir, err := os.MkdirTemp("", "supplygraph-repo-*")
	if err != nil {
		r.failJob(ctx, jobID, fmt.Errorf("create temp directory: %w", err))
		return
	}
	defer os.RemoveAll(tmpDir)

	repoDir, err := gh.DownloadAndExtractDefaultBranch(ctx, r.httpClient, repoInfo, tmpDir)
	if err != nil {
		r.failJob(ctx, jobID, err)
		return
	}

	doc, err := runSyft(ctx, repoDir)
	if err != nil {
		r.failJob(ctx, jobID, err)
		return
	}

	assetID, scanID, err := r.persistScan(ctx, repoInfo, repoDir, doc)
	if err != nil {
		r.failJob(ctx, jobID, err)
		return
	}

	if err := r.repo.MarkScanJobCompleted(ctx, jobID, assetID, scanID, time.Now().UTC()); err != nil {
		r.failJob(ctx, jobID, err)
	}
}

func (r *Runner) persistScan(ctx context.Context, repoInfo gh.RepoInfo, repoDir string, doc syft.Document) (string, string, error) {
	assetID, err := r.repo.FindOrCreateAsset(ctx, model.Asset{
		Name:      repoInfo.Name,
		AssetType: "repo_url",
		Source:    repoInfo.CanonicalURL,
	})
	if err != nil {
		return "", "", fmt.Errorf("persist asset: %w", err)
	}

	now := time.Now().UTC()
	scanID, err := r.repo.InsertScan(ctx, model.Scan{
		AssetID:     assetID,
		Status:      "running",
		SBOMFormat:  "syft-json",
		StartedAt:   now,
		CompletedAt: nil,
	})
	if err != nil {
		return "", "", fmt.Errorf("insert scan: %w", err)
	}

	if _, err := ingest.PersistInventory(ctx, r.repo, scanID, doc.Artifacts); err != nil {
		completedAt := time.Now().UTC()
		_ = r.repo.UpdateScanStatus(ctx, scanID, "failed", &completedAt)
		return assetID, scanID, fmt.Errorf("persist inventory: %w", err)
	}

	if _, err := ingest.EnrichScanWithOSV(ctx, r.repo, scanID); err != nil {
		completedAt := time.Now().UTC()
		_ = r.repo.UpdateScanStatus(ctx, scanID, "failed", &completedAt)
		return assetID, scanID, fmt.Errorf("enrich scan with osv: %w", err)
	}

	completedAt := time.Now().UTC()
	if err := r.repo.UpdateScanStatus(ctx, scanID, "completed", &completedAt); err != nil {
		return assetID, scanID, fmt.Errorf("complete scan: %w", err)
	}

	return assetID, scanID, nil
}

func (r *Runner) failJob(ctx context.Context, jobID string, err error) {
	if err == nil {
		return
	}
	_ = r.repo.MarkScanJobFailed(ctx, jobID, err.Error(), time.Now().UTC())
}

func runSyft(ctx context.Context, sourceDir string) (syft.Document, error) {
	cmd := exec.CommandContext(ctx, "syft", "-q", sourceDir, "-o", "json")
	var stderr bytes.Buffer
	cmd.Stderr = &stderr

	output, err := cmd.Output()
	if err != nil {
		return syft.Document{}, fmt.Errorf("run syft: %w: %s", err, strings.TrimSpace(stderr.String()))
	}

	doc, err := syft.LoadDocumentBytes(output)
	if err != nil {
		return syft.Document{}, fmt.Errorf("parse syft output: %w: %s", err, strings.TrimSpace(stderr.String()))
	}

	return doc, nil
}
