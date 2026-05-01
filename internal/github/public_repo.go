package github

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
)

type RepoInfo struct {
	Owner         string
	Name          string
	DefaultBranch string
	CanonicalURL  string
}

type repoResponse struct {
	DefaultBranch string `json:"default_branch"`
	HTMLURL       string `json:"html_url"`
	Private       bool   `json:"private"`
}

func ResolvePublicRepo(ctx context.Context, client *http.Client, rawURL string) (RepoInfo, error) {
	owner, repo, err := parseRepoURL(rawURL)
	if err != nil {
		return RepoInfo{}, err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, fmt.Sprintf("https://api.github.com/repos/%s/%s", owner, repo), nil)
	if err != nil {
		return RepoInfo{}, fmt.Errorf("build github repo request: %w", err)
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("User-Agent", "supplygraph/0.1")

	resp, err := client.Do(req)
	if err != nil {
		return RepoInfo{}, fmt.Errorf("query github repo metadata: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return RepoInfo{}, fmt.Errorf("github repository not found")
	}
	if resp.StatusCode != http.StatusOK {
		return RepoInfo{}, fmt.Errorf("github repo metadata returned status %d", resp.StatusCode)
	}

	var payload repoResponse
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		return RepoInfo{}, fmt.Errorf("decode github repo metadata: %w", err)
	}
	if payload.Private {
		return RepoInfo{}, fmt.Errorf("private repositories are not supported")
	}
	if payload.DefaultBranch == "" {
		return RepoInfo{}, fmt.Errorf("github repository does not expose a default branch")
	}

	canonicalURL := payload.HTMLURL
	if canonicalURL == "" {
		canonicalURL = fmt.Sprintf("https://github.com/%s/%s", owner, repo)
	}

	return RepoInfo{
		Owner:         owner,
		Name:          repo,
		DefaultBranch: payload.DefaultBranch,
		CanonicalURL:  canonicalURL,
	}, nil
}

func DownloadAndExtractDefaultBranch(ctx context.Context, client *http.Client, repo RepoInfo, destination string) (string, error) {
	tarballURL := fmt.Sprintf("https://codeload.github.com/%s/%s/tar.gz/refs/heads/%s", repo.Owner, repo.Name, repo.DefaultBranch)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, tarballURL, nil)
	if err != nil {
		return "", fmt.Errorf("build github tarball request: %w", err)
	}
	req.Header.Set("User-Agent", "supplygraph/0.1")

	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("download github tarball: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("github tarball returned status %d", resp.StatusCode)
	}

	return extractTarGz(resp.Body, destination)
}

func parseRepoURL(raw string) (string, string, error) {
	if strings.TrimSpace(raw) == "" {
		return "", "", fmt.Errorf("repo_url is required")
	}

	parsed, err := url.Parse(raw)
	if err != nil {
		return "", "", fmt.Errorf("parse repo url: %w", err)
	}

	if !strings.EqualFold(parsed.Host, "github.com") {
		return "", "", fmt.Errorf("only public github.com repositories are supported")
	}

	path := strings.Trim(parsed.Path, "/")
	parts := strings.Split(path, "/")
	if len(parts) < 2 {
		return "", "", fmt.Errorf("repo url must look like https://github.com/<owner>/<repo>")
	}

	owner := strings.TrimSpace(parts[0])
	repo := strings.TrimSuffix(strings.TrimSpace(parts[1]), ".git")
	if owner == "" || repo == "" {
		return "", "", fmt.Errorf("repo url must include both owner and repo")
	}

	return owner, repo, nil
}

func extractTarGz(r io.Reader, destination string) (string, error) {
	gzipReader, err := gzip.NewReader(r)
	if err != nil {
		return "", fmt.Errorf("open tar.gz stream: %w", err)
	}
	defer gzipReader.Close()

	tarReader := tar.NewReader(gzipReader)
	var rootDir string

	for {
		header, err := tarReader.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return "", fmt.Errorf("read tar entry: %w", err)
		}

		switch header.Typeflag {
		case tar.TypeXGlobalHeader, tar.TypeXHeader:
			continue
		}

		targetPath := filepath.Join(destination, header.Name)
		cleanTarget := filepath.Clean(targetPath)
		if !strings.HasPrefix(cleanTarget, filepath.Clean(destination)+string(os.PathSeparator)) && cleanTarget != filepath.Clean(destination) {
			return "", fmt.Errorf("tar entry escapes destination: %q", header.Name)
		}

		trimmedName := strings.TrimPrefix(header.Name, "./")
		if rootDir == "" {
			slashIndex := strings.Index(trimmedName, "/")
			if slashIndex > 0 {
				topLevel := trimmedName[:slashIndex]
				if topLevel != "" && topLevel != "pax_global_header" {
					rootDir = filepath.Join(destination, topLevel)
				}
			}
		}

		switch header.Typeflag {
		case tar.TypeDir:
			if err := os.MkdirAll(cleanTarget, 0o755); err != nil {
				return "", fmt.Errorf("create directory %q: %w", cleanTarget, err)
			}
		case tar.TypeReg:
			if err := os.MkdirAll(filepath.Dir(cleanTarget), 0o755); err != nil {
				return "", fmt.Errorf("create file parent %q: %w", cleanTarget, err)
			}
			file, err := os.OpenFile(cleanTarget, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, os.FileMode(header.Mode))
			if err != nil {
				return "", fmt.Errorf("create file %q: %w", cleanTarget, err)
			}
			if _, err := io.Copy(file, tarReader); err != nil {
				file.Close()
				return "", fmt.Errorf("write file %q: %w", cleanTarget, err)
			}
			if err := file.Close(); err != nil {
				return "", fmt.Errorf("close file %q: %w", cleanTarget, err)
			}
		case tar.TypeSymlink, tar.TypeLink:
			continue
		}
	}

	if rootDir == "" {
		return "", fmt.Errorf("tarball did not contain a repository directory")
	}

	rootInfo, err := os.Stat(rootDir)
	if err != nil {
		return "", fmt.Errorf("stat extracted repo root %q: %w", rootDir, err)
	}
	if !rootInfo.IsDir() {
		return "", fmt.Errorf("extracted repo root %q is not a directory", rootDir)
	}

	return rootDir, nil
}
