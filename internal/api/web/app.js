const state = {
  activeJobId: null,
  activeJob: null,
  activeAssetId: null,
  activeScanId: null,
  pollTimer: null,
};

const elements = {
  form: document.getElementById("scan-form"),
  repoUrl: document.getElementById("repo-url"),
  submitError: document.getElementById("submit-error"),
  submitButton: document.getElementById("scan-submit"),
  refreshJobs: document.getElementById("refresh-jobs"),
  recentJobs: document.getElementById("recent-jobs"),
  jobStatusBadge: document.getElementById("job-status-badge"),
  jobEmpty: document.getElementById("job-empty"),
  jobDetails: document.getElementById("job-details"),
  jobRepoName: document.getElementById("job-repo-name"),
  jobRepoURL: document.getElementById("job-repo-url"),
  jobId: document.getElementById("job-id"),
  jobCreatedAt: document.getElementById("job-created-at"),
  jobStartedAt: document.getElementById("job-started-at"),
  jobError: document.getElementById("job-error"),
  resultsPanel: document.getElementById("results-panel"),
  resultsTitle: document.getElementById("results-title"),
  resultsAssetId: document.getElementById("results-asset-id"),
  resultsScanId: document.getElementById("results-scan-id"),
  assetTotalFindings: document.getElementById("asset-total-findings"),
  scanTotalFindings: document.getElementById("scan-total-findings"),
  scanUniqueVulns: document.getElementById("scan-unique-vulns"),
  assetSummaryCaption: document.getElementById("asset-summary-caption"),
  scanSummaryCaption: document.getElementById("scan-summary-caption"),
  severityBars: document.getElementById("severity-bars"),
  findingsMeta: document.getElementById("findings-meta"),
  findingsList: document.getElementById("findings-list"),
  severityFilter: document.getElementById("severity-filter"),
  packageFilter: document.getElementById("package-filter"),
  sortFilter: document.getElementById("sort-filter"),
  orderFilter: document.getElementById("order-filter"),
  applyFilters: document.getElementById("apply-filters"),
};

const severityOrder = ["critical", "high", "medium", "low", "none", "unknown"];

elements.form.addEventListener("submit", handleSubmit);
elements.refreshJobs.addEventListener("click", () => loadRecentJobs());
elements.applyFilters.addEventListener("click", () => {
  if (state.activeScanId) {
    loadResults(state.activeAssetId, state.activeScanId);
  }
});

async function handleSubmit(event) {
  event.preventDefault();
  hideError(elements.submitError);

  const repoURL = elements.repoUrl.value.trim();
  if (!repoURL) {
    showError(elements.submitError, "Repository URL is required.");
    return;
  }

  elements.submitButton.disabled = true;
  elements.submitButton.textContent = "Submitting...";

  try {
    const response = await fetch("/scan-jobs", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
      },
      body: JSON.stringify({ repo_url: repoURL }),
    });

    const payload = await response.json();
    if (!response.ok) {
      throw new Error(payload.error || "Failed to create scan job.");
    }

    setActiveJob(payload);
    await loadRecentJobs();
  } catch (error) {
    showError(elements.submitError, error.message);
  } finally {
    elements.submitButton.disabled = false;
    elements.submitButton.textContent = "Launch Scan";
  }
}

async function loadRecentJobs() {
  try {
    const response = await fetch("/scan-jobs");
    const jobs = await response.json();
    renderRecentJobs(jobs);
  } catch (error) {
    elements.recentJobs.innerHTML = `<div class="empty-state">Failed to load recent jobs.</div>`;
  }
}

function renderRecentJobs(jobs) {
  if (!jobs.length) {
    elements.recentJobs.innerHTML = `<div class="empty-state">No jobs yet. Submit a repository above.</div>`;
    return;
  }

  elements.recentJobs.innerHTML = jobs
    .map((job) => {
      const label = `${escapeHTML(job.repo_owner)}/${escapeHTML(job.repo_name)}`;
      const createdAt = formatDate(job.created_at);
      return `
        <button class="job-card" type="button" data-job-id="${job.id}">
          <div class="job-card-top">
            <div>
              <strong>${label}</strong>
              <p class="meta-value">${escapeHTML(job.repo_url)}</p>
            </div>
            <span class="status-badge ${job.status}">${capitalize(job.status)}</span>
          </div>
          <div class="finding-meta">
            <span class="chip">Created ${createdAt}</span>
            ${job.scan_id ? `<span class="chip">Scan ${escapeHTML(job.scan_id.slice(0, 8))}</span>` : ""}
          </div>
        </button>
      `;
    })
    .join("");

  elements.recentJobs.querySelectorAll("[data-job-id]").forEach((button) => {
    button.addEventListener("click", async () => {
      const jobId = button.getAttribute("data-job-id");
      await loadJob(jobId, true);
    });
  });
}

async function loadJob(jobId, focusResults = false) {
  const response = await fetch(`/scan-jobs/${jobId}`);
  const payload = await response.json();
  if (!response.ok) {
    throw new Error(payload.error || "Failed to load job.");
  }

  setActiveJob(payload);
  if (focusResults && payload.status === "completed" && payload.asset_id && payload.scan_id) {
    await loadResults(payload.asset_id, payload.scan_id);
  }
}

function setActiveJob(job) {
  state.activeJobId = job.id;
  state.activeJob = job;

  elements.jobEmpty.classList.add("hidden");
  elements.jobDetails.classList.remove("hidden");
  hideError(elements.jobError);

  elements.jobStatusBadge.textContent = capitalize(job.status);
  elements.jobStatusBadge.className = `status-badge ${job.status}`;
  elements.jobRepoName.textContent = `${job.repo_owner}/${job.repo_name}`;
  elements.jobRepoURL.textContent = job.repo_url;
  elements.jobId.textContent = job.id;
  elements.jobCreatedAt.textContent = formatDate(job.created_at);
  elements.jobStartedAt.textContent = job.started_at ? formatDate(job.started_at) : "Not started";

  if (job.error) {
    showError(elements.jobError, job.error);
  }

  updateTimeline(job.status);
  managePolling(job);

  if (job.status === "completed" && job.asset_id && job.scan_id) {
    loadResults(job.asset_id, job.scan_id);
  }
}

function updateTimeline(status) {
  document.querySelectorAll(".timeline-step").forEach((step) => {
    step.classList.remove("active", "done");
    const key = step.getAttribute("data-step");

    if (status === "pending" && key === "pending") {
      step.classList.add("active");
    }

    if (status === "running") {
      if (key === "pending") step.classList.add("done");
      if (key === "running") step.classList.add("active");
    }

    if (status === "completed") {
      step.classList.add("done");
    }
  });
}

function managePolling(job) {
  if (state.pollTimer) {
    clearTimeout(state.pollTimer);
    state.pollTimer = null;
  }

  if (job.status === "pending" || job.status === "running") {
    state.pollTimer = setTimeout(async () => {
      try {
        await loadJob(job.id);
        await loadRecentJobs();
      } catch (_) {
        state.pollTimer = setTimeout(() => loadJob(job.id), 4000);
      }
    }, 2500);
  }
}

async function loadResults(assetId, scanId) {
  state.activeAssetId = assetId;
  state.activeScanId = scanId;

  const filters = new URLSearchParams({
    limit: "25",
    sort_by: elements.sortFilter.value || "severity",
    order: elements.orderFilter.value || "desc",
  });

  if (elements.severityFilter.value) {
    filters.set("severity_label", elements.severityFilter.value);
  }
  if (elements.packageFilter.value.trim()) {
    filters.set("package", elements.packageFilter.value.trim());
  }

  const [assetSummary, scanSummary, findingsPage] = await Promise.all([
    fetchJSON(`/assets/${assetId}/summary`),
    fetchJSON(`/scans/${scanId}/summary`),
    fetchJSON(`/scans/${scanId}/findings?${filters.toString()}`),
  ]);

  renderResults(assetSummary, scanSummary, findingsPage, assetId, scanId);
}

function renderResults(assetSummary, scanSummary, findingsPage, assetId, scanId) {
  elements.resultsPanel.classList.remove("hidden");
  elements.resultsTitle.textContent = `${state.activeJob.repo_owner}/${state.activeJob.repo_name}`;
  elements.resultsAssetId.textContent = `Asset ${assetId.slice(0, 8)}`;
  elements.resultsScanId.textContent = `Scan ${scanId.slice(0, 8)}`;

  elements.assetTotalFindings.textContent = assetSummary.total_findings;
  elements.scanTotalFindings.textContent = scanSummary.total_findings;
  elements.scanUniqueVulns.textContent = scanSummary.unique_vulnerabilities;
  elements.assetSummaryCaption.textContent = `${assetSummary.total_scans} scans, ${assetSummary.unique_vulnerabilities} unique vulns`;
  elements.scanSummaryCaption.textContent = `${scanSummary.unique_packages_affected} unique packages`;

  renderSeverityBars(scanSummary.severity_counts || {});
  renderFindings(findingsPage);
}

function renderSeverityBars(counts) {
  const total = severityOrder.reduce((sum, key) => sum + (counts[key] || 0), 0);

  elements.severityBars.innerHTML = severityOrder
    .map((label) => {
      const count = counts[label] || 0;
      const width = total ? Math.max((count / total) * 100, count > 0 ? 4 : 0) : 0;
      return `
        <div class="severity-row">
          <strong>${capitalize(label)}</strong>
          <div class="severity-track">
            <div class="severity-fill ${label}" style="width:${width}%"></div>
          </div>
          <span>${count}</span>
        </div>
      `;
    })
    .join("");
}

function renderFindings(page) {
  elements.findingsMeta.textContent = `Showing ${page.items.length} of ${page.total} findings. Limit ${page.limit}, offset ${page.offset}.`;

  if (!page.items.length) {
    elements.findingsList.innerHTML = `<div class="empty-state">No findings matched the current filters.</div>`;
    return;
  }

  elements.findingsList.innerHTML = page.items
    .map((finding) => {
      const score =
        typeof finding.vulnerability.severity_score === "number"
          ? `CVSS ${finding.vulnerability.severity_score.toFixed(1)}`
          : "Unscored";
      const severity = finding.vulnerability.severity_label || "unknown";
      return `
        <article class="finding-card">
          <div class="finding-top">
            <div>
              <strong>${escapeHTML(finding.component_version.component.name)}@${escapeHTML(finding.component_version.version)}</strong>
              <p>${escapeHTML(finding.vulnerability.external_id)} · ${escapeHTML(finding.vulnerability.source)}</p>
            </div>
            <span class="chip ${severity}">${capitalize(severity)}</span>
          </div>
          <p>${escapeHTML(finding.vulnerability.summary || "No summary available.")}</p>
          <div class="finding-meta">
            <span class="chip">${score}</span>
            <span class="chip">${escapeHTML(finding.component_version.component.ecosystem)}</span>
            <span class="chip">${escapeHTML(finding.component_version.component.purl)}</span>
            <span class="chip">Status ${escapeHTML(finding.status)}</span>
          </div>
        </article>
      `;
    })
    .join("");
}

function showError(element, message) {
  element.textContent = message;
  element.classList.remove("hidden");
}

function hideError(element) {
  element.textContent = "";
  element.classList.add("hidden");
}

function formatDate(value) {
  try {
    return new Date(value).toLocaleString();
  } catch (_) {
    return value;
  }
}

function capitalize(value) {
  if (!value) return "";
  return value.charAt(0).toUpperCase() + value.slice(1);
}

async function fetchJSON(url) {
  const response = await fetch(url);
  const payload = await response.json();
  if (!response.ok) {
    throw new Error(payload.error || `Request failed: ${url}`);
  }
  return payload;
}

function escapeHTML(value) {
  return String(value)
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#39;");
}

loadRecentJobs();
