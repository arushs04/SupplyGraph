CREATE TABLE vulnerabilities (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    external_id TEXT NOT NULL, -- The vulnerability ID from the source (e.g., CVE-2021-1234)
    source TEXT NOT NULL, -- The source of the vulnerability information (e.g., NVD, GitHub Advisories)
    severity TEXT, -- Severity level of the vulnerability (e.g., low, medium, high, critical)
    summary TEXT,
    UNIQUE (source, external_id)
);

CREATE TABLE findings (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    scan_id UUID NOT NULL REFERENCES scans(id) ON DELETE CASCADE, -- Foreign key to the scans table, each finding belongs to a scan
    component_version_id UUID NOT NULL REFERENCES component_versions(id) ON DELETE CASCADE, -- Foreign key to the component_versions table, each finding belongs to a component version
    vulnerability_id UUID NOT NULL REFERENCES vulnerabilities(id) ON DELETE CASCADE, -- Foreign key to the vulnerabilities table, each finding relates to a vulnerability
    fixed_version TEXT, -- The version in which the vulnerability is fixed
    status TEXT NOT NULL, -- The status of the finding (e.g., open, closed, mitigated)
    UNIQUE (scan_id, component_version_id, vulnerability_id)
);
