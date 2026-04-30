ALTER TABLE vulnerabilities
ADD COLUMN severity_score DOUBLE PRECISION,
ADD COLUMN severity_label TEXT NOT NULL DEFAULT 'unknown';
