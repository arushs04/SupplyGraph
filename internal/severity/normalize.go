package severity

import (
	"strings"

	cvss30 "github.com/pandatix/go-cvss/30"
	cvss31 "github.com/pandatix/go-cvss/31"
	cvss40 "github.com/pandatix/go-cvss/40"
)

type Normalized struct {
	Raw   string
	Score *float64
	Label string
}

func Normalize(raw string) Normalized {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return Normalized{Raw: "", Label: "unknown"}
	}

	switch {
	case strings.HasPrefix(raw, "CVSS:3.0/"):
		return normalizeCVSS30(raw)
	case strings.HasPrefix(raw, "CVSS:3.1/"):
		return normalizeCVSS31(raw)
	case strings.HasPrefix(raw, "CVSS:4.0/"):
		return normalizeCVSS40(raw)
	default:
		return Normalized{Raw: raw, Label: "unknown"}
	}
}

func normalizeCVSS30(raw string) Normalized {
	vector, err := cvss30.ParseVector(raw)
	if err != nil {
		return Normalized{Raw: raw, Label: "unknown"}
	}

	score := vector.BaseScore()
	label, err := cvss30.Rating(score)
	if err != nil {
		return Normalized{Raw: raw, Label: "unknown"}
	}

	label = strings.ToLower(label)
	return Normalized{Raw: raw, Score: &score, Label: label}
}

func normalizeCVSS31(raw string) Normalized {
	vector, err := cvss31.ParseVector(raw)
	if err != nil {
		return Normalized{Raw: raw, Label: "unknown"}
	}

	score := vector.BaseScore()
	label, err := cvss31.Rating(score)
	if err != nil {
		return Normalized{Raw: raw, Label: "unknown"}
	}

	label = strings.ToLower(label)
	return Normalized{Raw: raw, Score: &score, Label: label}
}

func normalizeCVSS40(raw string) Normalized {
	vector, err := cvss40.ParseVector(raw)
	if err != nil {
		return Normalized{Raw: raw, Label: "unknown"}
	}

	score := vector.Score()
	label, err := cvss40.Rating(score)
	if err != nil {
		return Normalized{Raw: raw, Label: "unknown"}
	}

	label = strings.ToLower(label)
	return Normalized{Raw: raw, Score: &score, Label: label}
}
