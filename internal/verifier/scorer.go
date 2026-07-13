package verifier

import (
	"strings"
	"time"

	"github.com/aydocs/fang/pkg/models"
)

type ConfidenceScorer struct{}

func (cs *ConfidenceScorer) Score(finding *models.Finding, verification *models.Verification) models.Confidence {
	if verification == nil || !verification.Confirmed {
		return models.Tentative
	}

	switch verification.Method {
	case "error_pattern":
		return models.CriticalConfidence
	case "reflection":
		evidenceLower := strings.ToLower(verification.Evidence)
		if strings.Contains(evidenceLower, "error") || strings.Contains(evidenceLower, "exception") || strings.Contains(evidenceLower, "warning") {
			return models.CriticalConfidence
		}
		return models.HighConfidence
	case "timing":
		if verification.Duration >= 5*time.Second {
			return models.HighConfidence
		}
		return models.MediumConfidence
	case "baseline", "differential":
		if strings.Contains(verification.Evidence, "Status code") {
			return models.MediumConfidence
		}
		return models.LowConfidence
	case "repeated":
		return models.LowConfidence
	default:
		return models.Tentative
	}
}
